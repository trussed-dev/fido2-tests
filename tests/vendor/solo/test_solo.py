import sys

import pytest
import ecdsa
import hashlib
from fido2.ctap1 import ApduError
from fido2.ctap2 import CtapError
from fido2.utils import hmac_sha256, sha256
try:
    from solo.client import SoloClient
except:
    from solo.devices.solo_v1 import Client as SoloClient

from solo.commands import SoloExtension

from tests.utils import shannon_entropy, verify, FidoRequest

# Is there no RFC for this?
def keypair_from_seed(seed: bytes):
    assert isinstance(seed, bytes)
    assert len(seed) == 32

    P256 = ecdsa.NIST256p
    scalar = int.from_bytes(seed, "little")
    iterations = 0
    while not (1 <= scalar < P256.order):
        seed = sha256(seed)
        scalar = int.from_bytes(seed, "little")
        iterations += 1

    keypair = ecdsa.SigningKey.from_secret_exponent(scalar, P256)
    return keypair, iterations

@pytest.fixture(scope="module", params=["u2f"])
def solo(request, device):
    sc = SoloClient()
    sc.find_device(device.dev)
    if request.param == "u2f":
        sc.use_u2f()
    else:
        sc.use_hid()
    return sc

IS_EXPERIMENTAL = '--experimental' in sys.argv
IS_NFC = '--nfc' in sys.argv

@pytest.mark.skipif(
    IS_NFC,
    reason="Wrong transport"
)
class TestSolo(object):
    def test_solo(self, solo):
        pass

    def test_rng(self, solo):

        total = 1024 * 16
        entropy = b""
        while len(entropy) < total:
            entropy += solo.get_rng()

        s = shannon_entropy(entropy)
        assert s > 7.98
        print("Entropy is %.5f bits per byte." % s)

    def test_version(self, solo):
        assert len(solo.solo_version()) == 4

    def test_version_hid(self, solo):
        data = solo.send_data_hid(0x61, b'')
        assert len(data) == 4
        print(f'Version is {data[0]}.{data[1]}.{data[2]} locked?=={data[3]}')


    def test_bootloader_not(self, solo):
        with pytest.raises(ApduError) as e:
            solo.write_flash(0x0, b"1234")

    def test_fido2_bridge(self, solo):
        exchange = solo.exchange
        solo.exchange = solo.exchange_fido2

        req = SoloClient.format_request(SoloExtension.version, 0, b"A" * 16)
        a = solo.ctap2.get_assertion(
            solo.host, b"B" * 32, [{"id": req, "type": "public-key"}]
        )

        assert a.auth_data.rp_id_hash == sha256(solo.host.encode("utf8"))
        assert a.credential["id"] == req
        assert (a.auth_data.flags & 0x5) == 0x5

        solo.get_rng()

        solo.exchange = exchange

    @pytest.mark.skipif(not IS_EXPERIMENTAL, reason="Experimental")
    def test_load_external_key_wrong_length(self,solo, ):
        ext_key_cmd = 0x62
        with pytest.raises(CtapError) as e:
            solo.send_data_hid(ext_key_cmd, b'\x01' + b'wrong length'*2)
        assert(e.value.code == CtapError.ERR.INVALID_LENGTH)

    @pytest.mark.skipif(not IS_EXPERIMENTAL, reason="Experimental")
    def test_load_external_key_wrong_length_ext_state(self,solo, ):

        key_A = b'A' * 32
        key_B = b'B' * 32
        ext_state1 = b"C" * 43
        ext_state2 = b"C" * 44
        version = b'\x01'

        ext_key_cmd = 0x62
        print ('Enter user presence THREE times.')
        solo.send_data_hid(ext_key_cmd, version + key_A + ext_state1)

        with pytest.raises(CtapError) as e:
            solo.send_data_hid(ext_key_cmd, version + key_A + ext_state2)
        assert(e.value.code == CtapError.ERR.INVALID_LENGTH)

    @pytest.mark.skipif(not IS_EXPERIMENTAL, reason="Experimental")
    def test_load_external_key_invalidate_old_cred(self,solo, device, MCRes, GARes):
        ext_key_cmd = 0x62
        verify(MCRes, GARes)
        print ('Enter user presence THREE times.')
        solo.send_data_hid(ext_key_cmd, b'\x01' + b'Z' * 32 + b'dicekeys key')

        # Old credential should not exist now.
        with pytest.raises(CtapError) as e:
            ga_bad_req = FidoRequest(GARes)
            device.sendGA(*ga_bad_req.toGA())
        assert(e.value.code == CtapError.ERR.NO_CREDENTIALS)



    @pytest.mark.skipif(not IS_EXPERIMENTAL, reason="Experimental")
    def test_load_external_key(self,solo, device,):
        
        key_A = b'A' * 32
        key_B = b'B' * 32
        ext_state = b"I'm a dicekey key"
        version = b'\x01'

        ext_key_cmd = 0x62
        print ('Enter user presence THREE times.')
        solo.send_data_hid(ext_key_cmd, version + key_A + ext_state)

        # New credential works.
        mc_A_req = FidoRequest()
        mc_A_res = device.sendMC(*mc_A_req.toMC())

        allow_list = [{"id":mc_A_res.auth_data.credential_data.credential_id, "type":"public-key"}]
        ga_A_req = FidoRequest(mc_A_req, allow_list=allow_list)
        ga_A_res = device.sendGA(*FidoRequest(ga_A_req).toGA())

        verify(mc_A_res, ga_A_res, ga_A_req.cdh)

        # Load up Key B and verify cred A doesn't exist.
        print ('Enter user presence THREE times.')
        solo.send_data_hid(ext_key_cmd, version + key_B + ext_state)
        with pytest.raises(CtapError) as e:
            ga_A_res = device.sendGA(*FidoRequest(ga_A_req).toGA())
        assert(e.value.code == CtapError.ERR.NO_CREDENTIALS)

        # Load up Key A and verify cred A is back.
        print ('Enter user presence THREE times.')
        solo.send_data_hid(ext_key_cmd, version + key_A + ext_state)
        ga_A_res = device.sendGA(*FidoRequest(ga_A_req).toGA())
        verify(mc_A_res, ga_A_res, ga_A_req.cdh)

    @pytest.mark.skipif(not IS_EXPERIMENTAL, reason="Experimental")
    def test_ext_state_in_credential_id(self,solo, device,):
        
        key_A = b'A' * 32
        ext_state = b"I'm a dicekey key abc1234!!@@##"
        version = b'\x01'

        ext_key_cmd = 0x62
        print ('Enter user presence THREE times.')
        solo.send_data_hid(ext_key_cmd, version + key_A + ext_state)

        # New credential works.
        mc_A_req = FidoRequest()
        mc_A_res = device.sendMC(*mc_A_req.toMC())

        assert ext_state in mc_A_res.auth_data.credential_data.credential_id

    @pytest.mark.skipif(not IS_EXPERIMENTAL, reason="Experimental")
    def test_backup_credential_is_generated_correctly(self,solo, device,):
        
        key_A = b'A' * 32
        ext_state = b"I'm a dicekey key!"
        version = b'\x01'

        ext_key_cmd = 0x62
        print ('Enter user presence THREE times.')
        solo.send_data_hid(ext_key_cmd, version + key_A + ext_state)

        # New credential works.
        mc_A_req = FidoRequest()
        mc_A_res = device.sendMC(*mc_A_req.toMC())

        credId = mc_A_res.auth_data.credential_data.credential_id
        uniqueId = credId[1:1+32]

        extStateInCredId = credId[33:33 + len(ext_state)]

        soloExtStateFieldSize = 43
        credMacInCredId = credId[33 + soloExtStateFieldSize: 33 + soloExtStateFieldSize + 32]

        rpIdHash = sha256(mc_A_req.rp['id'].encode('utf8'))
        print("rp:", mc_A_req.rp['id'])
        from binascii import hexlify
        print("rpIdHash:", hexlify(rpIdHash))
        print("uniqueId:", hexlify(uniqueId))

        assert version[0] == credId[0]
        assert ext_state == extStateInCredId

        credMac = hmac_sha256(key_A, rpIdHash + version + uniqueId + ext_state)
        print("recomputed mac:", hexlify(credMac))
        print("recv'd mac    :", hexlify(credMacInCredId))

        assert credMac == credMacInCredId

        credentialSeed = hmac_sha256(key_A, credMac)
        print('Computed private key:', hexlify(credentialSeed))
        key_pair = keypair_from_seed(credentialSeed)
        assert key_pair[1] == 0
        key_pair = key_pair[0]

        allow_list = [{"id": mc_A_res.auth_data.credential_data.credential_id, "type": "public-key"}]
        ga_req = FidoRequest(allow_list = allow_list)

        ga_res = device.sendGA(*ga_req.toGA())

        verify(mc_A_res, ga_res, ga_req.cdh)

        key_pair.verifying_key.verify(
            ga_res.signature,
            ga_res.auth_data + ga_req.cdh,
            sigdecode=ecdsa.util.sigdecode_der,
            hashfunc=hashlib.sha256
        )

