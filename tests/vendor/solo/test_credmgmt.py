import pytest
import time
from fido2.ctap import CtapError
from fido2.ctap2 import CredentialManagement
from tests.utils import *
from binascii import hexlify

@pytest.fixture(params=["123456"])
def PinToken(request, device):
    device.reboot()
    device.reset()
    pin = request.param
    device.client.pin_protocol.set_pin(pin)
    return device.client.pin_protocol.get_pin_token(pin)


@pytest.fixture()
def MC_RK_Res(device, PinToken):
    req = FidoRequest()
    pin_auth = hmac_sha256(PinToken, req.cdh)[:16]
    rp = {"id": "ssh:", "name": "Bate Goiko"}
    req = FidoRequest(
        request=None, pin_protocol=1, pin_auth=pin_auth, rp=rp, options={"rk": True},
    )
    device.sendMC(*req.toMC())

    req = FidoRequest()
    pin_auth = hmac_sha256(PinToken, req.cdh)[:16]
    rp = {"id": "xakcop.com", "name": "John Doe"}
    req = FidoRequest(
        request=None, pin_protocol=1, pin_auth=pin_auth, rp=rp, options={"rk": True},
    )
    device.sendMC(*req.toMC())


@pytest.fixture()
def CredMgmt(device, PinToken):
    pin_protocol = 1
    return CredentialManagement(device.ctap2, pin_protocol, PinToken)


@pytest.fixture()
def CredMgmtWrongPinAuth(device, PinToken):
    pin_protocol = 1
    wrong_pt = bytearray(PinToken)
    wrong_pt[0] = (wrong_pt[0] + 1) % 256
    return CredentialManagement(device.ctap2, pin_protocol, bytes(wrong_pt))

def assert_cred_response_has_all_fields(cred_res):
    for i in (
        CredentialManagement.RESULT.USER,
        CredentialManagement.RESULT.CREDENTIAL_ID,
        CredentialManagement.RESULT.PUBLIC_KEY,
        CredentialManagement.RESULT.TOTAL_CREDENTIALS,
        CredentialManagement.RESULT.CRED_PROTECT,
        ):
        assert( i in cred_res )

class TestCredentialManagement(object):
    def test_get_info(self, info):
        assert('credMgmt' in info.options)
        assert(info.options['credMgmt'] == True)
        assert(0x7 in info)
        assert(info[0x7] > 1)
        assert(0x8 in info)
        assert(info[0x8] > 1)

    def test_get_metadata(self, CredMgmt, MC_RK_Res):
        metadata = CredMgmt.get_metadata()
        assert metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 2
        assert metadata[CredentialManagement.RESULT.MAX_REMAINING_COUNT] == 48

    def test_enumerate_rps(self, CredMgmt, MC_RK_Res):
        res = CredMgmt.enumerate_rps()
        assert len(res) == 2
        assert res[0][CredentialManagement.RESULT.RP]["id"] == "ssh:"
        assert res[0][CredentialManagement.RESULT.RP_ID_HASH] == sha256(b"ssh:")
        # Solo doesn't store rpId with the exception of "ssh:"
        assert res[1][CredentialManagement.RESULT.RP]["id"] == "xakcop.com"
        assert res[1][CredentialManagement.RESULT.RP_ID_HASH] == sha256(b"xakcop.com")

    def test_enumarate_creds(self, CredMgmt, MC_RK_Res):
        res = CredMgmt.enumerate_creds(sha256(b"ssh:"))
        assert len(res) == 1
        assert_cred_response_has_all_fields(res[0])
        res = CredMgmt.enumerate_creds(sha256(b"xakcop.com"))
        assert len(res) == 1
        assert_cred_response_has_all_fields(res[0])
        res = CredMgmt.enumerate_creds(sha256(b"missing.com"))
        assert not res

    def test_get_metadata_wrong_pinauth(self, device, CredMgmtWrongPinAuth, MC_RK_Res):
        cmd = lambda: CredMgmtWrongPinAuth.get_metadata()
        self._test_wrong_pinauth(device, CredMgmtWrongPinAuth, cmd)

    def test_rpbegin_wrong_pinauth(self, device, CredMgmtWrongPinAuth, MC_RK_Res):
        cmd = lambda: CredMgmtWrongPinAuth.enumerate_rps_begin()
        self._test_wrong_pinauth(device, CredMgmtWrongPinAuth, cmd)

    def test_rkbegin_wrong_pinauth(self, device, CredMgmtWrongPinAuth, MC_RK_Res):
        cmd = lambda: CredMgmtWrongPinAuth.enumerate_creds_begin(sha256(b"ssh:"))
        self._test_wrong_pinauth(device, CredMgmtWrongPinAuth, cmd)

    def test_rpnext_without_rpbegin(self, device, CredMgmt, MC_RK_Res):
        CredMgmt.enumerate_creds_begin(sha256(b"ssh:"))
        with pytest.raises(CtapError) as e:
            CredMgmt.enumerate_rps_next()
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

    def test_rknext_without_rkbegin(self, device, CredMgmt, MC_RK_Res):
        CredMgmt.enumerate_rps_begin()
        with pytest.raises(CtapError) as e:
            CredMgmt.enumerate_creds_next()
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

    def test_delete(self, device, PinToken, CredMgmt):

        # create a new RK
        req = FidoRequest()
        pin_auth = hmac_sha256(PinToken, req.cdh)[:16]
        rp = {"id": "example_3.com", "name": "John Doe 2"}
        req = FidoRequest(
            pin_protocol=1, pin_auth=pin_auth, options={"rk": True}, rp = rp,
        )
        reg = device.sendMC(*req.toMC())

        # make sure it works
        req = FidoRequest(rp = rp)
        auth = device.sendGA(*req.toGA())

        verify(reg, auth, req.cdh)

        # get the ID from enumeration
        creds = CredMgmt.enumerate_creds(reg.auth_data.rp_id_hash)
        for cred in creds:
            if cred[7]['id'] == reg.auth_data.credential_data.credential_id:
                break

        # delete it
        cred = {"id": cred[7]['id'], "type": "public-key"}
        CredMgmt.delete_cred( cred )

        # make sure it doesn't work
        req = FidoRequest(rp = rp)
        with pytest.raises(CtapError) as e:
            auth = device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

    def test_add_delete(self, device, PinToken, CredMgmt):
        """ Delete a credential in the 'middle' and ensure other credentials are not affected. """

        rp = {"id": "example_4.com", "name": "John Doe 3"}
        regs = []

        # create 3 new RK's
        for i in range(0,3):
            req = FidoRequest()
            pin_auth = hmac_sha256(PinToken, req.cdh)[:16]
            req = FidoRequest(
                pin_protocol=1, pin_auth=pin_auth, options={"rk": True}, rp = rp,
            )
            reg = device.sendMC(*req.toMC())
            regs.append(reg)

        # Check they all enumerate
        res = CredMgmt.enumerate_creds(regs[1].auth_data.rp_id_hash)
        assert len(res) == 3

        # delete the middle one
        creds = CredMgmt.enumerate_creds(reg.auth_data.rp_id_hash)
        for cred in creds:
            if cred[7]['id'] == regs[1].auth_data.credential_data.credential_id:
                break

        assert cred[7]['id'] == regs[1].auth_data.credential_data.credential_id

        cred = {"id": cred[7]['id'], "type": "public-key"}
        CredMgmt.delete_cred( cred )

        # Check one less enumerates
        res = CredMgmt.enumerate_creds(regs[0].auth_data.rp_id_hash)
        assert len(res) == 2

    def test_multiple_creds_per_multiple_rps(self, device, PinToken, CredMgmt, MC_RK_Res):
        res = CredMgmt.enumerate_rps()
        assert len(res) == 2

        new_rps = [
            {"id": "new_example_1.com", "name": "Example-3-creds"},
            {"id": "new_example_2.com", "name": "Example-3-creds"},
            {"id": "new_example_3.com", "name": "Example-3-creds"},
        ]

        # create 3 new credentials per RP
        for rp in new_rps:
            for i in range(0,3):
                req = FidoRequest()
                pin_auth = hmac_sha256(PinToken, req.cdh)[:16]
                req = FidoRequest(
                    pin_protocol=1, pin_auth=pin_auth, options={"rk": True}, rp = rp,
                )
                reg = device.sendMC(*req.toMC())

        res = CredMgmt.enumerate_rps()
        assert len(res) == 5

        for rp in res:
            if rp[3]['id'][:12] == 'new_example_':
                creds = CredMgmt.enumerate_creds(sha256( rp[3]['id'].encode('utf8') ))
                assert len(creds) == 3

    def test_multiple_enumeration(self, device, PinToken, MC_RK_Res, CredMgmt):
        """ Test enumerate still works after different commands """

        res = CredMgmt.enumerate_rps()

        expected_enumeration = {"xakcop.com": 1, "ssh:": 1}

        self._test_enumeration(CredMgmt, expected_enumeration)

        new_rps = [
            {"id": "example-2.com", "name": "Example-2-creds", "count": 2},
            {"id": "example-5.com", "name": "Example-5-creds", "count": 5},
            {"id": "example-4.com", "name": "Example-4-creds", "count": 4},
        ]

        # create 3 new credentials per RP
        for rp in new_rps:
            for i in range(0,rp['count']):
                req = FidoRequest()
                pin_auth = hmac_sha256(PinToken, req.cdh)[:16]
                req = FidoRequest(
                    pin_protocol=1, pin_auth=pin_auth, options={"rk": True}, rp = {
                        "id": rp["id"], "name": rp["name"]
                    },
                )
                reg = device.sendMC(*req.toMC())

            # Now expect creds from this RP
            expected_enumeration[rp['id']] = rp['count']

        self._test_enumeration(CredMgmt, expected_enumeration)
        self._test_enumeration(CredMgmt, expected_enumeration)

        metadata = CredMgmt.get_metadata()

        self._test_enumeration(CredMgmt, expected_enumeration)
        self._test_enumeration(CredMgmt, expected_enumeration)

        # delete one
        cred = CredMgmt.enumerate_creds(sha256( 'example-5.com'.encode('utf8') ))[0]
        cred = {"id": cred[7]['id'], "type": "public-key"}
        CredMgmt.delete_cred( cred )

        expected_enumeration['example-5.com'] -= 1

        self._test_enumeration(CredMgmt, expected_enumeration)
        self._test_enumeration(CredMgmt, expected_enumeration)

    def _test_enumeration(self, CredMgmt, rp_map):
        res = CredMgmt.enumerate_rps()
        assert len(rp_map.keys()) == len(res)

        for rp in res:
            creds = CredMgmt.enumerate_creds(sha256( rp[3]['id'].encode('utf8') ))
            assert len(creds) == rp_map[rp[3]['id']]

    def _test_wrong_pinauth(self, device, CredMgmtWrongPinAuth, cmd):
        for i in range(2):
            with pytest.raises(CtapError) as e:
                cmd()
            assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        with pytest.raises(CtapError) as e:
            cmd()
        assert e.value.code == CtapError.ERR.PIN_AUTH_BLOCKED

        device.reboot()
        time.sleep(.2)

        for i in range(2):
            with pytest.raises(CtapError) as e:
                cmd()
            assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        with pytest.raises(CtapError) as e:
            cmd()
        assert e.value.code == CtapError.ERR.PIN_AUTH_BLOCKED

        device.reboot()
        time.sleep(.2)

        for i in range(2):
            with pytest.raises(CtapError) as e:
                cmd()
            assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        with pytest.raises(CtapError) as e:
            cmd()
        assert e.value.code == CtapError.ERR.PIN_BLOCKED

class TestCredProtect(object):
    def test_credProtect_0(self,resetDevice):
        req = FidoRequest(extensions={"credProtect": 0}, options={"rk": True})
        res = resetDevice.sendMC(*req.toMC())

        if res.auth_data.extensions:
            assert "credProtect" not in res.auth_data.extensions

    def test_credProtect_1(self,device):
        req = FidoRequest(extensions={"credProtect": 1}, options={"rk": True})
        MCRes = device.sendMC(*req.toMC())

        assert MCRes.auth_data.extensions["credProtect"] == 1
        assert (MCRes.auth_data.flags & (1 << 2)) == 0

        req = FidoRequest(
            allow_list=[
                {"id": MCRes.auth_data.credential_data.credential_id, "type": "public-key"}
            ]
        )

        GARes = device.sendGA(*req.toGA())
        verify(MCRes, GARes, req.cdh)
        assert (GARes.auth_data.flags & (1 << 2)) == 0

    def test_credProtect_2_allow_list(self,device):
        """ credProtect level 2 shouldn't need UV if allow_list is specified """
        req = FidoRequest(extensions={"credProtect": 2}, options={"rk": True})
        MCRes = device.sendMC(*req.toMC())

        assert MCRes.auth_data.extensions["credProtect"] == 2
        assert (MCRes.auth_data.flags & (1 << 2)) == 0

        req = FidoRequest(
            allow_list=[
                {"id": MCRes.auth_data.credential_data.credential_id, "type": "public-key"}
            ]
        )

        GARes = device.sendGA(*req.toGA())
        verify(MCRes, GARes, req.cdh)
        assert (GARes.auth_data.flags & (1 << 2)) == 0

    def test_credProtect_2_no_allow_list(self,device):
        device.reset()
        req = FidoRequest(extensions={"credProtect": 2}, options={"rk": True})
        MCRes = device.sendMC(*req.toMC())

        assert MCRes.auth_data.extensions["credProtect"] == 2
        assert (MCRes.auth_data.flags & (1 << 2)) == 0

        req = FidoRequest()

        with pytest.raises(CtapError) as e:
            GARes = device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

    def test_credProtect_3_allow_list_and_no_allow_list(self,device):
        """ credProtect level 3 requires UV """
        device.reset()
        req = FidoRequest(extensions={"credProtect": 3}, options={"rk": True})
        MCRes = device.sendMC(*req.toMC())

        assert MCRes.auth_data.extensions["credProtect"] == 3
        assert (MCRes.auth_data.flags & (1 << 2)) == 0

        req = FidoRequest(
            allow_list=[
                {"id": MCRes.auth_data.credential_data.credential_id, "type": "public-key"}
            ]
        )

        with pytest.raises(CtapError) as e:
            GARes = device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

        req = FidoRequest()

        with pytest.raises(CtapError) as e:
            GARes = device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

    def test_credProtect_3_success(self,device):
        device.reset()

        # Set a PIN
        pin = '1234'
        device.client.pin_protocol.set_pin(pin)
        pin_token = device.client.pin_protocol.get_pin_token(pin)
        req = FidoRequest()
        pin_auth = hmac_sha256(pin_token, req.cdh)[:16]
        req = FidoRequest(req, pin_auth = pin_auth, pin_protocol = 1, extensions={"credProtect": 3}, options={"rk": True})

        MCRes = device.sendMC(*req.toMC())

        assert MCRes.auth_data.extensions["credProtect"] == 3
        assert (MCRes.auth_data.flags & (1 << 2)) != 0

        req = FidoRequest(
            pin = pin,
            pin_auth = pin_auth,
            allow_list=[
                {"id": MCRes.auth_data.credential_data.credential_id, "type": "public-key"}
            ]
        )

        GARes = device.sendGA(*req.toGA())
        assert (GARes.auth_data.flags & (1 << 2)) != 0
        verify(MCRes, GARes, req.cdh)

