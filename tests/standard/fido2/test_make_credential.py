import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ES256, AttestedCredentialData, PinProtocolV1
from fido2.cose import EdDSA
from fido2.utils import hmac_sha256, sha256

from tests.utils import FidoRequest, verify


class TestMakeCredential(object):
    def test_make_credential(self, MCRes):
        pass

    def test_attestation_format(self, MCRes):
        assert MCRes.fmt in ["packed", "tpm", "android-key", "adroid-safetynet"]

    def test_authdata_length(self, MCRes):
        assert len(MCRes.auth_data) >= 77

    def test_missing_cdh(self, device, MCRes):
        req = FidoRequest(MCRes, cdh=None)

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

        assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    def test_bad_type_cdh(self, device, MCRes):
        req = FidoRequest(MCRes, cdh=5)

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_missing_user(self, device, MCRes):
        req = FidoRequest(MCRes, user=None)

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

        assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    def test_bad_type_user(self, device, MCRes):
        req = FidoRequest(MCRes, user=b"1234abcdf")

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_missing_rp(self, device, MCRes):
        req = FidoRequest(MCRes, rp=None)

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

        assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    def test_bad_type_rp(self, device, MCRes):
        req = FidoRequest(MCRes, rp=b"1234abcdef")

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_missing_pubKeyCredParams(self, device, MCRes):
        req = FidoRequest(MCRes, key_params=None)

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

        assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    def test_bad_type_pubKeyCredParams(self, device, MCRes):
        req = FidoRequest(MCRes, key_params=b"1234a")

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_bad_type_excludeList(self, device, MCRes):
        req = FidoRequest(MCRes, exclude_list=8)

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_bad_type_extensions(self, device, MCRes):
        req = FidoRequest(MCRes, extensions=8)

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_bad_type_options(self, device, MCRes):
        req = FidoRequest(MCRes, options=8)

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_bad_type_rp_name(self, device, MCRes):
        req = FidoRequest(MCRes, rp={"id": "test.org", "name": 8, "icon": "icon"})

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_bad_type_rp_id(self, device, MCRes):
        req = FidoRequest(MCRes, rp={"id": 8, "name": "name", "icon": "icon"})

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_bad_type_rp_icon(self, device, MCRes):
        req = FidoRequest(MCRes, rp={"id": "test.org", "name": "name", "icon": 8})

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_bad_type_user_name(self, device, MCRes):
        req = FidoRequest(MCRes, user={"id": b"user_id", "name": 8})

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_bad_type_user_id(self, device, MCRes):
        req = FidoRequest(MCRes, user={"id": "user_id", "name": "name"})

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_bad_type_user_displayName(self, device, MCRes):
        req = FidoRequest(
            MCRes, user={"id": "user_id", "name": "name", "displayName": 8}
        )

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_bad_type_user_icon(self, device, MCRes):
        req = FidoRequest(MCRes, user={"id": "user_id", "name": "name", "icon": 8})

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_bad_type_pubKeyCredParams(self, device, MCRes):
        req = FidoRequest(MCRes, key_params=["wrong"])

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_missing_pubKeyCredParams_type(self, device, MCRes):
        req = FidoRequest(MCRes, key_params=[{"alg": ES256.ALGORITHM}])

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

        assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    def test_missing_pubKeyCredParams_alg(self, device, MCRes):
        req = FidoRequest(MCRes, key_params=[{"type": "public-key"}])

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

        assert e.value.code in [CtapError.ERR.MISSING_PARAMETER, CtapError.ERR.UNSUPPORTED_ALGORITHM]

    def test_bad_type_pubKeyCredParams_alg(self, device, MCRes):
        req = FidoRequest(MCRes, key_params=[{"alg": "7", "type": "public-key"}])

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_unsupported_algorithm(self, device, MCRes):
        req = FidoRequest(MCRes, key_params=[{"alg": 1337, "type": "public-key"}])

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

        assert e.value.code == CtapError.ERR.UNSUPPORTED_ALGORITHM

    def test_exclude_list(self, device, MCRes):
        req = FidoRequest(MCRes, exclude_list=[{"id": b"1234", "type": "rot13"}])

        device.sendMC(*req.toMC())

    def test_exclude_list2(self, device, MCRes):
        req = FidoRequest(
            MCRes,
            exclude_list=[{"id": b"1234", "type": "mangoPapayaCoconutNotAPublicKey"}],
        )

        device.sendMC(*req.toMC())

    def test_bad_type_exclude_list(self, device, MCRes):
        req = FidoRequest(MCRes, exclude_list=["1234"])

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_missing_exclude_list_type(self, device, MCRes):
        req = FidoRequest(MCRes, exclude_list=[{"id": b"1234"}])

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_missing_exclude_list_id(self, device, MCRes):
        req = FidoRequest(MCRes, exclude_list=[{"type": "public-key"}])

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_bad_type_exclude_list_id(self, device, MCRes):
        req = FidoRequest(MCRes, exclude_list=[{"type": "public-key", "id": "1234"}])

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_bad_type_exclude_list_type(self, device, MCRes):
        req = FidoRequest(MCRes, exclude_list=[{"type": b"public-key", "id": b"1234"}])

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

    def test_exclude_list_excluded(self, device, MCRes, GARes):
        req = FidoRequest(MCRes, exclude_list=GARes.request.allow_list)

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

        assert e.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED

    def test_unknown_option(self, device, MCRes):
        req = FidoRequest(MCRes, options={"unknown": False})
        print("MC", req.toMC())
        device.sendMC(*req.toMC())

    def test_eddsa(self, device):
        mc_req = FidoRequest(key_params=[{"type": "public-key", "alg": EdDSA.ALGORITHM}])
        try:
            mc_res = device.sendMC(*mc_req.toMC())
        except CtapError as e:
            if e.code == CtapError.ERR.UNSUPPORTED_ALGORITHM:
                print("ed25519 is not supported.  Skip this test.")
                return

        setattr(mc_res, "request", mc_req)

        allow_list = [{"id": mc_res.auth_data.credential_data.credential_id[:], "type": "public-key"}]

        ga_req = FidoRequest(allow_list=allow_list)
        ga_res = device.sendGA(*ga_req.toGA())
        setattr(ga_res, "request", ga_req)

        try:
            verify(mc_res, ga_res)
        except:
            # Print out extra details on failure
            from binascii import hexlify
            print('authdata', hexlify(ga_res.auth_data))
            print('cdh', hexlify(ga_res.request.cdh))
            print('sig', hexlify(ga_res.signature))
            from fido2.ctap2 import AttestedCredentialData 
            credential_data = AttestedCredentialData(mc_res.auth_data.credential_data)
            print('public key:', hexlify(credential_data.public_key[-2]))
            verify(mc_res, ga_res)
