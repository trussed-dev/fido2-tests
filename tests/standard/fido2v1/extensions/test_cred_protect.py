import pytest

from fido2.ctap import CtapError
from tests.utils import *

class CredProtect:
    UserVerificationOptional = 1
    UserVerificationOptionalWithCredentialId = 2
    UserVerificationRequired = 3

@pytest.fixture(scope="class")
def MCCredProtectOptional(
    resetDevice,
):
    req = FidoRequest(options = {'rk': True}, extensions={"credProtect": CredProtect.UserVerificationOptional})
    res = resetDevice.sendMC(*req.toMC())
    setattr(res, "request", req)
    return res

@pytest.fixture(scope="class")
def MCCredProtectOptionalList(
    resetDevice,
):
    req = FidoRequest(options = {'rk': True}, extensions={"credProtect": CredProtect.UserVerificationOptionalWithCredentialId})
    res = resetDevice.sendMC(*req.toMC())
    setattr(res, "request", req)
    return res

@pytest.fixture(scope="class")
def MCCredProtectRequired(
    resetDevice,
):
    req = FidoRequest(options = {'rk': True}, extensions={"credProtect": CredProtect.UserVerificationRequired})
    res = resetDevice.sendMC(*req.toMC())
    setattr(res, "request", req)
    return res



class TestCredProtect(object):
    def test_credprotect_make_credential_1(self, MCCredProtectOptional):
        assert MCCredProtectOptional.auth_data.extensions
        assert "credProtect" in MCCredProtectOptional.auth_data.extensions
        assert MCCredProtectOptional.auth_data.extensions["credProtect"] == 1

    def test_credprotect_make_credential_2(self, MCCredProtectOptionalList):
        assert MCCredProtectOptionalList.auth_data.extensions
        assert "credProtect" in MCCredProtectOptionalList.auth_data.extensions
        assert MCCredProtectOptionalList.auth_data.extensions["credProtect"] == 2

    def test_credprotect_make_credential_3(self, MCCredProtectRequired):
        assert MCCredProtectRequired.auth_data.extensions
        assert "credProtect" in MCCredProtectRequired.auth_data.extensions
        assert MCCredProtectRequired.auth_data.extensions["credProtect"] == 3

    def test_credprotect_optional_excluded(self, device, MCCredProtectOptional):
        """ CredProtectOptional Cred should be visible to be excluded with no UV """
        exclude_list = [
            {
                "id": MCCredProtectOptional.auth_data.credential_data.credential_id[:],
                "type": "public-key",
            }
        ]

        req = FidoRequest(MCCredProtectOptional, exclude_list= exclude_list)

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

        assert e.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED

    def test_credprotect_optional_list_excluded(self, device, MCCredProtectOptionalList):
        """ CredProtectOptionalList Cred should be visible to be excluded with no UV """
        exclude_list = [
            {
                "id": MCCredProtectOptionalList.auth_data.credential_data.credential_id[:],
                "type": "public-key",
            }
        ]

        req = FidoRequest(MCCredProtectOptionalList, exclude_list= exclude_list)

        with pytest.raises(CtapError) as e:
            device.sendMC(*req.toMC())

        assert e.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED

    def test_credprotect_required_not_excluded_with_no_uv(self, device, MCCredProtectRequired):
        """ CredProtectRequired Cred should NOT be visible to be excluded with no UV """
        exclude_list = [
            {
                "id": MCCredProtectRequired.auth_data.credential_data.credential_id[:],
                "type": "public-key",
            }
        ]

        req = FidoRequest(MCCredProtectRequired, exclude_list= exclude_list)

        # works
        device.sendMC(*req.toMC())

    def test_credprotect_optional_works_with_no_allowList_no_uv(self, device, MCCredProtectOptional):
        req = FidoRequest()

        # works
        res = device.sendGA(*req.toGA())

        # If there's only one credential, this is None
        assert res.number_of_credentials == None

    def test_credprotect_optional_and_list_works_no_uv(self, device, MCCredProtectOptional, MCCredProtectOptionalList, MCCredProtectRequired):
        allow_list = [
            {
                "id": MCCredProtectOptional.auth_data.credential_data.credential_id[:],
                "type": "public-key",
            },
            {
                "id": MCCredProtectOptionalList.auth_data.credential_data.credential_id[:],
                "type": "public-key",
            },
            {
                "id": MCCredProtectRequired.auth_data.credential_data.credential_id[:],
                "type": "public-key",
            },
        ]

        req = FidoRequest(allow_list = allow_list)

        # works
        res1 = device.sendGA(*req.toGA())
        assert res1.number_of_credentials in (None, 2)

        results = [res1]
        if res1.number_of_credentials == 2:
            res2 = device.ctap2.get_next_assertion()
            results.append(res2)

        # the required credProtect is not returned.
        for res in results:
            assert res.credential["id"] != MCCredProtectRequired.auth_data.credential_data.credential_id[:]

    def test_hmac_secret_and_credProtect_make_credential(
        self, resetDevice, MCCredProtectOptional
    ):

        req = FidoRequest(extensions={"credProtect": 1, "hmac-secret": True})
        res = resetDevice.sendMC(*req.toMC())
        setattr(res, "request", req)

        for ext in ["credProtect", "hmac-secret"]:
            assert res.auth_data.extensions
            assert ext in res.auth_data.extensions
            assert res.auth_data.extensions[ext] == True


class TestCredProtectUv:
    def test_credprotect_all_with_uv(self, device, MCCredProtectOptional, MCCredProtectOptionalList, MCCredProtectRequired):
        allow_list = [
            {
                "id": MCCredProtectOptional.auth_data.credential_data.credential_id[:],
                "type": "public-key",
            },
            {
                "id": MCCredProtectOptionalList.auth_data.credential_data.credential_id[:],
                "type": "public-key",
            },
            {
                "id": MCCredProtectRequired.auth_data.credential_data.credential_id[:],
                "type": "public-key",
            },
        ]

        pin = "123456A"
        req = FidoRequest()

        device.client.pin_protocol.set_pin(pin)
        pin_token = device.client.pin_protocol.get_pin_token(pin)
        pin_auth = hmac_sha256(pin_token, req.cdh)[:16]

        req = FidoRequest(req, pin_protocol=1, pin_auth=pin_auth, allow_list = allow_list)

        res1 = device.sendGA(*req.toGA())

        assert res1.number_of_credentials in (None, 3)

        if res1.number_of_credentials == 3:

            res2 = device.ctap2.get_next_assertion()
            res3 = device.ctap2.get_next_assertion()

