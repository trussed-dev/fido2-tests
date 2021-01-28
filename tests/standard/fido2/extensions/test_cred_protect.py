import pytest

from tests.utils import FidoRequest 


@pytest.fixture(scope="class")
def MCCredProtect(
    resetDevice,
):
    req = FidoRequest(extensions={"credProtect": 1})
    res = resetDevice.sendMC(*req.toMC())
    setattr(res, "request", req)
    return res


class TestCredProtect(object):
    def test_credprotect_make_credential(self, MCCredProtect):
        assert MCCredProtect.auth_data.extensions
        assert "credProtect" in MCCredProtect.auth_data.extensions
        assert MCCredProtect.auth_data.extensions["credProtect"] == True

    def test_hmac_secret_and_credProtect_make_credential(
        self, resetDevice, MCCredProtect
    ):

        req = FidoRequest(extensions={"credProtect": 1, "hmac-secret": True})
        res = resetDevice.sendMC(*req.toMC())
        setattr(res, "request", req)

        for ext in ["credProtect", "hmac-secret"]:
            assert res.auth_data.extensions
            assert ext in res.auth_data.extensions
            assert res.auth_data.extensions[ext] == True
