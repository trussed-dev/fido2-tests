import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import CredentialManagement
from tests.utils import *


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
        assert res[1][CredentialManagement.RESULT.RP]["id"] == ""
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

        # delete it
        cred = {"id": reg.auth_data.credential_data.credential_id, "type": "public-key"}
        CredMgmt.delete_cred( cred )

        # make sure it doesn't work
        req = FidoRequest(rp = rp)
        with pytest.raises(CtapError) as e:
            auth = device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS


    def _test_wrong_pinauth(self, device, CredMgmtWrongPinAuth, cmd):
        for i in range(2):
            with pytest.raises(CtapError) as e:
                cmd()
            assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        with pytest.raises(CtapError) as e:
            cmd()
        assert e.value.code == CtapError.ERR.PIN_AUTH_BLOCKED

        device.reboot()

        for i in range(2):
            with pytest.raises(CtapError) as e:
                cmd()
            assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

        with pytest.raises(CtapError) as e:
            cmd()
        assert e.value.code == CtapError.ERR.PIN_AUTH_BLOCKED

        device.reboot()

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

        print('cred res:',res)
        print('auth_data:',res.auth_data)
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

