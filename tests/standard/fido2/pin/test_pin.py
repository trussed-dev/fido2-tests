import sys
import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ES256, AttestedCredentialData, PinProtocolV1

from tests.utils import *

PIN1 = "123456789A"
PIN2 = "ABCDEF"


@pytest.fixture(scope="class", params=[PIN1])
def SetPinRes(request, device):
    device.reset()

    pin = request.param
    req = FidoRequest()

    device.client.pin_protocol.set_pin(pin)

    req = FidoRequest(req, pin = pin)

    res = device.sendMC(*req.toMC())
    setattr(res, "request", req)
    setattr(res, "PIN", pin)
    return res


@pytest.fixture(scope="class")
def CPRes(request, device, SetPinRes):
    res = device.sendCP(1, PinProtocolV1.CMD.GET_KEY_AGREEMENT)
    return res


@pytest.fixture(scope="class")
def MCPinRes(device, SetPinRes):
    req = FidoRequest(SetPinRes)
    res = device.sendMC(*req.toMC())
    setattr(res, "request", req)
    return res


@pytest.fixture(scope="class")
def GAPinRes(device, MCPinRes):
    req = FidoRequest(MCPinRes)
    res = device.sendGA(*req.toGA())
    setattr(res, "request", req)
    return res


@pytest.mark.skipif(
    "trezor" in sys.argv, reason="ClientPin is not supported on Trezor."
)
class TestPin(object):
    def test_pin(self, CPRes):
        pass

    def test_set_pin_twice(self, device, SetPinRes):
        """ Setting pin when a pin is already set should result in error NotAllowed. """
        with pytest.raises(CtapError) as e:
            device.client.pin_protocol.set_pin('1234')

        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID


    def test_get_key_agreement_fields(self, CPRes):
        key = CPRes[1]
        assert "Is public key" and key[1] == 2
        assert "Is P256" and key[-1] == 1
        assert "Is ALG_ECDH_ES_HKDF_256" and key[3] == -25

        assert "Right key" and len(key[-3]) == 32 and isinstance(key[-3], bytes)

    def test_verify_flag(self, device, SetPinRes):
        reg = device.sendMC(*FidoRequest(SetPinRes).toMC())
        assert reg.auth_data.flags & (1 << 2)

    def test_get_no_pin_auth(self, device, SetPinRes):

        reg = device.sendMC(*FidoRequest(SetPinRes).toMC())
        allow_list = [
            {"type": "public-key", "id": reg.auth_data.credential_data.credential_id}
        ]
        auth = device.sendGA(
            *FidoRequest(
                SetPinRes, allow_list=allow_list, pin_auth=None, pin_protocol=None, pin = None,
            ).toGA()
        )

        assert not (auth.auth_data.flags & (1 << 2))

        with pytest.raises(CtapError) as e:
            reg = device.sendMC(
                *FidoRequest(SetPinRes, pin_auth=None, pin_protocol=None, pin = None).toMC()
            )

        assert e.value.code == CtapError.ERR.PIN_REQUIRED

    def test_zero_length_pin_auth(self, device, SetPinRes):
        with pytest.raises(CtapError) as e:
            reg = device.sendMC(*FidoRequest(SetPinRes, pin_auth=b"").toMC())
        assert e.value.code == CtapError.ERR.PIN_INVALID

        with pytest.raises(CtapError) as e:
            reg = device.sendGA(*FidoRequest(SetPinRes, pin_auth=b"").toGA())
        assert e.value.code == CtapError.ERR.PIN_INVALID

    def test_make_credential_no_pin(self, device, SetPinRes):
        with pytest.raises(CtapError) as e:
            reg = device.sendMC(*FidoRequest().toMC())
        assert e.value.code == CtapError.ERR.PIN_REQUIRED

    def test_get_assertion_no_pin(self, device, SetPinRes):
        with pytest.raises(CtapError) as e:
            reg = device.sendGA(*FidoRequest().toGA())
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

class TestChangePin:
    def test_change_pin(self, device, SetPinRes):
        device.client.pin_protocol.change_pin(PIN1, PIN2)

        req = FidoRequest(SetPinRes.request, pin = PIN2)

        reg = device.sendMC(*req.toMC())
        auth = device.sendGA(
            *FidoRequest(
                req,
                allow_list=[
                    {
                        "type": "public-key",
                        "id": reg.auth_data.credential_data.credential_id,
                    }
                ],
            ).toGA()
        )

        assert reg.auth_data.flags & (1 << 2)
        assert auth.auth_data.flags & (1 << 2)

        verify(reg, auth, cdh=SetPinRes.request.cdh)

class TestPinAttempts:
    @pytest.mark.skipif(
        "trezor" in sys.argv, reason="ClientPin is not supported on Trezor."
    )
    def test_pin_attempts(self, device, SetPinRes):
        # Flip 1 bit
        pin = SetPinRes.PIN
        pin_wrong = list(pin)
        c = pin[len(pin) // 2]

        pin_wrong[len(pin) // 2] = chr(ord(c) ^ 1)
        pin_wrong = "".join(pin_wrong)

        for i in range(1, 3):
            with pytest.raises(CtapError) as e:
                device.sendPP(pin_wrong)
            assert e.value.code == CtapError.ERR.PIN_INVALID

            print("Check there is %d pin attempts left" % (8 - i))
            res = device.ctap2.client_pin(1, PinProtocolV1.CMD.GET_RETRIES)
            assert res[3] == (8 - i)

        for i in range(1, 3):
            with pytest.raises(CtapError) as e:
                device.sendPP(pin_wrong)
            assert e.value.code == CtapError.ERR.PIN_AUTH_BLOCKED

        device.reboot()

        reg = device.sendMC(*FidoRequest(SetPinRes, pin = pin).toMC())

        res = device.ctap2.client_pin(1, PinProtocolV1.CMD.GET_RETRIES)
        assert res[3] == (8)
