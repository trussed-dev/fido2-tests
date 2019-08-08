import pytest

from fido2.ctap import CtapError

from tests.utils import *


def test_credential_resets(device, MCRes, GARes):
    verify(MCRes, GARes)
    device.reset()
    with pytest.raises(CtapError) as e:
        new_auth = device.sendGA(*FidoRequest(GARes).toGA())
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS
