import time

import pytest
from fido2.ctap import CtapError
from tests.utils import DeviceSelectCredential
import tests


def test_reset(device):
    device.reset()

def test_reset_window(device):
    print("Waiting 11s before sending reset...")
    time.sleep(11)
    with pytest.raises(CtapError) as e:
        device.ctap2.reset(on_keepalive=DeviceSelectCredential(1))
    assert e.value.code == CtapError.ERR.NOT_ALLOWED
