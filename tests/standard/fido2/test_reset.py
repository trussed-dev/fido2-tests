import time
import pytest
from fido2.ctap import CtapError

import tests


def test_reset(device):
    device.reset()

def test_reset_after_10s_fails(device):
    device.reboot()
    time.sleep(10.1)
    with pytest.raises(CtapError) as e:
        device.ctap2.reset()
    assert e.value.code == CtapError.ERR.NOT_ALLOWED
    

