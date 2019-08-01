import tests

from fido2.ctap import CtapError


def test_reset(device):
    device.reset()
