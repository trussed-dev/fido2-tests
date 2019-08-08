import pytest

from fido2 import cbor
from fido2.ctap import CtapError

from tests.utils import *


def test_get_info(info):
    pass


def test_get_info_version(info):
    assert "FIDO_2_0" in info.versions


def test_Check_pin_protocols_field(info):
    if len(info.pin_protocols):
        assert sum(info.pin_protocols) > 0


def test_Check_options_field(info):
    for x in info.options:
        assert info.options[x] in [True, False]


def test_Check_uv_option(device, info):
    if "uv" in info.options:
        if info.options["uv"]:
            device.sendMC(*FidoRequest().toMC(), options={"uv": True})


def test_Check_up_option(device, info):
    if "up" in info.options:
        if info.options["up"]:
            with pytest.raises(CtapError) as e:
                device.sendMC(*FidoRequest(options={"up": True}).toMC())
            assert e.value.code == CtapError.ERR.INVALID_OPTION
