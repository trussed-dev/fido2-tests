import pytest

from fido2 import cbor
from fido2.ctap import CtapError


@pytest.fixture(scope="session")
def info(device):
    info = device.ctap2.get_info()
    print("data:", bytes(info))
    print("decoded:", cbor.decode_from(bytes(info)))
    return info


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

def test_Check_uv_option(device, info, MCParams):
    if "uv" in info.options:
        if info.options["uv"]:
            device.sendMC(
                *MCParams,
                options = {"uv": True},
            )

def test_Check_up_option(device,info,MCParams):
    if "up" in info.options:
        if info.options["up"]:
            with pytest.raises(CtapError) as e:
                device.sendMC(
                    *MCParams,
                    options = {"up": True},
                )
            assert e.value.code == CtapError.ERR.INVALID_OPTION
