import math
from binascii import hexlify

import pytest
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError
from fido2.hid import CTAPHID
from fido2.utils import sha256
from solo.client import SoloClient
from solo.commands import SoloExtension

from tests.utils import shannon_entropy


@pytest.fixture(scope="module", params=["u2f"])
def solo(request, device):
    sc = SoloClient()
    sc.find_device(device.dev)
    if request.param == "u2f":
        sc.use_u2f()
    else:
        sc.use_hid()
    return sc


class TestSolo(object):
    def test_solo(self, solo):
        pass

    def test_rng(self, solo):

        total = 1024 * 16
        entropy = b""
        while len(entropy) < total:
            entropy += solo.get_rng()

        s = shannon_entropy(entropy)
        assert s > 7.98
        print("Entropy is %.5f bits per byte." % s)

    def test_version(self, solo):
        assert len(solo.solo_version()) == 3

    def test_bootloader_not(self, solo):
        with pytest.raises(ApduError) as e:
            solo.write_flash(0x0, b"1234")

    def test_fido2_bridge(self, solo):
        exchange = solo.exchange
        solo.exchange = solo.exchange_fido2

        req = SoloClient.format_request(SoloExtension.version, 0, b"A" * 16)
        a = solo.ctap2.get_assertion(
            solo.host, b"B" * 32, [{"id": req, "type": "public-key"}]
        )

        assert a.auth_data.rp_id_hash == sha256(solo.host.encode("utf8"))
        assert a.credential["id"] == req
        assert (a.auth_data.flags & 0x5) == 0x5

        assert len(solo.solo_version()) == 3
        solo.get_rng()

        solo.exchange = exchange

    # def test_bootloader(self,):
    # solo = SoloClient()
    # solo.find_device(self.dev)
    # solo.use_u2f()

    # memmap = (0x08005000, 0x08005000 + 198 * 1024 - 8)
    # data = b"A" * 64

    # with Test("Test version command"):
    # assert len(solo.bootloader_version()) == 3

    # with Test("Test write command"):
    # solo.write_flash(memmap[0], data)

    # for addr in (memmap[0] - 8, memmap[0] - 4, memmap[1], memmap[1] - 8):
    # with Test("Test out of bounds write command at 0x%04x" % addr):
    # try:
    # solo.write_flash(addr, data)
    # except CtapError as e:
    # assert e.code == CtapError.ERR.NOT_ALLOWED
