import struct, time

import pytest

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client
from fido2.utils import Timeout

from solo.fido2 import force_udp_backend

__device = None

origin = "https://solokeys.com"


class Packet(object):
    def __init__(self, data):
        self.data = data

    def ToWireFormat(self,):
        return self.data

    @staticmethod
    def FromWireFormat(pkt_size, data):
        return Packet(data)


def cid():
    return __device._dev.cid


def set_cid(cid):
    if not isinstance(cid, (bytes, bytearray)):
        cid = struct.pack("%dB" % len(cid), *[ord(x) for x in cid])
    __device._dev.cid = cid


def recv_raw():
    with Timeout(1.0):
        cmd, payload = __device._dev.InternalRecv()
    return cmd, payload


def send_data(cmd, data):
    if not isinstance(data, bytes):
        data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
    with Timeout(1.0) as event:
        return __device.call(cmd, data, event)


def send_raw(data, cid=None):
    if cid is None:
        cid = __device._dev.cid
    elif not isinstance(cid, bytes):
        cid = struct.pack("%dB" % len(cid), *[ord(x) for x in cid])
    if not isinstance(data, bytes):
        data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
    data = cid + data
    l = len(data)
    if l != 64:
        pad = "\x00" * (64 - l)
        pad = struct.pack("%dB" % len(pad), *[ord(x) for x in pad])
        data = data + pad
    data = list(data)
    assert len(data) == 64
    __device._dev.InternalSendPacket(Packet(data))


def send_magic_reboot():
    """
    For use in simulation and testing.  Random bytes that authentictor should detect
    and then restart itself.
    """
    magic_cmd = (
        b"\xac\x10\x52\xca\x95\xe5\x69\xde\x69\xe0\x2e\xbf"
        + b"\xf3\x33\x48\x5f\x13\xf9\xb2\xda\x34\xc5\xa8\xa3"
        + b"\x40\x52\x66\x97\xa9\xab\x2e\x0b\x39\x4d\x8d\x04"
        + b"\x97\x3c\x13\x40\x05\xbe\x1a\x01\x40\xbf\xf6\x04"
        + b"\x5b\xb2\x6e\xb7\x7a\x73\xea\xa4\x78\x13\xf6\xb4"
        + b"\x9a\x72\x50\xdc"
    )
    __device.dev._dev.InternalSendPacket(Packet(magic_cmd))


def reboot():
    if is_simulation:
        print("Sending restart command...")
        self.send_magic_reboot()
        Tester.delay(0.25)
    else:
        print("Please reboot authentictor and hit enter")
        input()
        self.find_device(self.nfc_interface_only)


def find_device(nfcInterfaceOnly=False):
    print(is_simulation)
    if is_simulation:
        print("FORCE UDP")
        force_udp_backend()
    dev = None
    nfcInterfaceOnly
    if not nfcInterfaceOnly:
        print("--- HID ---")
        print(list(CtapHidDevice.list_devices()))
        dev = next(CtapHidDevice.list_devices(), None)

    if not dev:
        from fido2.pcsc import CtapPcscDevice

        print("--- NFC ---")
        print(list(CtapPcscDevice.list_devices()))
        dev = next(CtapPcscDevice.list_devices(), None)

    if not dev:
        raise RuntimeError("No FIDO device found")

    return Fido2Client(dev, origin)


def set_device(dev):
    __device = dev


def _get_device(refresh=False):

    print(0)
    dev = find_device()
    print(1, dev)
    yield dev

    while True:
        if refresh:
            print("REFRESH")
            dev = find_device()
        print(2, dev)
        yield dev


def get_device(*args):
    time.sleep(0.5)
    return next(_get_device(*args))
