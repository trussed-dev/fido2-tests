import socket
from fido2.ctap import STATUS

from trezorlib import debuglink
from trezorlib.debuglink import TrezorClientDebugLink
from trezorlib.device import wipe as wipe_device
from trezorlib.transport import enumerate_devices


def load_client():
    devices = enumerate_devices()
    for device in devices:
        try:
            client = TrezorClientDebugLink(device)
            break
        except Exception:
            pass
    else:
        raise RuntimeError("No debuggable device found")

    wipe_device(client)
    debuglink.load_device_by_mnemonic(
        client,
        mnemonic=" ".join(["all"] * 12),
        pin=None,
        passphrase_protection=False,
        label="test",
        language="english",
    )
    client.clear_session()

    client.open()
    return client


TREZOR_CLIENT = load_client()


class DeviceSelectCredential:
    def __init__(self, number=1):
        self.number = number

    def __call__(self, status):
        if status != STATUS.UPNEEDED:
            return

        if self.number == 0:
            TREZOR_CLIENT.debug.press_no()
        else:
            for _ in range(self.number - 1):
                TREZOR_CLIENT.debug.swipe_left()
            TREZOR_CLIENT.debug.press_yes()
