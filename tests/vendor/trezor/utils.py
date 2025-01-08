import os
from fido2.ctap import STATUS

from trezorlib import debuglink
from trezorlib.debuglink import TrezorClientDebugLink, LayoutType
from trezorlib.device import wipe as wipe_device
from trezorlib.transport import enumerate_devices, get_transport


def get_device():
    path = os.environ.get("TREZOR_PATH")
    interact = os.environ.get("INTERACT") == "1"
    if path:
        try:
            transport = get_transport(path)
            return TrezorClientDebugLink(transport, auto_interact=not interact)
        except Exception as e:
            raise RuntimeError("Failed to open debuglink for {}".format(path)) from e

    else:
        devices = enumerate_devices()
        for device in devices:
            try:
                return TrezorClientDebugLink(device, auto_interact=not interact)
            except Exception:
                pass
        else:
            raise RuntimeError("No debuggable device found")


def load_client():
    try:
        client = get_device()
    except RuntimeError:
        request.session.shouldstop = "No debuggable Trezor is available"
        pytest.fail("No debuggable Trezor is available")

    wipe_device(client)
    debuglink.load_device_by_mnemonic(
        client,
        mnemonic=" ".join(["all"] * 12),
        pin=None,
        passphrase_protection=False,
        label="test",
    )
    client.clear_session()

    client.open()
    return client


TREZOR_CLIENT = load_client()
CLICK_CONFIRM = (120, 120)
CLICK_UPPER = (120, 80)
CLICK_LOWER = (120, 140)
CLICK_CORNER = (215, 25)


class DeviceSelectCredential:
    def __init__(self, number=1):
        self.number = number

    def __call__(self, status):
        if status != STATUS.UPNEEDED:
            return

        # avoid homescreen
        TREZOR_CLIENT.debug.synchronize_at("Frame")

        if TREZOR_CLIENT.debug.layout_type is LayoutType.Ford:
            if self.number == 0:
                TREZOR_CLIENT.debug.press_no()
            else:
                for _ in range(self.number - 1):
                    TREZOR_CLIENT.debug.swipe_left()
                TREZOR_CLIENT.debug.press_yes()

        elif TREZOR_CLIENT.debug.layout_type is LayoutType.Mercury:
            if self.number < 1:
                # cancel
                TREZOR_CLIENT.debug.click(CLICK_CORNER)
                TREZOR_CLIENT.debug.click(CLICK_UPPER)
                return

            l = TREZOR_CLIENT.debug.read_layout()
            select_from_multiple = "FidoCredential" not in l.all_components()
            if select_from_multiple:
                # info screen
                TREZOR_CLIENT.debug.swipe_up()
                # 2 credentials per page
                index = self.number - 1
                for _ in range(index // 2):
                    TREZOR_CLIENT.debug.swipe_up()
                TREZOR_CLIENT.debug.click(
                    CLICK_UPPER if index % 2 == 0 else CLICK_LOWER
                )

            # credential details
            TREZOR_CLIENT.debug.swipe_up()
            # tap to confirm
            TREZOR_CLIENT.debug.click(CLICK_CONFIRM)

        else:
            raise NotImplementedError(TREZOR_CLIENT.debug.layout_type)
