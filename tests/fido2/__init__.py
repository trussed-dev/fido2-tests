import time

import tests


def reset():
    print("Resetting Authenticator...")
    dev = tests.get_device()
    try:
        dev.ctap2.reset()
    except CtapError:
        # Some authenticators need a power cycle
        print("You must power cycle authentictor.  Hit enter when done.")
        input()
        time.sleep(0.2)
        dev = tests.get_device(refresh=True)
        dev.ctap2.reset()
