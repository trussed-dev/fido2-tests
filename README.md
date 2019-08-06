# fido2-tests

Test suite for FIDO2, U2F, and other security key functions

# Installation

Need python 3.6+.


```
pip3 install -r requirements.txt
```

# Running the tests

Run all FIDO2, U2F, and HID tests.

```
python -m pytest tests/standard
```

Run vendor/model specific tests.

```
python -m pytest tests/vendor
```

# Running against simulation

To run tests against a "simulation" build of the Solo authenticator, supply the `--sim` option.

```
python -m pytest tests/standard --sim
```


