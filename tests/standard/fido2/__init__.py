import time
from functools import cmp_to_key

import tests
from fido2 import cbor

def cbor_key_to_representative(key):
    if isinstance(key, int):
        if key >= 0:
            return (0, key)
        return (1, -key)
    elif isinstance(key, bytes):
        return (2, key)
    elif isinstance(key, str):
        return (3, key)
    else:
        raise ValueError(key)


def cbor_str_cmp(a, b):
    if isinstance(a, str) or isinstance(b, str):
        a = a.encode("utf8")
        b = b.encode("utf8")

    if len(a) == len(b):
        for x, y in zip(a, b):
            if x != y:
                return x - y
        return 0
    else:
        return len(a) - len(b)


def cmp_cbor_keys(a, b):
    a = cbor_key_to_representative(a)
    b = cbor_key_to_representative(b)
    if a[0] != b[0]:
        return a[0] - b[0]
    if a[0] in (2, 3):
        return cbor_str_cmp(a[1], b[1])
    else:
        return (a[1] > b[1]) - (a[1] < b[1])


def TestCborKeysSorted(cbor_obj):
    # Cbor canonical ordering of keys.
    # https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form

    def test_cbor_level(parsed_cbor):
        if isinstance(parsed_cbor, dict):
            l = [x for x in parsed_cbor]
        else:
            l = parsed_cbor

        l_sorted = sorted(l[:], key=cmp_to_key(cmp_cbor_keys))

        for i in range(len(l)):

            if isinstance(parsed_cbor, dict) and not isinstance(l[i], (str, int)):
                raise ValueError(f"Cbor map key {l[i]} must be int or str for CTAP2")

            if l[i] != l_sorted[i]:
                raise ValueError(f"Cbor map item {i}: {l[i]} is out of order")

            value = None
            if isinstance(parsed_cbor, dict):
                value = parsed_cbor[l[i]]
            else: 
                value = i

            if value == '' or value == b'':
                raise ValueError(f"Cbor item {i}: {l[i]} is an empty string.")

            if i == '' or i == b'':
                raise ValueError(f"Cbor index {i}: {l[i]} is an empty string.")

            if isinstance(value, dict) or isinstance(value, list):
                # print('recursing', value)
                test_cbor_level(value)


        return l

    if isinstance(cbor_obj, bytes):
        cbor_obj = cbor.decode(cbor_obj)

    test_cbor_level(cbor_obj)


# hot patch cbor map parsing to test the order of keys in map
_load_map_old = cbor.load_map


def _load_map_new(ai, data):
    values, data = _load_map_old(ai, data)
    TestCborKeysSorted(values)
    return values, data

cbor.load_map = _load_map_new
cbor._DESERIALIZERS[5] = _load_map_new
