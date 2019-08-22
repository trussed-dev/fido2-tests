import os
import socket
import sys
import time
import struct
from binascii import hexlify
from fido2.pcsc import CtapPcscDevice, AID_FIDO, SW_SUCCESS

import pytest
from fido2.ctap import CtapError
from fido2.hid import CTAPHID
from tests.utils import FidoRequest

@pytest.mark.skipif(
    '--nfc' not in sys.argv,
    reason="Wrong transport"
)
class TestNFC(object):
    def test_select(self,device):
        apdu = struct.pack('!BBBBB', 0x00, 0xA4, 0x04, 0x00, len(AID_FIDO)) + AID_FIDO
        resp, sw1, sw2 = device.dev.apdu_exchange(apdu)
        print(hex(sw1),hex(sw2))
        assert (sw1, sw2) == SW_SUCCESS

    def test_bad_select(self,device):
        apdu = struct.pack('!BBBBB', 0x00, 0xA4, 0x04, 0x00, len(AID_FIDO) + 4) + AID_FIDO + b'1234'
        resp, sw1, sw2 = device.dev.apdu_exchange(apdu)
        print(hex(sw1),hex(sw2))
        assert (sw1, sw2) == (0x6a, 0x82)

    def test_bad_ins(self,device):
        apdu = struct.pack('!BBBBB', 0x00, 0x00, 0x04, 0x00, len(AID_FIDO)) + AID_FIDO
        resp, sw1, sw2 = device.dev.apdu_exchange(apdu)
        print(hex(sw1),hex(sw2))
        assert (sw1, sw2) == (0x6d, 0x00)

    def test_small_lt_250_byte_request(self,device):
        req = FidoRequest()
        device.sendMC(*req.toMC())
    
    def test_large_gt_250_byte_request(self,device):
        ex_id = b'A' * 125
        ex_type = 'B' * 125
        req = FidoRequest(
            exclude_list=[{"id": ex_id, "type": ex_type}],
        )
        device.sendMC(*req.toMC())
 


