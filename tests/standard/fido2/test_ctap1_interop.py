import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ES256, AttestedCredentialData, PinProtocolV1
from fido2.utils import hmac_sha256, sha256

from tests.utils import FidoRequest


class TestCtap1WithCtap2(object):
    def test_ctap1_register(self, RegRes):
        RegRes.verify(RegRes.request.appid, RegRes.request.challenge)

    def test_ctap1_authenticate(self, RegRes, AuthRes):
        AuthRes.verify(
            AuthRes.request.appid, AuthRes.request.challenge, RegRes.public_key
        )

    def test_authenticate_ctap1_through_ctap2(self, device, RegRes):
        req = FidoRequest(allow_list=[{"id": RegRes.key_handle, "type": "public-key"}])

        auth = device.sendGA(*req.toGA())

        credential_data = AttestedCredentialData.from_ctap1(
            RegRes.key_handle, RegRes.public_key
        )
        auth.verify(req.cdh, credential_data.public_key)
        assert auth.credential["id"] == RegRes.key_handle
