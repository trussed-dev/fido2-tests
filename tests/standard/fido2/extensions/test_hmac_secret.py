import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fido2.utils import sha256, hmac_sha256
from fido2.ctap import CtapError

from tests.utils import FidoRequest, verify, shannon_entropy


def get_salt_params(cipher, shared_secret, salts):
    enc = cipher.encryptor()
    salt_enc = b""
    for salt in salts:
        salt_enc += enc.update(salt)
    salt_enc += enc.finalize()

    salt_auth = hmac_sha256(shared_secret, salt_enc)[:16]
    return salt_enc, salt_auth


salt1 = b"\xa5" * 32
salt2 = b"\x96" * 32
salt3 = b"\x03" * 32
salt4 = b"\x5a" * 16
salt5 = b"\x96" * 64


@pytest.fixture(scope="module")
def MCHmacSecret(resetDevice,):
    req = FidoRequest(extensions={"hmac-secret": True}, options={"rk": True})
    res = resetDevice.sendMC(*req.toMC())
    setattr(res, "request", req)
    return res


@pytest.fixture(scope="class")
def sharedSecret(device, MCHmacSecret):
    return device.client.pin_protocol.get_shared_secret()


@pytest.fixture(scope="class")
def cipher(device, sharedSecret):
    key_agreement, shared_secret = sharedSecret
    return Cipher(
        algorithms.AES(shared_secret), modes.CBC(b"\x00" * 16), default_backend()
    )


class TestHmacSecret(object):
    def test_hmac_secret_make_credential(self, MCHmacSecret):
        assert MCHmacSecret.auth_data.extensions
        assert "hmac-secret" in MCHmacSecret.auth_data.extensions
        assert MCHmacSecret.auth_data.extensions["hmac-secret"] == True

    def test_hmac_secret_info(self, info):
        assert "hmac-secret" in info.extensions

    def test_fake_extension(self, device):
        req = FidoRequest(extensions={"tetris": True})
        res = device.sendMC(*req.toMC())

    def test_get_shared_secret(self, sharedSecret):
        pass

    @pytest.mark.parametrize("salts", [(salt1,), (salt1, salt2)])
    def test_hmac_secret(self, device, MCHmacSecret, cipher, sharedSecret, salts):
        print("salts:", salts)
        key_agreement, shared_secret = sharedSecret
        salt_enc, salt_auth = get_salt_params(cipher, shared_secret, salts)
        req = FidoRequest(
            extensions={"hmac-secret": {1: key_agreement, 2: salt_enc, 3: salt_auth}}
        )
        auth = device.sendGA(*req.toGA())

        ext = auth.auth_data.extensions
        assert ext
        assert "hmac-secret" in ext
        assert isinstance(ext["hmac-secret"], bytes)
        assert len(ext["hmac-secret"]) == len(salts) * 32

        verify(MCHmacSecret, auth, req.cdh)

        dec = cipher.decryptor()
        key = dec.update(ext["hmac-secret"]) + dec.finalize()

        print(shannon_entropy(ext["hmac-secret"]))
        if len(salts) == 1:
            assert shannon_entropy(ext["hmac-secret"]) > 4.6
            assert shannon_entropy(key) > 4.6
        if len(salts) == 2:
            assert shannon_entropy(ext["hmac-secret"]) > 5.4
            assert shannon_entropy(key) > 5.4

    def test_missing_keyAgreement(self, device, cipher, sharedSecret):
        key_agreement, shared_secret = sharedSecret

        salt_enc, salt_auth = get_salt_params(cipher, shared_secret, (salt3,))

        req = FidoRequest(extensions={"hmac-secret": {2: salt_enc, 3: salt_auth}})

        with pytest.raises(CtapError):
            device.sendGA(*req.toGA())

    def test_missing_saltAuth(self, device, cipher, sharedSecret):
        key_agreement, shared_secret = sharedSecret

        salt_enc, salt_auth = get_salt_params(cipher, shared_secret, (salt3,))

        req = FidoRequest(extensions={"hmac-secret": {1: key_agreement, 2: salt_enc}})

        with pytest.raises(CtapError) as e:
            device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    def test_missing_saltEnc(self, device, cipher, sharedSecret):
        key_agreement, shared_secret = sharedSecret

        salt_enc, salt_auth = get_salt_params(cipher, shared_secret, (salt3,))

        req = FidoRequest(extensions={"hmac-secret": {1: key_agreement, 3: salt_auth}})

        with pytest.raises(CtapError) as e:
            device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    def test_bad_auth(self, device, cipher, sharedSecret):

        key_agreement, shared_secret = sharedSecret

        salt_enc, salt_auth = get_salt_params(cipher, shared_secret, (salt3,))

        bad_auth = list(salt_auth[:])
        bad_auth[len(bad_auth) // 2] = bad_auth[len(bad_auth) // 2] ^ 1
        bad_auth = bytes(bad_auth)

        req = FidoRequest(
            extensions={"hmac-secret": {1: key_agreement, 2: salt_enc, 3: bad_auth}}
        )

        with pytest.raises(CtapError) as e:
            device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.EXTENSION_FIRST

    @pytest.mark.parametrize("salts", [(salt4,), (salt4, salt5)])
    def test_invalid_salt_length(self, device, cipher, sharedSecret, salts):
        key_agreement, shared_secret = sharedSecret
        salt_enc, salt_auth = get_salt_params(cipher, shared_secret, salts)

        req = FidoRequest(
            extensions={"hmac-secret": {1: key_agreement, 2: salt_enc, 3: salt_auth}}
        )

        with pytest.raises(CtapError) as e:
            device.sendGA(*req.toGA())
        assert e.value.code == CtapError.ERR.INVALID_LENGTH
        # auth = self.testGA(
        # "Send GA request with incorrect salt length %d, expect INVALID_LENGTH"
        #% len(salt_enc),
        # rp["id"],
        # cdh,
        # other={
        # "extensions": {
        # "hmac-secret": {1: key_agreement, 2: salt_enc, 3: salt_auth}
        # }
        # },
        # expectedError=CtapError.ERR.INVALID_LENGTH,
        # )
