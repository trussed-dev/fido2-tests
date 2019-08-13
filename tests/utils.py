import math
import random
import secrets

from fido2.ctap2 import ES256, AttestedCredentialData, PinProtocolV1
from fido2.utils import hmac_sha256, sha256

name_list = open("data/first-names.txt").readlines()


def shannon_entropy(data):
    s = 0.0
    total = len(data)
    for x in range(0, 256):
        freq = data.count(x)
        p = freq / total
        if p > 0:
            s -= p * math.log2(p)
    return s


def verify(reg, auth, cdh=None):
    credential_data = AttestedCredentialData(reg.auth_data.credential_data)
    if cdh is None:
        cdh = auth.request.cdh
    auth.verify(cdh, credential_data.public_key)
    assert auth.credential["id"] == reg.auth_data.credential_data.credential_id


def generate_rp():
    return {"id": "example.org", "name": "ExampleRP"}


def generate_user():

    # https://www.w3.org/TR/webauthn/#user-handle
    user_id_length = random.randint(1, 64)
    user_id = secrets.token_bytes(user_id_length)

    # https://www.w3.org/TR/webauthn/#dictionary-pkcredentialentity
    name = " ".join(random.choice(name_list).strip() for i in range(0, 3))
    icon = "https://www.w3.org/TR/webauthn/"
    display_name = "Displayed " + name

    return {"id": user_id, "name": name, "icon": icon, "displayName": display_name}


def generate_challenge():
    return secrets.token_bytes(32)


def get_key_params():
    return [{"type": "public-key", "alg": ES256.ALGORITHM}]


def generate_cdh():
    return b"123456789abcdef0123456789abcdef0"


def generate(param):
    if param == "rp":
        return generate_rp()
    if param == "user":
        return generate_user()
    if param == "challenge":
        return generate_challenge()
    if param == "cdh":
        return generate_cdh()
    if param == "key_params":
        return get_key_params()
    if param == "allow_list":
        return []
    return None


class Empty:
    pass


class FidoRequest:
    def __init__(self, request=None, **kwargs):

        if not isinstance(request, FidoRequest) and request is not None:
            request = request.request

        self.request = request

        for i in (
            "cdh",
            "key_params",
            "allow_list",
            "challenge",
            "rp",
            "user",
            "pin_protocol",
            "options",
            "appid",
            "exclude_list",
            "extensions",
            "pin_auth",
        ):
            self.save_attr(i, kwargs.get(i, Empty), request)

        if isinstance(self.rp, dict) and "id" in self.rp:
            if hasattr(self.rp["id"], "encode"):
                self.appid = sha256(self.rp["id"].encode("utf8"))

        # self.chal = sha256(self.challenge.encode("utf8"))

    def save_attr(self, attr, value, request):
        """
            Will assign attribute from source, in following priority:
                Argument, request object, generated
        """
        if value != Empty:
            setattr(self, attr, value)
        elif request is not None:
            setattr(self, attr, getattr(request, attr))
        else:
            setattr(self, attr, generate(attr))

    def toGA(self,):
        return [
            None if not self.rp else self.rp["id"],
            self.cdh,
            self.allow_list,
            self.extensions,
            self.options,
            self.pin_auth,
            self.pin_protocol,
        ]

    def toMC(self,):
        return [
            self.cdh,
            self.rp,
            self.user,
            self.key_params,
            self.exclude_list,
            self.extensions,
            self.options,
            self.pin_auth,
            self.pin_protocol,
        ]

        return args + self.get_optional_args()
