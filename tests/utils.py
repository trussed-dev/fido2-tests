from fido2.ctap2 import ES256, PinProtocolV1, AttestedCredentialData


def generate_rp():
    return {"id": "example.org", "name": "ExampleRP"}

def generate_user():
    return {"id": b"user_id", "name": "A User"}

def generate_challenge():
    return "Y2hhbGxlbmdl"

def get_key_params():
    return [{"type": "public-key", "alg": ES256.ALGORITHM}]

def generate_cdh():
    return b"123456789abcdef0123456789abcdef0"

def generate(param):
    if param == 'rp':
        return generate_rp()
    if param == 'user':
        return generate_user()
    if param == 'challenge':
        return generate_challenge()
    if param == 'cdh':
        return generate_cdh()
    if param == 'key_params':
        return get_key_params()
    if param == 'allow_list':
        return []
    if param == 'pin_protocol':
        return 1

class Empty:
    pass

class FidoRequest():
    def __init__(self, **kwargs):

        request = kwargs.get('request', None)

        for i in ('cdh', 'key_params', 'allow_list', 'challenge', 'rp', 'user', 'pin_protocol'):
            self.save_attr(i, kwargs.get(i, Empty), request)

    def save_attr(self,attr,value,request):
        """
            Will assign attribute from source, in following priority: 
                Argument, request object, generated
        """
        if value != Empty:
            setattr(self, attr, value)
        elif request is not None:
            setattr(self, attr, getattr(request,attr))
        else:
            setattr(self, attr, generate(attr))


    def toGA(self,):
        return [None if not self.rp else self.rp['id'], self.cdh, self.allow_list]

    def toMC(self,):
        return [self.cdh, self.rp, self.user, self.key_params]




