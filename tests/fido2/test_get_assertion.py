import pytest

from fido2.ctap import CtapError
from fido2.utils import sha256, hmac_sha256

from tests.utils import *

def verify(reg,auth,cdh = None):
    credential_data = AttestedCredentialData(reg.auth_data.credential_data)
    cdh = auth.request.cdh
    auth.verify(cdh, credential_data.public_key)
    assert (
        auth.credential["id"] == reg.auth_data.credential_data.credential_id
    )


#with test_reset():
    #self.testReset()
#class TestGetAssertion():
        #allow_list = [
            #{
                #"id": prev_reg.auth_data.credential_data.credential_id,
                #"type": "public-key",
            #}
        #]
class TestGetAssertion(object):
    def test_get_assertion(self,device, MCRes, GARes):
        #allow_list = []
        #self.params = GetGAParams(allow_list = [allowListItem])
        #auth = device.sendGA(
            #*self.params,
        #)
        verify(MCRes, GARes)

    def test_assertion_auth_data(self,GARes):
        assert len(GARes.auth_data) == 37
        assert sha256(GARes.request.rp["id"].encode()) == GARes.auth_data.rp_id_hash

    def test_Check_that_AT_flag_is_not_set(self, GARes):
        assert (GARes.auth_data.flags & 0xF8) == 0

    def test_that_user_credential_and_numberOfCredentials_are_not_present(self,GARes):
        assert GARes.user == None
        assert GARes.number_of_credentials == None


    def test_send_GA_request_with_empty_allowList(self,device):
        with pytest.raises(CtapError) as e:
            device.sendGA(
                *FidoRequest(allow_list = []).toGA()
            )
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

    def test_GA_request_corrupt_credId(self,device,MCRes):
        # apply bit flip
        badid = list(MCRes.auth_data.credential_data.credential_id[:])
        badid[len(badid) // 2] = badid[len(badid) // 2] ^ 1
        badid = bytes(badid)

        allow_list = [{"id": badid, "type": "public-key"}]

        with pytest.raises(CtapError) as e:
            device.sendGA(
                *FidoRequest(allow_list = allow_list).toGA()
            )
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS


    def test_GA_request_missing_rp(self,device,GARes):
        with pytest.raises(CtapError) as e:
            device.sendGA(
                *FidoRequest(rp = None, request = GARes.request).toGA()
            )
        assert e.value.code == CtapError.ERR.MISSING_PARAMETER


        
#class TestGetAssertionErrors(object):

class TestGetAssertionAfterBoot(object):
    def test_assertion_after_reboot(self,rebootedDevice, MCRes, GARes):
        credential_data = AttestedCredentialData(MCRes.auth_data.credential_data)
        verify(MCRes, GARes)






        #self.testGA(
            #"Send GA request with bad RPID, expect error",
            #{"type": "wrong"},
            #cdh,
            #allow_list,
        #)

        #self.testGA(
            #"Send GA request with missing clientDataHash, expect MISSING_PARAMETER",
            #rp["id"],
            #None,
            #allow_list,
            #expectedError=CtapError.ERR.MISSING_PARAMETER,
        #)

        #self.testGA(
            #"Send GA request with bad clientDataHash, expect error",
            #rp["id"],
            #{"type": "wrong"},
            #allow_list,
        #)

        #self.testGA(
            #"Send GA request with bad allow_list, expect error",
            #rp["id"],
            #cdh,
            #{"type": "wrong"},
        #)

        #self.testGA(
            #"Send GA request with bad item in allow_list, expect error",
            #rp["id"],
            #cdh,
            #allow_list + ["wrong"],
        #)

        #self.testGA(
            #"Send GA request with unknown option, expect SUCCESS",
            #rp["id"],
            #cdh,
            #allow_list,
            #other={"options": {"unknown": True}},
            #expectedError=CtapError.ERR.SUCCESS,
        #)
        #with Test("Get info"):
            #info = self.ctap.get_info()

        #if "uv" in info.options:
            #if info.options["uv"]:
                #res = self.testGA(
                    #"Send GA request with uv set to true, expect SUCCESS",
                    #rp["id"],
                    #cdh,
                    #allow_list,
                    #other={"options": {"uv": True}},
                    #expectedError=CtapError.ERR.SUCCESS,
                #)
                #with Test("Check that UV flag is set in response"):
                    #assert res.auth_data.flags & (1 << 2)
        #if "up" in info.options:
            #if info.options["up"]:
                #res = self.testGA(
                    #"Send GA request with up set to true, expect SUCCESS",
                    #rp["id"],
                    #cdh,
                    #allow_list,
                    #other={"options": {"up": True}},
                    #expectedError=CtapError.ERR.SUCCESS,
                #)
            #with Test("Check that UP flag is set in response"):
                #assert res.auth_data.flags & 1

        #self.testGA(
            #"Send GA request with bogus type item in allow_list, expect SUCCESS",
            #rp["id"],
            #cdh,
            #allow_list + [{"type": "rot13", "id": b"1234"}],
            #expectedError=CtapError.ERR.SUCCESS,
        #)

        #self.testGA(
            #"Send GA request with item missing type field in allow_list, expect error",
            #rp["id"],
            #cdh,
            #allow_list + [{"id": b"1234"}],
        #)

        #self.testGA(
            #"Send GA request with item containing bad type field in allow_list, expect error",
            #rp["id"],
            #cdh,
            #allow_list + [{"type": b"public-key", "id": b"1234"}],
        #)

        #self.testGA(
            #"Send GA request with item containing bad id in allow_list, expect error",
            #rp["id"],
            #cdh,
            #allow_list + [{"type": b"public-key", "id": 42}],
        #)

        #self.testGA(
            #"Send GA request with item missing id in allow_list, expect error",
            #rp["id"],
            #cdh,
            #allow_list + [{"type": b"public-key"}],
        #)

        #self.testReset()

        #appid = sha256(rp["id"].encode("utf8"))
        #chal = sha256(challenge.encode("utf8"))
        #with Test("Send CTAP1 register request"):
            #u2f = U2FTests(self)
            #reg = u2f.register(chal, appid)
            #reg.verify(appid, chal)

        #with Test("Authenticate CTAP1"):
            #auth = u2f.authenticate(chal, appid, reg.key_handle)
            #auth.verify(appid, chal, reg.public_key)

        #auth = self.testGA(
            #"Authenticate CTAP1 registration with CTAP2",
            #rp["id"],
            #cdh,
            #[{"id": reg.key_handle, "type": "public-key"}],
            #expectedError=CtapError.ERR.SUCCESS,
        #)

        #with Test("Check assertion is correct"):
            #credential_data = AttestedCredentialData.from_ctap1(
                #reg.key_handle, reg.public_key
            #)
            #auth.verify(cdh, credential_data.public_key)
            #assert auth.credential["id"] == reg.key_handle




