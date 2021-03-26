import sys
import pytest
from fido2.ctap import CtapError
from fido2.utils import hmac_sha256, sha256

from tests.utils import *


class TestGetAssertion(object):
    def test_get_assertion(self, device, MCRes, GARes):
        verify(MCRes, GARes)

    def test_assertion_auth_data(self, GARes):
        assert len(GARes.auth_data) == 37
        assert sha256(GARes.request.rp["id"].encode()) == GARes.auth_data.rp_id_hash

    def test_Check_that_AT_flag_is_not_set(self, GARes):
        assert (GARes.auth_data.flags & 0xF8) == 0

    def test_that_user_credential_and_numberOfCredentials_are_not_present(self, GARes):
        assert GARes.user == None
        assert GARes.number_of_credentials == None

    def test_empty_allowList(self, device):
        with pytest.raises(CtapError) as e:
            device.sendGA(*FidoRequest(allow_list=[]).toGA())
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

    def test_get_assertion_allow_list_filtering_and_buffering(self, device):
        """ Check that authenticator filters and stores items in allow list correctly """
        allow_list = []

        rp1 = {"id": "rp1.com", "name": "rp1.com"}
        rp2 = {"id": "rp2.com", "name": "rp2.com"}
        req1 = FidoRequest(rp=rp1)
        req2 = FidoRequest(rp=rp2)

        rp1_registrations = []
        rp2_registrations = []
        rp1_assertions = []
        rp2_assertions = []

        for i in range(0,4):
            res = device.sendMC(*req1.toMC())
            rp1_registrations.append(res)
            allow_list.append({
                "id": res.auth_data.credential_data.credential_id[:],
                "type": "public-key",
            })

        for i in range(0,6):
            res = device.sendMC(*req2.toMC())
            rp2_registrations.append(res)
            allow_list.append({
                "id": res.auth_data.credential_data.credential_id[:],
                "type": "public-key",
            })

        req1 = FidoRequest(req1, allow_list = allow_list)
        req2 = FidoRequest(req2, allow_list = allow_list)

        # Should authenticate to all credentials matching rp1
        ga_res1 = device.sendGA(*req1.toGA())
        assert ga_res1.number_of_credentials == len(rp1_registrations)

        rp1_assertions.append(ga_res1)
        for i in range(len(rp1_registrations) - 1):
            rp1_assertions.append(device.ctap2.get_next_assertion())

        # Should authenticate to all credentials matching rp2
        ga_res2 = device.sendGA(*req2.toGA())
        assert ga_res2.number_of_credentials == len(rp2_registrations)

        rp2_assertions.append(ga_res2)
        for i in range(len(rp2_registrations) - 1):
            rp2_assertions.append(device.ctap2.get_next_assertion())

        # Assertions return in order of most recently created credential.
        rp1_assertions.reverse()
        rp2_assertions.reverse()

        for (reg, auth) in zip(rp1_registrations, rp1_assertions):
            verify(reg, auth, req1.cdh)

        for (reg, auth) in zip(rp2_registrations, rp2_assertions):
            verify(reg, auth, req2.cdh)

    def test_corrupt_credId(self, device, MCRes):
        # apply bit flip
        badid = list(MCRes.auth_data.credential_data.credential_id[:])
        badid[len(badid) // 2] = badid[len(badid) // 2] ^ 1
        badid = bytes(badid)

        allow_list = [{"id": badid, "type": "public-key"}]

        with pytest.raises(CtapError) as e:
            device.sendGA(*FidoRequest(allow_list=allow_list).toGA())
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

    def test_mismatched_rp(self, device, GARes):
        rp_id = GARes.request.rp["id"][:]
        rp_name = GARes.request.rp["name"][:]
        rp_id += ".com"

        mismatch_rp = {"id": rp_id, "name": rp_name}

        with pytest.raises(CtapError) as e:
            device.sendGA(*FidoRequest(GARes, rp=mismatch_rp).toGA())
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS

    def test_missing_rp(self, device, GARes):
        with pytest.raises(CtapError) as e:
            device.sendGA(*FidoRequest(GARes, rp=None).toGA())
        assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    def test_bad_rp(self, device, GARes):

        with pytest.raises(CtapError) as e:
            device.sendGA(*FidoRequest(GARes, rp={"id": {"type": "wrong"}}).toGA())

    def test_missing_cdh(self, device, GARes):
        with pytest.raises(CtapError) as e:
            device.sendGA(*FidoRequest(GARes, cdh=None).toGA())
        assert e.value.code == CtapError.ERR.MISSING_PARAMETER

    def test_bad_cdh(self, device, GARes):
        with pytest.raises(CtapError) as e:
            device.sendGA(*FidoRequest(GARes, cdh={"type": "wrong"}).toGA())

    def test_bad_allow_list(self, device, GARes):
        with pytest.raises(CtapError) as e:
            device.sendGA(*FidoRequest(GARes, allow_list={"type": "wrong"}).toGA())

    def test_bad_allow_list_item(self, device, GARes):
        with pytest.raises(CtapError) as e:
            device.sendGA(
                *FidoRequest(
                    GARes, allow_list=["wrong"] + GARes.request.allow_list
                ).toGA()
            )

    def test_unknown_option(self, device, GARes):
        device.sendGA(*FidoRequest(GARes, options={"unknown": True}).toGA())

    @pytest.mark.skipif(
        "trezor" in sys.argv,
        reason="User verification flag is intentionally set to true on Trezor even when user verification is not configured. (Otherwise some services refuse registration without giving a reason.)",
    )
    def test_option_uv(self, device, info, GARes):
        if "uv" in info.options:
            if info.options["uv"]:
                res = device.sendGA(*FidoRequest(GARes, options={"uv": True}).toGA())
                assert res.auth_data.flags & (1 << 2)

    def test_option_up(self, device, info, GARes):
        if "up" in info.options:
            if info.options["up"]:
                res = device.sendGA(*FidoRequest(GARes, options={"up": True}).toGA())
                assert res.auth_data.flags & (1 << 0)

    def test_allow_list_fake_item(self, device, GARes):
        device.sendGA(
            *FidoRequest(
                GARes,
                allow_list=[{"type": "rot13", "id": b"1234"}]
                + GARes.request.allow_list,
            ).toGA()
        )

    def test_allow_list_missing_field(self, device, GARes):
        with pytest.raises(CtapError) as e:
            device.sendGA(
                *FidoRequest(
                    GARes, allow_list=[{"id": b"1234"}] + GARes.request.allow_list
                ).toGA()
            )

    def test_allow_list_field_wrong_type(self, device, GARes):
        with pytest.raises(CtapError) as e:
            device.sendGA(
                *FidoRequest(
                    GARes,
                    allow_list=[{"type": b"public-key", "id": b"1234"}]
                    + GARes.request.allow_list,
                ).toGA()
            )

    def test_allow_list_id_wrong_type(self, device, GARes):
        with pytest.raises(CtapError) as e:
            device.sendGA(
                *FidoRequest(
                    GARes,
                    allow_list=[{"type": "public-key", "id": 42}]
                    + GARes.request.allow_list,
                ).toGA()
            )

    def test_allow_list_missing_id(self, device, GARes):
        with pytest.raises(CtapError) as e:
            device.sendGA(
                *FidoRequest(
                    GARes,
                    allow_list=[{"type": "public-key"}] + GARes.request.allow_list,
                ).toGA()
            )

    def test_user_presence_option_false(self, device, MCRes, GARes):
        from cryptography.exceptions import InvalidSignature

        res = device.sendGA(*FidoRequest(GARes, options={"up": False}).toGA())

        try:
            verify(MCRes, res, GARes.request.cdh)
        except InvalidSignature:
            if "trezor" not in sys.argv:
                raise

        if "--nfc" not in sys.argv:
            assert (res.auth_data.flags & 1) == 0


@pytest.mark.skipif("trezor" in sys.argv, reason="Reboot is not supported on Trezor.")
class TestGetAssertionAfterBoot(object):
    def test_assertion_after_reboot(self, rebootedDevice, MCRes, GARes):
        credential_data = AttestedCredentialData(MCRes.auth_data.credential_data)
        verify(MCRes, GARes)
