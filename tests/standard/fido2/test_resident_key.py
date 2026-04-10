import sys
import pytest
import time
import random
from fido2.ctap import CtapError

from tests.utils import *


@pytest.fixture(scope="class", params=["", "123456"])
def SetPINRes(request, device, info):

    device.reset()

    pin = request.param
    req = FidoRequest()

    if pin:
        if "clientPin" in info.options:
            device.client.pin_protocol.set_pin(pin)
            req = FidoRequest(req, pin = pin)

    res = device.sendMC(*req.toMC())
    setattr(res, "request", req)
    return res


@pytest.fixture(scope="class")
def MC_RK_Res(device, SetPINRes):
    req = FidoRequest(SetPINRes, options={"rk": True})
    res = device.sendMC(*req.toMC())
    setattr(res, "request", req)
    return res


@pytest.fixture(scope="class")
def GA_RK_Res(device, MC_RK_Res):
    req = FidoRequest(MC_RK_Res, options=None)
    res = device.sendGA(*req.toGA())
    setattr(res, "request", req)
    return res


class TestResidentKeyPersistance(object):
    @pytest.mark.parametrize("do_reboot", [False, True])
    def test_user_info_returned_when_using_allowlist(self, device, MC_RK_Res, GA_RK_Res, do_reboot):
        assert "id" in GA_RK_Res.user.keys()

        allow_list = [
            {
                "id": MC_RK_Res.auth_data.credential_data.credential_id[:],
                "type": "public-key",
            }
        ]

        if do_reboot:
            device.reboot()

        ga_req = FidoRequest(allow_list=allow_list)
        ga_res = device.sendGA(*ga_req.toGA())
        setattr(ga_res, "request", ga_req)
        verify(MC_RK_Res, ga_res)

        assert MC_RK_Res.request.user["id"] == ga_res.user["id"]

class TestResidentKeyAfterReset(object):
    def test_with_allow_list_after_reset(self, device, MC_RK_Res, GA_RK_Res):
        assert "id" in GA_RK_Res.user.keys()

        allow_list = [
            {
                "id": MC_RK_Res.auth_data.credential_data.credential_id[:],
                "type": "public-key",
            }
        ]

        ga_req = FidoRequest(allow_list=allow_list)
        ga_res = device.sendGA(*ga_req.toGA())
        setattr(ga_res, "request", ga_req)
        verify(MC_RK_Res, ga_res)

        assert MC_RK_Res.request.user["id"] == ga_res.user["id"]

        device.reset()

        ga_req = FidoRequest(allow_list=allow_list)
        with pytest.raises(CtapError) as e:
            ga_res = device.sendGA(*ga_req.toGA())
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS



class TestResidentKey(object):
    def test_resident_key(self, MC_RK_Res, info):
        pass

    def test_resident_key_auth(self, MC_RK_Res, GA_RK_Res):
        verify(MC_RK_Res, GA_RK_Res)

    def test_user_info_returned(self, MC_RK_Res, GA_RK_Res):
        assert "id" in GA_RK_Res.user.keys()
        assert (
            MC_RK_Res.auth_data.credential_data.credential_id
            == GA_RK_Res.credential["id"]
        )
        assert MC_RK_Res.request.user["id"] == GA_RK_Res.user["id"]
        if not MC_RK_Res.request.pin_protocol or not GA_RK_Res.number_of_credentials:
            assert "id" in GA_RK_Res.user.keys() and len(GA_RK_Res.user.keys()) == 1
        else:
            assert MC_RK_Res.request.user == GA_RK_Res.user

    @pytest.mark.skipif(
        "trezor" in sys.argv,
        reason="Trezor does not support get_next_assertion() because it has a display.",
    )
    def test_multiple_rk_nodisplay(self, device, MC_RK_Res):
        auths = []
        regs = []
        # Use unique RP to not collide with other credentials
        rp = {"id": f"unique-{random.random()}.com", "name": "Example"}
        for i in range(0, 3):
            req = FidoRequest(MC_RK_Res, user=generate_user(), rp = rp)
            print(f"""
            {req.user}
            {req.cdh}
            {req.rp}
            """)
            res = device.sendMC(*req.toMC())
            regs.append(res)
            # time.sleep(2)

        req = FidoRequest(MC_RK_Res, options=None, user=generate_user(), rp = rp)
        res = device.sendGA(*req.toGA())

        auths.append(res)
        auths.append(device.ctap2.get_next_assertion())
        # time.sleep(2)
        auths.append(device.ctap2.get_next_assertion())
        # time.sleep(2)

        with pytest.raises(CtapError) as e:
            device.ctap2.get_next_assertion()

        assert len(regs) == 3
        assert len(regs) == len(auths)

        if MC_RK_Res.request.pin_protocol:
            for x in auths:
                for y in ("name", "icon", "displayName", "id"):
                    if y not in x.user.keys():
                        print("FAIL: %s was not in user: " % y, x.user)

        for x, y in zip(regs, auths[::-1]):
            verify(x, y, req.cdh)

    @pytest.mark.skipif("trezor" not in sys.argv, reason="Only Trezor has a display.")
    def test_multiple_rk_display(self, device, MC_RK_Res):
        regs = [MC_RK_Res]
        for i in range(0, 3):
            req = FidoRequest(MC_RK_Res, user=generate_user())
            res = device.sendMC(*req.toMC())
            setattr(res, "request", req)
            regs.append(res)

        for i, reg in enumerate(reversed(regs)):
            req = FidoRequest(
                MC_RK_Res, options=None, on_keepalive=DeviceSelectCredential(i + 1)
            )
            res = device.sendGA(*req.toGA())
            assert res.number_of_credentials is None

            with pytest.raises(CtapError) as e:
                device.ctap2.get_next_assertion()
            assert e.value.code == CtapError.ERR.NOT_ALLOWED

            assert res.user["id"] == reg.request.user["id"]
            verify(reg, res, req.cdh)

    @pytest.mark.skipif("trezor" not in sys.argv, reason="Only Trezor has a display.")
    def test_replace_rk_display(self, device):
        """
        Test replacing resident keys.
        """
        user1 = generate_user()
        user2 = generate_user()
        rp1 = {"id": "example.org", "name": "Example"}
        rp2 = {"id": "example.com", "name": "Example"}

        # Registration data is a list of (rp, user, number), where number is
        # the expected position of the credential after all registrations are
        # complete.
        reg_data = [
            (rp1, user1, 2),
            (rp1, user2, None),
            (rp1, user2, 1),
            (rp2, user2, 1),
        ]
        regs = []
        for rp, user, number in reg_data:
            req = FidoRequest(options={"rk": True}, rp=rp, user=user)
            res = device.sendMC(*req.toMC())
            setattr(res, "request", req)
            setattr(res, "number", number)
            regs.append(res)

        # Check.
        for reg in regs:
            if reg.number is not None:
                req = FidoRequest(
                    rp=reg.request.rp,
                    options=None,
                    on_keepalive=DeviceSelectCredential(reg.number),
                )
                res = device.sendGA(*req.toGA())
                assert res.user["id"] == reg.request.user["id"]
                verify(reg, res, req.cdh)

    @pytest.mark.skipif(
        "trezor" in sys.argv,
        reason="Trezor does not support get_next_assertion() because it has a display.",
    )
    @pytest.mark.skipif(
        "solokeys" in sys.argv, reason="Initial SoloKeys model truncates displayName"
    )
    def test_rk_maximum_size_nodisplay(self, device, MC_RK_Res):
        """
        Check the lengths of the fields according to the FIDO2 spec
        https://github.com/solokeys/solo/issues/158#issue-426613303
        https://www.w3.org/TR/webauthn/#dom-publickeycredentialuserentity-displayname
        """
        auths = []
        user_max = generate_user_maximum()
        req = FidoRequest(MC_RK_Res, user=user_max)
        resMC = device.sendMC(*req.toMC())
        req.options = {}
        resGA = device.sendGA(*req.toGA())
        credentials = resGA.number_of_credentials

        auths.append(resGA)
        for i in range(credentials - 1):
            auths.append(device.ctap2.get_next_assertion())

        user_max_GA = auths[0]
        verify(resMC, user_max_GA, req.cdh)

        if MC_RK_Res.request.pin_protocol:
            for y in ("name", "icon", "displayName", "id"):
                assert user_max_GA.user[y] == user_max[y]

    @pytest.mark.skipif("trezor" not in sys.argv, reason="Only Trezor has a display.")
    def test_rk_maximum_size_display(self, device, MC_RK_Res):
        """
        Check the lengths of the fields according to the FIDO2 spec
        https://github.com/solokeys/solo/issues/158#issue-426613303
        https://www.w3.org/TR/webauthn/#dom-publickeycredentialuserentity-displayname
        """
        user_max = generate_user_maximum()
        req = FidoRequest(MC_RK_Res, user=user_max)
        resMC = device.sendMC(*req.toMC())
        req = FidoRequest(MC_RK_Res, options=None)
        resGA = device.sendGA(*req.toGA())
        assert resGA.number_of_credentials is None
        verify(resMC, resGA, req.cdh)

    @pytest.mark.skipif(
        "trezor" in sys.argv,
        reason="Trezor does not support get_next_assertion() because it has a display.",
    )
    @pytest.mark.skipif(
        "solokeys" in sys.argv, reason="Initial SoloKeys model truncates displayName"
    )
    def test_rk_maximum_list_capacity_per_rp_nodisplay(self, info, device, MC_RK_Res):
        """
        Test maximum returned capacity of the RK for the given RP
        """

        # Try to determine from get_info, or default to 19.
        RK_CAPACITY_PER_RP = info.max_creds_in_list
        if not RK_CAPACITY_PER_RP:
            RK_CAPACITY_PER_RP = 19

        users = []

        def get_user():
            user = generate_user_maximum()
            users.append(user)
            return user

        # Use unique RP to not collide with other credentials from other tests.
        rp = {"id": f"unique-{random.random()}.com", "name": "Example"}

        # req = FidoRequest(MC_RK_Res, options=None, user=get_user(), rp = rp)
        # res = device.sendGA(*req.toGA())
        current_credentials_count = 0

        auths = []
        regs = [MC_RK_Res]
        RK_to_generate = RK_CAPACITY_PER_RP - current_credentials_count
        for i in range(RK_to_generate):
            req = FidoRequest(MC_RK_Res, user=get_user(), rp = rp)
            res = device.sendMC(*req.toMC())
            regs.append(res)

        req = FidoRequest(MC_RK_Res, options=None, user=generate_user_maximum(), rp = rp)
        res = device.sendGA(*req.toGA())
        assert res.number_of_credentials == RK_CAPACITY_PER_RP

        auths.append(res)
        for i in range(RK_CAPACITY_PER_RP - 1):
            auths.append(device.ctap2.get_next_assertion())

        with pytest.raises(CtapError) as e:
            device.ctap2.get_next_assertion()

        auths = auths[::-1][-RK_to_generate:]
        regs = regs[-RK_to_generate:]
        users = users[-RK_to_generate:]

        assert len(auths) == len(users)

        if MC_RK_Res.request.pin_protocol:
            for x, u in zip(auths, users):
                for y in ("name", "icon", "displayName", "id"):
                    assert y in x.user.keys()
                    assert x.user[y] == u[y]

        assert len(auths) == len(regs)
        for x, y in zip(regs, auths):
            verify(x, y, req.cdh)

    @pytest.mark.skipif("trezor" not in sys.argv, reason="Only Trezor has a display.")
    def test_rk_maximum_list_capacity_per_rp_display(self, device):
        """
        Test maximum capacity of resident keys.
        """
        RK_CAPACITY = 16
        device.reset()
        req = FidoRequest(options={"rk": True})

        regs = []
        for i in range(RK_CAPACITY):
            req = FidoRequest(req, user=generate_user_maximum())
            res = device.sendMC(*req.toMC())
            setattr(res, "request", req)
            regs.append(res)

        req = FidoRequest(req, user=generate_user_maximum())
        with pytest.raises(CtapError) as e:
            res = device.sendMC(*req.toMC())
        assert e.value.code == CtapError.ERR.KEY_STORE_FULL

        for i, reg in enumerate(reversed(regs)):
            if i not in (0, 1, 7, 14, 15):
                continue
            req = FidoRequest(
                req, options=None, on_keepalive=DeviceSelectCredential(i + 1)
            )
            res = device.sendGA(*req.toGA())
            assert res.user["id"] == reg.request.user["id"]
            verify(reg, res, req.cdh)

    def test_rk_with_allowlist_of_different_rp(self, resetDevice):
        """
        Test that a rk credential is not found when using an allowList item for a different RP
        """

        rk_rp = {"id": "rk-cred.org", "name": "Example"}
        rk_req = FidoRequest(rp = rk_rp, options={"rk": True})
        rk_res = resetDevice.sendMC(*rk_req.toMC())

        server_rp = {"id": "server-cred.com", "name": "Example"}
        server_req = FidoRequest(rp = server_rp)
        server_res = resetDevice.sendMC(*server_req.toMC())

        allow_list_with_different_rp_cred = [
            {
                "id": server_res.auth_data.credential_data.credential_id[:],
                "type": "public-key",
            }
        ]

        test_req = FidoRequest(rp = rk_rp, allow_list = allow_list_with_different_rp_cred)

        with pytest.raises(CtapError) as e:
            res = resetDevice.sendGA(*test_req.toGA())
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS


    def test_same_userId_overwrites_rk(self, resetDevice):
        """
        A make credential request with a UserId & Rp that is the same as an existing one should overwrite.
        """
        rp = {"id": "overwrite.org", "name": "Example"}
        user = generate_user()

        req = FidoRequest(rp = rp, options={"rk": True}, user = user)
        mc_res1 = resetDevice.sendMC(*req.toMC())

        # Should overwrite the first credential.
        mc_res2 = resetDevice.sendMC(*req.toMC())

        ga_res = resetDevice.sendGA(*req.toGA())

        # If there's only one credential, this is None
        assert ga_res.number_of_credentials == None

        verify(mc_res2, ga_res, req.cdh)

    def test_larger_icon_than_128(self, device):
        """
        Test it works if we give an icon value larger than 128 bytes
        """
        rp = {"id": "overwrite.org", "name": "Example"}
        user = generate_user()
        user['icon'] = 'https://www.w3.org/TR/webauthn/?icon=' + ("A" * 128)

        req = FidoRequest(rp = rp, options={"rk": True}, user = user)
        device.sendMC(*req.toMC())


    def test_returned_credential(self, device):
        """
        Test that when two rk credentials put in allow_list,
        only 1 will get returned.
        """
        device.reset()
        pin = '12345'
        device.client.pin_protocol.set_pin(pin)
        req = FidoRequest(pin = pin, options={"rk": True})

        regs = []
        allow_list = []
        for i in range(0, 2):
            req = FidoRequest(req, user = {
                "id": b'123456' + bytes([i]), "name": f'Test User {i}', "displayName": f'Test User display {i}'
            })
            res = device.sendMC(*req.toMC())
            setattr(res, "request", req)
            regs.append(res)
            allow_list.append({"id": res.auth_data.credential_data.credential_id[:], "type": "public-key"})


        print('allow_list: ' , allow_list)
        ga_req = FidoRequest(pin = pin, allow_list=allow_list)
        ga_res = device.sendGA(*ga_req.toGA())

        # No other credentials should be returned
        with pytest.raises(CtapError) as e:
            device.ctap2.get_next_assertion()

        # the returned credential should have user id in it
        print(ga_res)
        assert 'id' in ga_res.user and len(ga_res.user["id"]) > 0
