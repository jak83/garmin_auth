"""
Tests for garmin_auth.

Nothing here touches the network or a real Garmin account: garminconnect and
requests are both mocked.
"""
import json
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import garmin_auth
from garmin_auth import bridge

BRIDGE_ENV = {
    "GARMIN_TOKEN_URL": "https://klaanisodat.fi/api/garmin-token",
    "GARMIN_BRIDGE_SECRET": "test-secret",
}

TOKENS = {
    "di_token": "access-abc",
    "di_refresh_token": "refresh-abc",
    "di_client_id": "client-abc",
}

ROTATED = {
    "di_token": "access-xyz",
    "di_refresh_token": "refresh-xyz",
    "di_client_id": "client-abc",
}


def _response(status=200, payload=None):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload if payload is not None else {}
    resp.raise_for_status.return_value = None
    return resp


class StoreTestCase(unittest.TestCase):
    """Shared temp token store."""

    def setUp(self):
        self.store = Path(__file__).resolve().parent / "_tmp_store"
        if self.store.exists():
            shutil.rmtree(self.store)
        self.store.mkdir()

    def tearDown(self):
        if self.store.exists():
            shutil.rmtree(self.store)

    def _write(self, tokens=TOKENS):
        bridge.token_file(self.store).write_text(json.dumps(tokens))


class TestTokenStoreResolution(StoreTestCase):
    """The store must be shared with the MCP, not reinvented per project."""

    def test_explicit_path_wins(self):
        self.assertEqual(garmin_auth.token_store(self.store), self.store)

    def test_garmintokens_env_is_honoured(self):
        """The Garmin MCP configures this variable, so we must respect it."""
        with patch.dict(os.environ, {"GARMINTOKENS": str(self.store)}, clear=True):
            self.assertEqual(garmin_auth.token_store(), self.store)

    def test_defaults_to_garminconnect_dir(self):
        # Keep the home variables: clearing them would break expanduser()
        # itself, which is not what this test is about.
        home = {k: v for k, v in os.environ.items()
                if k in ("USERPROFILE", "HOME", "HOMEDRIVE", "HOMEPATH")}
        with patch.dict(os.environ, home, clear=True):
            self.assertEqual(garmin_auth.token_store(),
                             Path("~/.garminconnect").expanduser())


class TestBridgeConfiguration(StoreTestCase):
    def test_disabled_without_url(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(bridge.is_configured())
            self.assertFalse(bridge.fetch_tokens(self.store))
            self.assertFalse(bridge.push_tokens(self.store))

    def test_url_without_secret_sends_nothing(self):
        env = {"GARMIN_TOKEN_URL": BRIDGE_ENV["GARMIN_TOKEN_URL"]}
        with patch.dict(os.environ, env, clear=True):
            with patch("requests.get") as mock_get:
                self.assertFalse(bridge.fetch_tokens(self.store))
            mock_get.assert_not_called()


class TestFetch(StoreTestCase):
    def test_writes_tokens_garminconnect_can_load(self):
        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.get", return_value=_response(200, TOKENS)) as mock_get:
                self.assertTrue(bridge.fetch_tokens(self.store))

        _, kwargs = mock_get.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer test-secret")
        self.assertEqual(json.loads(bridge.token_file(self.store).read_text()), TOKENS)

    def test_strips_unexpected_fields(self):
        """A stray field must not reach client.loads()."""
        payload = dict(TOKENS, surprise="nope")
        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.get", return_value=_response(200, payload)):
                self.assertTrue(bridge.fetch_tokens(self.store))

        self.assertEqual(json.loads(bridge.token_file(self.store).read_text()), TOKENS)

    def test_404_means_nothing_stored_yet(self):
        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.get", return_value=_response(404)):
                self.assertFalse(bridge.fetch_tokens(self.store))

    def test_outage_does_not_raise(self):
        """A bridge outage must not stop a sync that local tokens could serve."""
        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.get", side_effect=OSError("connection refused")):
                self.assertFalse(bridge.fetch_tokens(self.store))

    def test_payload_without_access_token_is_rejected(self):
        self._write()
        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.get", return_value=_response(200, {"hello": "x"})):
                self.assertFalse(bridge.fetch_tokens(self.store))

        # Good local tokens survive a junk response.
        self.assertEqual(json.loads(bridge.token_file(self.store).read_text()), TOKENS)


class TestPush(StoreTestCase):
    def test_publishes_stored_tokens(self):
        self._write()
        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.put", return_value=_response(200)) as mock_put:
                self.assertTrue(bridge.push_tokens(self.store))

        _, kwargs = mock_put.call_args
        self.assertEqual(kwargs["json"], TOKENS)
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer test-secret")

    def test_nothing_stored_is_not_an_error(self):
        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.put") as mock_put:
                self.assertFalse(bridge.push_tokens(self.store))
            mock_put.assert_not_called()

    def test_incomplete_tokens_are_not_published(self):
        """Publishing a half-written file would break the other PCs."""
        bridge.token_file(self.store).write_text(json.dumps({"di_client_id": "x"}))
        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.put") as mock_put:
                self.assertFalse(bridge.push_tokens(self.store))
            mock_put.assert_not_called()

    def test_server_error_does_not_raise(self):
        self._write()
        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.put", side_effect=OSError("503")):
                self.assertFalse(bridge.push_tokens(self.store))


class TestRotationDetection(StoreTestCase):
    """Garmin rotates refresh tokens, so rotations must be detected."""

    def test_fingerprint_changes_when_tokens_rotate(self):
        self._write(TOKENS)
        before = bridge.fingerprint(self.store)
        self._write(ROTATED)
        self.assertNotEqual(before, bridge.fingerprint(self.store))

    def test_fingerprint_empty_without_tokens(self):
        self.assertEqual(bridge.fingerprint(self.store), "")

    def test_rotation_is_published(self):
        self._write(TOKENS)
        before = bridge.fingerprint(self.store)
        self._write(ROTATED)

        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.put", return_value=_response(200)) as mock_put:
                garmin_auth._publish_if_rotated(self.store, before)

        self.assertEqual(mock_put.call_args[1]["json"], ROTATED)

    def test_unchanged_tokens_are_not_republished(self):
        self._write(TOKENS)
        before = bridge.fingerprint(self.store)

        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.put") as mock_put:
                garmin_auth._publish_if_rotated(self.store, before)
            mock_put.assert_not_called()


class TestGetClient(StoreTestCase):
    """get_client() resolves bridge -> local tokens -> credentials."""

    def setUp(self):
        super().setUp()
        self.mock_garmin_cls = MagicMock()
        self.client = MagicMock()
        self.mock_garmin_cls.return_value = self.client
        self.module = MagicMock(Garmin=self.mock_garmin_cls)
        self.patcher = patch.dict(sys.modules, {"garminconnect": self.module})
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        super().tearDown()

    def test_resumes_from_stored_tokens_without_credentials(self):
        self._write()
        with patch.dict(os.environ, {}, clear=True):
            client = garmin_auth.get_client(tokenstore=self.store)

        self.assertIs(client, self.client)
        self.client.login.assert_called_once_with(tokenstore=str(self.store))
        # Resume must not construct a credentialed client.
        self.mock_garmin_cls.assert_called_once_with(prompt_mfa=None)

    def test_fetches_from_bridge_before_resuming(self):
        """The bridge copy is newer, so it must be pulled first."""
        self._write()
        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.get", return_value=_response(200, ROTATED)) as mock_get:
                with patch("requests.put", return_value=_response(200)):
                    garmin_auth.get_client(tokenstore=self.store)

        mock_get.assert_called_once()
        self.assertEqual(json.loads(bridge.token_file(self.store).read_text()), ROTATED)

    def test_falls_back_to_env_credentials(self):
        """A scheduled run with no tokens uses the environment."""
        self.client.login.side_effect = [Exception("no tokens"), None]
        env = {"GARMIN_EMAIL": "a@b.c", "GARMIN_PASSWORD": "pw"}

        with patch.dict(os.environ, env, clear=True):
            garmin_auth.get_client(tokenstore=self.store)

        self.mock_garmin_cls.assert_called_with("a@b.c", "pw", prompt_mfa=None)

    def test_login_is_published_to_the_bridge(self):
        self.client.login.side_effect = [Exception("no tokens"), None]
        env = dict(BRIDGE_ENV, GARMIN_EMAIL="a@b.c", GARMIN_PASSWORD="pw")

        def write_tokens(**kwargs):
            self._write(ROTATED)

        self.client.login.side_effect = [Exception("no tokens"), write_tokens()]

        with patch.dict(os.environ, env, clear=True):
            with patch("requests.get", return_value=_response(404)):
                with patch("requests.put", return_value=_response(200)) as mock_put:
                    garmin_auth.get_client(tokenstore=self.store)

        self.assertEqual(mock_put.call_args[1]["json"], ROTATED)

    def test_no_tokens_and_no_credentials_raises_clearly(self):
        self.client.login.side_effect = Exception("no tokens")
        with patch.dict(os.environ, {}, clear=True):
            with patch("sys.stdin") as stdin:
                stdin.isatty.return_value = False
                with self.assertRaises(RuntimeError) as cm:
                    garmin_auth.get_client(tokenstore=self.store)

        self.assertIn("no credentials are available", str(cm.exception))

    def test_use_bridge_false_skips_the_network(self):
        self._write()
        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.get") as mock_get:
                with patch("requests.put") as mock_put:
                    garmin_auth.get_client(tokenstore=self.store, use_bridge=False)

            mock_get.assert_not_called()
            mock_put.assert_not_called()


if __name__ == "__main__":
    unittest.main()


def _jwt(exp: int) -> str:
    """Build a di_token-shaped JWT whose exp claim is `exp`."""
    import base64 as b64
    payload = b64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
    return f"header.{payload}.signature"


def _tokens_expiring(exp: int, refresh="ref"):
    return {"di_token": _jwt(exp), "di_refresh_token": refresh,
            "di_client_id": "client"}


class TestDoesNotClobberNewerLocalTokens(StoreTestCase):
    """
    The Garmin MCP server shares this token store and refreshes without
    publishing. Overwriting its rotation with an older bridge copy would kill
    both, since the rotation already invalidated the bridge's refresh token.
    """

    def test_newer_local_is_kept_and_published(self):
        import time
        newer = _tokens_expiring(int(time.time()) + 86400, refresh="local-new")
        older = _tokens_expiring(int(time.time()) + 3600, refresh="bridge-old")
        bridge.token_file(self.store).write_text(json.dumps(newer))

        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.get", return_value=_response(200, older)):
                with patch("requests.put", return_value=_response(200)) as mock_put:
                    self.assertFalse(bridge.fetch_tokens(self.store))

        # Local untouched...
        kept = json.loads(bridge.token_file(self.store).read_text())
        self.assertEqual(kept["di_refresh_token"], "local-new")
        # ...and pushed, so the other machines recover.
        self.assertEqual(mock_put.call_args[1]["json"]["di_refresh_token"],
                         "local-new")

    def test_newer_bridge_still_wins(self):
        import time
        older = _tokens_expiring(int(time.time()) + 3600, refresh="local-old")
        newer = _tokens_expiring(int(time.time()) + 86400, refresh="bridge-new")
        bridge.token_file(self.store).write_text(json.dumps(older))

        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.get", return_value=_response(200, newer)):
                self.assertTrue(bridge.fetch_tokens(self.store))

        got = json.loads(bridge.token_file(self.store).read_text())
        self.assertEqual(got["di_refresh_token"], "bridge-new")

    def test_unreadable_expiry_does_not_block_the_bridge(self):
        """An opaque token must not make us prefer a stale local copy."""
        bridge.token_file(self.store).write_text(json.dumps(
            {"di_token": "not-a-jwt", "di_refresh_token": "x", "di_client_id": "c"}))

        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.get", return_value=_response(200, TOKENS)):
                self.assertTrue(bridge.fetch_tokens(self.store))

    def test_expiry_of_a_real_looking_token(self):
        self.assertEqual(bridge.access_expiry(_tokens_expiring(1790000000)),
                         1790000000.0)
        self.assertEqual(bridge.access_expiry({}), 0.0)
        self.assertEqual(bridge.access_expiry({"di_token": "junk"}), 0.0)


SERVICE_ENV = {
    "TOKEN_SERVICE_URL": "https://klaanisodat.fi/auth",
    "TOKEN_SERVICE_KEY": "machine-key",
}


class TestServiceMode(StoreTestCase):
    """
    In service mode the server keeps the refresh token, so this client holds
    nothing long-lived and cannot rotate anything.
    """

    def test_off_unless_both_variables_are_set(self):
        from garmin_auth import service
        for env in ({}, {"TOKEN_SERVICE_URL": "x"}, {"TOKEN_SERVICE_KEY": "y"}):
            with patch.dict(os.environ, env, clear=True):
                self.assertFalse(service.is_configured(), env)
        with patch.dict(os.environ, SERVICE_ENV, clear=True):
            self.assertTrue(service.is_configured())

    def test_fetch_sends_the_machine_key(self):
        from garmin_auth import service
        payload = {"access_token": "a" * 600, "expires_at": 123}
        with patch.dict(os.environ, SERVICE_ENV, clear=True):
            with patch("requests.get", return_value=_response(200, payload)) as mock_get:
                got = service.fetch_access_token("garmin")

        url, = mock_get.call_args[0]
        self.assertEqual(url, "https://klaanisodat.fi/auth/garmin/access-token")
        self.assertEqual(mock_get.call_args[1]["headers"]["Authorization"],
                         "Bearer machine-key")
        self.assertEqual(got["access_token"], payload["access_token"])

    def test_service_errors_are_explained(self):
        from garmin_auth import service
        cases = {401: "rejected", 404: "no garmin token", 503: "expired"}
        with patch.dict(os.environ, SERVICE_ENV, clear=True):
            for status, expected in cases.items():
                with patch("requests.get", return_value=_response(status)):
                    with self.assertRaises(RuntimeError) as cm:
                        service.fetch_access_token("garmin")
                self.assertIn(expected, str(cm.exception).lower(), status)

    def test_token_is_never_written_to_disk(self):
        """
        The access token is handed to login() as a string, which garminconnect
        treats as token data rather than a path when it is over 512 chars.
        """
        from garmin_auth import service
        token = "h." + "a" * 900 + ".s"
        captured = {}

        class FakeGarmin:
            def __init__(self, prompt_mfa=None):
                self.display_name = "tester"

            def login(self, tokenstore=None):
                captured["tokenstore"] = tokenstore

        module = MagicMock(Garmin=FakeGarmin)
        with patch.dict(sys.modules, {"garminconnect": module}):
            with patch.dict(os.environ, SERVICE_ENV, clear=True):
                with patch("requests.get",
                           return_value=_response(200, {"access_token": token})):
                    client = service.garmin_client()

        self.assertEqual(client.display_name, "tester")
        blob = captured["tokenstore"]
        self.assertGreater(len(blob), 512, "would be treated as a file path")
        parsed = json.loads(blob)
        self.assertEqual(parsed["di_token"], token)
        # The whole point: no refresh token reaches the client.
        self.assertNotIn("di_refresh_token", parsed)
        self.assertFalse(bridge.token_file(self.store).exists())

    def test_get_client_prefers_the_service(self):
        sentinel = MagicMock(display_name="from-service")
        with patch.dict(os.environ, SERVICE_ENV, clear=True):
            with patch.object(garmin_auth.service, "garmin_client",
                              return_value=sentinel) as mock_service:
                client = garmin_auth.get_client(tokenstore=self.store)

        self.assertIs(client, sentinel)
        mock_service.assert_called_once()

    def test_get_client_falls_back_when_the_service_is_down(self):
        """A server outage must not stop a sync local tokens could serve."""
        self._write()
        fake_client = MagicMock(display_name="local")
        module = MagicMock(Garmin=MagicMock(return_value=fake_client))

        with patch.dict(sys.modules, {"garminconnect": module}):
            with patch.dict(os.environ, SERVICE_ENV, clear=True):
                with patch.object(garmin_auth.service, "garmin_client",
                                  side_effect=RuntimeError("service down")):
                    client = garmin_auth.get_client(tokenstore=self.store)

        self.assertIs(client, fake_client)
        fake_client.login.assert_called_once()
