"""
garmin_auth - one way to authenticate to Garmin Connect.

Replaces the per-project copies of "resume, else log in, else prompt" with a
single call:

    from garmin_auth import get_client

    client = get_client()
    client.upload_activity("ride.fit")
    client.connectapi("/usersummary-service/usersummary/daily/...")

The returned object is a garminconnect.Garmin instance, so every method that
library offers is available.

Credentials are resolved in this order, and are only needed when no usable
tokens exist anywhere:
    1. the email/password arguments
    2. GARMIN_EMAIL / GARMIN_PASSWORD (for scheduled, non-interactive runs)
    3. an interactive prompt, when attached to a terminal

Tokens live in one place shared with every other consumer, including the
Garmin MCP server:
    GARMINTOKENS, else ~/.garminconnect

Set GARMIN_TOKEN_URL and GARMIN_BRIDGE_SECRET to also share the session across
machines; see garmin_auth.bridge.
"""
import atexit
import logging
import os
import sys
from pathlib import Path

from . import bridge

logger = logging.getLogger(__name__)

__all__ = ["get_client", "token_store", "publish_tokens", "bridge"]

DEFAULT_TOKEN_STORE = "~/.garminconnect"


def token_store(tokenstore=None) -> Path:
    """
    Resolve the token store directory.

    Args:
        tokenstore: explicit path, or None to use GARMINTOKENS / the default.

    Returns:
        Path: the directory holding garmin_tokens.json.
    """
    raw = tokenstore or os.environ.get("GARMINTOKENS") or DEFAULT_TOKEN_STORE
    return Path(raw).expanduser()


def _credentials(email, password):
    """
    Resolve credentials from arguments, the environment, or the terminal.

    Returns:
        tuple: (email, password), either of which may be None if unavailable.
    """
    email = email or os.environ.get("GARMIN_EMAIL")
    password = password or os.environ.get("GARMIN_PASSWORD")

    if email and password:
        return email, password

    # Only prompt when a human is actually there; a scheduled task must fail
    # with a clear message instead of blocking forever on stdin.
    if not sys.stdin.isatty():
        return email, password

    import getpass
    print("\nGarmin Connect login required.", flush=True)
    email = email or input("Email: ")
    password = password or getpass.getpass("Password: ")
    return email, password


def publish_tokens(tokenstore=None) -> bool:
    """
    Push the stored tokens to the bridge, if one is configured.

    Returns:
        bool: True when the bridge accepted them.
    """
    return bridge.push_tokens(token_store(tokenstore))


def _publish_if_rotated(store: Path, before: str):
    """
    Publish tokens when they differ from the recorded fingerprint.

    Garmin rotates both tokens on refresh, and garminconnect refreshes lazily
    from inside ordinary API calls, so a rotation can happen long after
    get_client() returned. This runs at exit to catch those.
    """
    after = bridge.fingerprint(store)
    if after and after != before:
        logger.info("Garmin tokens rotated; publishing to the bridge.")
        bridge.push_tokens(store)


def get_client(email=None, password=None, tokenstore=None, prompt_mfa=None,
               use_bridge=True):
    """
    Return an authenticated garminconnect.Garmin client.

    Resolution order:
        1. tokens pulled from the bridge (the freshest copy wins, because
           refresh tokens rotate and only the newest one works),
        2. tokens already in the local store,
        3. a credentials login, which is then published to the bridge.

    Args:
        email: Garmin account email; see the module docstring for fallbacks.
        password: Garmin account password.
        tokenstore: override the token store directory.
        prompt_mfa: callable returning an MFA code, for accounts with 2FA.
        use_bridge: set False to ignore the bridge entirely.

    Returns:
        garminconnect.Garmin: a logged-in client.

    Raises:
        Exception: when no tokens work and no credentials are available.
    """
    from garminconnect import Garmin

    store = token_store(tokenstore)
    store.mkdir(parents=True, exist_ok=True)

    # 1. The bridge may hold a newer session than this PC does.
    if use_bridge and bridge.is_configured():
        bridge.fetch_tokens(store)

    before = bridge.fingerprint(store)

    client = Garmin(prompt_mfa=prompt_mfa)
    try:
        client.login(tokenstore=str(store))
        logger.info("Resumed Garmin session from stored tokens.")
        if use_bridge:
            _publish_if_rotated(store, before)
            atexit.register(_publish_if_rotated, store, bridge.fingerprint(store))
        return client
    except Exception as e:
        logger.info(f"Could not resume a Garmin session: {e}")

    # 2. Fall back to credentials, and publish whatever we end up with so the
    #    other PCs resume it instead of logging in again.
    email, password = _credentials(email, password)
    if not email or not password:
        raise RuntimeError(
            "Garmin authentication required but no credentials are available. "
            "Pass email/password, set GARMIN_EMAIL and GARMIN_PASSWORD, or run "
            "this interactively."
        )

    client = Garmin(email, password, prompt_mfa=prompt_mfa)
    client.login(tokenstore=str(store))
    logger.info("Logged in to Garmin Connect.")

    bridge._restrict(bridge.token_file(store))
    if use_bridge:
        bridge.push_tokens(store)
        atexit.register(_publish_if_rotated, store, bridge.fingerprint(store))
    return client
