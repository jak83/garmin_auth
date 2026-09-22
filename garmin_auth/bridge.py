"""
Token bridge - share one Garmin session across several PCs.

Tokens live behind an HTTP endpoint guarded by a shared secret, so every PC
resumes the same session instead of logging in separately.

Configure with two environment variables:
    GARMIN_TOKEN_URL       e.g. https://klaanisodat.fi/api/garmin-token
    GARMIN_BRIDGE_SECRET   sent as "Authorization: Bearer <secret>"

When GARMIN_TOKEN_URL is unset every function here is a no-op and the caller
falls back to the local token store. Bridge failures are logged and treated as
"no tokens available" rather than raised: an outage must not stop a sync when
local tokens still work.

IMPORTANT - Garmin rotates refresh tokens on every use. Whichever PC refreshes
invalidates the copy the others hold, so the bridge cannot be a write-once
cache. Callers must fetch before use and push after any refresh; see
garmin_auth.get_client, which does both.
"""
import base64
import hashlib
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# The file garminconnect persists inside its token store directory.
TOKEN_FILENAME = "garmin_tokens.json"

# The only fields garminconnect reads back (client.loads()).
TOKEN_FIELDS = ("di_token", "di_refresh_token", "di_client_id")

HTTP_TIMEOUT = 10


def bridge_url():
    """Return the configured bridge URL, or None when the bridge is disabled."""
    return os.environ.get("GARMIN_TOKEN_URL")


def _bridge_headers():
    """Return auth headers for the bridge, or None when no secret is set."""
    secret = os.environ.get("GARMIN_BRIDGE_SECRET")
    return {"Authorization": f"Bearer {secret}"} if secret else None


def is_configured():
    """True when both the URL and the secret are present."""
    return bool(bridge_url()) and bool(_bridge_headers())


def _require_config():
    """
    Validate bridge configuration.

    Returns:
        tuple: (url, headers) when usable, (None, None) when the bridge is off.
    """
    url = bridge_url()
    if not url:
        return None, None
    headers = _bridge_headers()
    if not headers:
        logger.warning("GARMIN_TOKEN_URL is set but GARMIN_BRIDGE_SECRET is missing; "
                       "ignoring the bridge and using local tokens.")
        return None, None
    return url, headers


def token_file(token_dir) -> Path:
    """Return the path of the token file inside a token store directory."""
    return Path(token_dir).expanduser() / TOKEN_FILENAME


def fingerprint(token_dir) -> str:
    """
    Hash the stored tokens so a rotation can be detected.

    Returns:
        str: a short digest, or "" when no tokens are stored.
    """
    path = token_file(token_dir)
    if not path.exists():
        return ""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as e:
        logger.warning(f"Could not read {path.name}: {e}")
        return ""


def _read_local(token_dir) -> dict:
    """Read the stored tokens, or {} when there are none."""
    path = token_file(token_dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def access_expiry(tokens: dict) -> float:
    """
    Return the access token's expiry as a unix timestamp, 0.0 if unknown.

    di_token is a JWT, so its exp claim tells us which of two token sets is
    the newer one without having to ask Garmin.
    """
    token = tokens.get("di_token") if isinstance(tokens, dict) else None
    if not token:
        return 0.0
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return float(json.loads(base64.urlsafe_b64decode(payload))["exp"])
    except Exception:
        return 0.0


def fetch_tokens(token_dir) -> bool:
    """
    Download tokens from the bridge into token_dir.

    Call this before logging in: another PC may hold a newer session, and
    because refresh tokens rotate, the newest copy is the only usable one.

    Returns:
        bool: True when tokens were written, False when the bridge is disabled,
        empty, or unreachable.
    """
    url, headers = _require_config()
    if not url:
        return False

    import requests

    try:
        resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        if resp.status_code == 404:
            logger.info("No Garmin tokens on the bridge yet; "
                        "will log in locally and publish them.")
            return False
        resp.raise_for_status()
        payload = resp.json()
    except Exception as e:
        logger.warning(f"Could not fetch Garmin tokens from the bridge: {e}")
        return False

    if not isinstance(payload, dict) or not payload.get("di_token"):
        logger.warning("Bridge returned no usable Garmin tokens; using local tokens.")
        return False

    # Never overwrite a newer local token. Other tools share this store - the
    # Garmin MCP server uses garminconnect directly - and they rotate tokens
    # without publishing. Clobbering their rotation with an older bridge copy
    # would kill both, since the rotation already invalidated the bridge's
    # refresh token. Publish the newer local copy instead.
    local = _read_local(token_dir)
    if local and access_expiry(local) > access_expiry(payload):
        logger.info("Local Garmin tokens are newer than the bridge; another tool "
                    "refreshed them. Keeping them and publishing to the bridge.")
        push_tokens(token_dir)
        return False

    path = token_file(token_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Keep only the fields garminconnect reads, so a stray field on the bridge
    # cannot confuse client.loads().
    tokens = {k: payload[k] for k in TOKEN_FIELDS if k in payload}
    path.write_text(json.dumps(tokens, indent=2))
    _restrict(path)
    logger.info("Loaded Garmin tokens from the bridge.")
    return True


def push_tokens(token_dir) -> bool:
    """
    Publish the local tokens so the other PCs resume this session.

    Call this after any login or refresh. Garmin rotates the refresh token on
    use, so skipping this leaves the other PCs holding a dead token.

    Returns:
        bool: True when the bridge accepted the tokens, False otherwise.
    """
    url, headers = _require_config()
    if not url:
        return False

    import requests

    path = token_file(token_dir)
    if not path.exists():
        logger.warning(f"No tokens at {path}; nothing to publish.")
        return False

    try:
        stored = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(f"Could not read {path.name} to publish: {e}")
        return False

    tokens = {k: stored[k] for k in TOKEN_FIELDS if k in stored}
    if not tokens.get("di_token"):
        logger.warning("Local tokens look incomplete; not publishing.")
        return False

    try:
        resp = requests.put(url, json=tokens, headers=headers, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
    except Exception as e:
        logger.warning(f"Could not publish Garmin tokens to the bridge: {e}")
        return False

    logger.info("Published Garmin tokens to the bridge.")
    return True


def _restrict(path: Path):
    """
    Make the token file owner-only where the OS supports it.

    These tokens grant full account access, so they should not be readable by
    other accounts on a shared machine. Silently ignored on Windows, where
    chmod cannot express this.
    """
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
