"""
Token service mode - fetch a short-lived access token from the server.

The server owns the refresh tokens and is the only thing that rotates them, so
a client in this mode holds nothing long-lived and *cannot* rotate anything.
That is structural rather than a convention: garminconnect needs only di_token
to call the API (is_authenticated is bool(di_token)), and raises "No DI refresh
token available" if asked to refresh without one.

Configure with two variables, shared by garmin_auth and withings_auth:

    TOKEN_SERVICE_URL   e.g. https://example.com/auth
    TOKEN_SERVICE_KEY   this machine's API key

When either is missing this mode is off and the caller falls back to managing
its own tokens.
"""
import json
import logging
import os

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 15


def service_url():
    """Base URL of the token service, or None when not configured."""
    url = os.environ.get("TOKEN_SERVICE_URL")
    return url.rstrip("/") if url else None


def api_key():
    """This machine's API key, or None."""
    return os.environ.get("TOKEN_SERVICE_KEY")


def is_configured():
    """True when both the URL and this machine's key are present."""
    return bool(service_url()) and bool(api_key())


def fetch_access_token(service: str = "garmin") -> dict:
    """
    Fetch a current access token from the service.

    Args:
        service: "garmin" or "withings".

    Returns:
        dict: {"access_token": str, "expires_at": float|None, ...}

    Raises:
        RuntimeError: when the service is unreachable, rejects the key, or has
        nothing usable. The caller decides whether to fall back.
    """
    base = service_url()
    if not base:
        raise RuntimeError("TOKEN_SERVICE_URL is not set")
    if not api_key():
        raise RuntimeError("TOKEN_SERVICE_KEY is not set")

    import requests

    url = f"{base}/{service}/access-token"
    try:
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {api_key()}"},
            timeout=HTTP_TIMEOUT,
        )
    except Exception as e:
        raise RuntimeError(f"Token service unreachable: {e}")

    if resp.status_code == 401:
        raise RuntimeError("Token service rejected this machine's API key")
    if resp.status_code == 404:
        raise RuntimeError(f"Token service has no {service} token stored yet")
    if resp.status_code == 503:
        # The stored token has expired and only the server can fix that.
        raise RuntimeError(f"Token service reports the {service} token expired")
    if resp.status_code != 200:
        raise RuntimeError(f"Token service returned {resp.status_code}")

    payload = resp.json()
    if not payload.get("access_token"):
        raise RuntimeError(f"Token service returned no {service} access token")

    logger.info(f"Fetched a {service} access token from the token service.")
    return payload


def garmin_client(prompt_mfa=None):
    """
    Build a garminconnect client from a service-issued access token.

    The token is passed to login() as a string, so it never touches disk, and
    because no refresh token comes with it the client cannot rotate anything.

    Returns:
        garminconnect.Garmin: a logged-in client.

    Raises:
        RuntimeError: when the service cannot supply a usable token.
    """
    from garminconnect import Garmin

    payload = fetch_access_token("garmin")

    client = Garmin(prompt_mfa=prompt_mfa)
    # garminconnect treats a tokenstore longer than 512 chars as token data
    # rather than a path, which is how we avoid writing it anywhere.
    blob = json.dumps({"di_token": payload["access_token"]})
    if len(blob) <= 512:
        raise RuntimeError("Access token is implausibly short; refusing it")

    try:
        client.login(tokenstore=blob)
    except Exception as e:
        raise RuntimeError(f"Service-issued Garmin token was not usable: {e}")

    return client
