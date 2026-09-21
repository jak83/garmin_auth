# garmin_auth

One shared way to authenticate to Garmin Connect, so each project stops
reimplementing "resume, else log in, else prompt".

```python
from garmin_auth import get_client

client = get_client()
client.upload_activity("ride.fit")
client.connectapi("/usersummary-service/usersummary/daily/jka1983")
```

The return value is a `garminconnect.Garmin`, so every method that library
offers is available.

## Install

```
pip install git+https://github.com/jak83/garmin_auth.git
```

Requires **64-bit** Python 3.10+. `garminconnect` depends on `curl_cffi`,
which publishes no 32-bit Windows wheels.

## How a session is resolved

1. tokens pulled from the token bridge, if one is configured,
2. tokens already in the local store,
3. a credentials login, which is then published to the bridge.

Credentials are only needed when no tokens work anywhere, and are taken from
the `email`/`password` arguments, then `GARMIN_EMAIL` / `GARMIN_PASSWORD`,
then an interactive prompt. It never prompts when stdin is not a terminal, so
a scheduled task fails with a clear message instead of hanging.

## Token store

`GARMINTOKENS`, else `~/.garminconnect` - the same location the Garmin MCP
server uses, so one login serves every consumer on the machine.

## Multi-PC sharing

Set both to share one session across machines:

| Variable | Example |
|---|---|
| `GARMIN_TOKEN_URL` | `https://example.com/api/garmin-token` |
| `GARMIN_BRIDGE_SECRET` | shared secret, sent as `Authorization: Bearer ...` |

With `GARMIN_TOKEN_URL` unset the bridge is inert and only local tokens are
used. Bridge failures are logged, never raised: an outage must not break a
sync that local tokens could serve.

The endpoint stores one JSON blob and needs two verbs:

```
GET  -> {"di_token": "...", "di_refresh_token": "...", "di_client_id": "..."}
        404 before anything is stored
PUT  <- the same shape
```

### Refresh tokens rotate

Garmin issues **single-use** refresh tokens: every resume rotates both tokens,
and `garminconnect` refreshes lazily from inside ordinary API calls. Whichever
machine refreshes invalidates the copy the others hold.

So this package fetches before login, fingerprints the token file, and
republishes whenever it changes - including rotations that happen long after
`get_client()` returned. A write-once cache would leave the other machines
demanding a password for no apparent reason.

## API

| Function | Purpose |
|---|---|
| `get_client(email=None, password=None, tokenstore=None, prompt_mfa=None, use_bridge=True)` | authenticated client |
| `token_store(tokenstore=None)` | resolve the token directory |
| `publish_tokens(tokenstore=None)` | push the stored tokens to the bridge |
| `bridge.fetch_tokens(dir)` / `bridge.push_tokens(dir)` | direct bridge access |

Pass `use_bridge=False` for a purely local, read-only check.

## Security

These are full-access tokens: anyone holding them can read all your Garmin
Connect data and post activities as you, without your password and without
passing MFA. The token file is written `0600` where the OS supports it. Keep
`GARMIN_BRIDGE_SECRET` out of version control - it belongs in an environment
variable.

## Why not garth

`garth` is deprecated and no longer maintained upstream, and uses Garmin's
older SSO scheme. `garminconnect` 0.3.x uses the current DI OAuth flow,
supports MFA, drops the `pydantic` dependency, and ships `curl_cffi` for TLS
impersonation, which Garmin's blocking of plain `requests` clients makes
necessary.

## Tests

```
python -m unittest discover tests
```

24 tests, no network and no Garmin account required.
