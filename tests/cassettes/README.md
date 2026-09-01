# REST / credential replay cassettes

Hand-authored fixtures for `tests/test_api_replay.py`. They let us regression-test
Aiper's regional API variance (see the v1.3.1 `getOpenIdToken` / `tokenDuration`
fix) without any live network.

These are **not** recorded from real traffic. They are built from the payload
shapes already visible in `tests/test_api_session.py`,
`tests/test_mqtt_credentials.py`, and `docs/`. All identifiers, tokens, and
secrets are obviously fake.

## Format

Each cassette is a JSON **list** of entries, consumed **strictly in order** by
`tests/replay.py`:

```json
[
  {
    "request":  { "method": "POST", "path_contains": "/login" },
    "response": { "status": 200, "json": { "code": "0", "successful": true, "data": { "...": "..." } } }
  },
  {
    "request":  { "method": "POST", "path_contains": "cognito-identity." },
    "response": { "status": 403, "message": "optional human note", "json": { "__type": "NotAuthorizedException" } }
  }
]
```

### `request`

| key             | meaning                                                                 |
| --------------- | ---------------------------------------------------------------------- |
| `method`        | Expected HTTP method. Asserted (case-insensitive) against the client.  |
| `path_contains` | Substring that **must** appear in the request URL. Asserted.          |

The player does not match on body. Ordering plus `path_contains` is enough to
pin each step, and it keeps cassettes readable.

### `response`

| key       | meaning                                                                                    |
| --------- | ---------------------------------------------------------------------------------------- |
| `status`  | HTTP status. `>= 400` is raised as `aiohttp.ClientResponseError(status=...)`, exactly like the real `_request_with_backoff` does via `resp.raise_for_status()`. Otherwise the entry is returned as `(status, json.dumps(json))`. |
| `json`    | Response body. For Aiper REST calls this is the *decrypted* envelope (`FakeEncryption` is a no-op). For the Cognito exchange it is the raw `GetCredentialsForIdentity` body. |
| `message` | Optional. Human note; also used as the `ClientResponseError` message for `>= 400`.       |

## What a happy-path cassette must contain

`await api.login()` alone makes **two** calls: `POST …/login`, then
`POST …/users/getOpenIdToken` (login calls `get_openid_token()` internally). So a
cassette covering `login -> get_devices -> get_openid_token -> get_aws_credentials`
needs, in order:

1. `/login`
2. `/users/getOpenIdToken`   (from inside `login()`)
3. `/equipment/getEquipment` (from `get_devices()`)
4. `/users/getOpenIdToken`   (the explicit `get_openid_token()` call)
5. `cognito-identity.`       (the `GetCredentialsForIdentity` exchange)

Key fields the client actually reads:

- **login** `data.token` (required, else it raises), `data.serialNumber`,
  `data.tokenExpires`, `data.domain` (list; first entry becomes `base_url`).
  Success needs `code` in `{"0","200"}` or `successful: true`.
- **getOpenIdToken** `data.identityId`, `data.token` (both required before an AWS
  exchange is attempted), `data.iotEndpoint`, `data.region`,
  `data.identityPoolId`, `data.developerProviderName`, and **`data.tokenDuration`**
  — omit it to model a region that gives no expiry hint (`_openid_token_exp`
  stays `None`).
- **getEquipment** `data` is a list of device dicts; each needs `sn`.
- **Cognito** `Credentials.AccessKeyId` (required), plus `SecretKey` /
  `SessionToken` for realism.

## The `cognito_4xx_then_recover` shape

When the exchange returns a 4xx, `_get_aws_credentials_locked` refreshes the
OpenID token **once** and retries. So after the two `getOpenIdToken` calls above:

6. `cognito-identity.` → `status: 4xx`  (rejected)
7. `/users/getOpenIdToken` → **new** `identityId` and `token` (must differ from
   the previous values, or the client concludes the refresh was a no-op and
   backs off instead of retrying)
8. `cognito-identity.` → `status: 200`  (retry succeeds)

## Turning a redacted diagnostics payload into a cassette

`custom_components/aiper/diagnostics.py` already masks tokens, `SecretKey`,
`identityId`, passwords, etc. (see `tests/test_diagnostics.py`,
`tests/test_redaction.py`). To build a cassette from a user's diagnostics or a
`tools/aiper_probe.py` capture:

1. Take the decrypted REST payloads (`rest-snapshot.json` entries, or the
   `data` blocks from diagnostics) and drop each one into a `response.json`.
2. Add a `request` with the matching `method` and a `path_contains` that is a
   stable, unambiguous slice of the endpoint path
   (e.g. `/users/getOpenIdToken`, `/equipment/getEquipment`, `cognito-identity.`).
3. Put the entries in the order the client issues them (see the list above).
   Remember `login()` pulls an OpenID token before you make any explicit call.
4. Replace every redacted `***` with a deterministic fake that is still
   internally consistent — e.g. the `IdentityId` in a Cognito response should
   match the `identityId` from the `getOpenIdToken` entry that precedes it, and a
   post-refresh entry must use *different* fakes so the "did it actually change?"
   check in the client passes.
5. Keep serial numbers realistic but fake; they only need to be consistent
   between the `getEquipment` list and anything keyed by `sn`.
6. For an error step, set `response.status` to the real HTTP status (a Cognito
   `NotAuthorizedException` is a 400/403) and, optionally, a `message`.

## Current cassettes

| file                          | models                                                              |
| ----------------------------- | ------------------------------------------------------------------ |
| `eu_happy_path.json`          | EU region, full chain succeeds, `tokenDuration` present.          |
| `us_happy_path.json`          | US region, full chain succeeds.                                   |
| `asia_happy_path.json`        | Asia region, full chain succeeds.                                 |
| `openid_no_token_duration.json` | Region omits `tokenDuration`; exchange 4xx → one refresh → retry OK. |
| `cognito_4xx_then_recover.json`  | Cognito rejects the cached token once → one bounded refresh → retry OK. |
