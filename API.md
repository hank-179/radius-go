# radius-go API

All API endpoints are under `/api` and require:

```http
X-API-Key: rg_your_api_key
```

Unauthorized or missing API keys return:

```json
{
  "error": "unauthorized"
}
```

If `api.allowed_sources` is configured, the resolved client IP must match one of the configured IP addresses or CIDR ranges. Requests from other sources return:

```json
{
  "error": "source_forbidden"
}
```

When the API is behind a reverse proxy, configure `api.trusted_proxies` with the proxy IP address or CIDR. radius-go then resolves the client IP from `X-Forwarded-For` or `X-Real-IP`; forwarded headers from untrusted peers are ignored.

All request and response bodies use JSON unless the endpoint returns `204 No Content`.

## Health Check

Checks that the API service is reachable. This endpoint is still authenticated.

```http
GET /api/health
```

Response `200 OK`:

```json
{
  "status": "ok"
}
```

## Create User

Creates a user with a bcrypt-hashed password.

```http
POST /api/users
```

Request body:

```json
{
  "username": "alice",
  "password": "correct-password"
}
```

Response `201 Created`:

```json
{
  "user": {
    "id": 1,
    "username": "alice",
    "disabled": false,
    "created_at": "2026-05-28T08:00:00.000Z",
    "updated_at": "2026-05-28T08:00:00.000Z"
  }
}
```

Possible errors:

- `400 Bad Request`: invalid JSON, invalid username, or password outside the 8 to 72 byte limit.
- `401 Unauthorized`: missing or invalid API key.
- `409 Conflict`: user already exists.

## Change User Password

Replaces an existing user's password.

```http
PATCH /api/users/{username}/password
```

Request body:

```json
{
  "password": "new-correct-password"
}
```

Response `200 OK`:

```json
{
  "user": {
    "id": 1,
    "username": "alice",
    "disabled": false,
    "created_at": "2026-05-28T08:00:00.000Z",
    "updated_at": "2026-05-28T08:10:00.000Z"
  }
}
```

Possible errors:

- `400 Bad Request`: invalid JSON, invalid username, or invalid password.
- `401 Unauthorized`: missing or invalid API key.
- `404 Not Found`: user does not exist.

## Suspend User

Suspends a user. Suspended users are always rejected by RADIUS authentication.

```http
POST /api/users/{username}/suspend
```

Request body: none.

Response `200 OK`:

```json
{
  "user": {
    "id": 1,
    "username": "alice",
    "disabled": true,
    "created_at": "2026-05-28T08:00:00.000Z",
    "updated_at": "2026-05-28T08:15:00.000Z"
  }
}
```

Possible errors:

- `400 Bad Request`: invalid username.
- `401 Unauthorized`: missing or invalid API key.
- `404 Not Found`: user does not exist.

## Delete User

Deletes a user.

```http
DELETE /api/users/{username}
```

Request body: none.

Response `204 No Content`.

Possible errors:

- `400 Bad Request`: invalid username.
- `401 Unauthorized`: missing or invalid API key.
- `404 Not Found`: user does not exist.

## Create API Key

Creates an API key. Only the SHA-256 hash is stored. The plaintext key is returned once in the `key` field.

```http
POST /api/api-keys
```

Request body:

```json
{
  "name": "operator"
}
```

Response `201 Created`:

```json
{
  "api_key": {
    "id": 2,
    "name": "operator",
    "disabled": false,
    "last_used_at": null,
    "created_at": "2026-05-28T08:20:00.000Z",
    "updated_at": "2026-05-28T08:20:00.000Z"
  },
  "key": "rg_generated_key_value"
}
```

Possible errors:

- `400 Bad Request`: invalid JSON or invalid name.
- `401 Unauthorized`: missing or invalid API key.
- `409 Conflict`: API key name already exists.

## Suspend API Key

Suspends an API key. Suspended keys cannot call the API.

```http
POST /api/api-keys/{id}/suspend
```

Request body: none.

Response `200 OK`:

```json
{
  "api_key": {
    "id": 2,
    "name": "operator",
    "disabled": true,
    "last_used_at": "2026-05-28T08:21:00.000Z",
    "created_at": "2026-05-28T08:20:00.000Z",
    "updated_at": "2026-05-28T08:25:00.000Z"
  }
}
```

Possible errors:

- `400 Bad Request`: invalid API key id.
- `401 Unauthorized`: missing or invalid API key.
- `404 Not Found`: API key does not exist.
- `409 Conflict`: the requested key is the last active API key.

## Delete API Key

Deletes an API key.

```http
DELETE /api/api-keys/{id}
```

Request body: none.

Response `204 No Content`.

Possible errors:

- `400 Bad Request`: invalid API key id.
- `401 Unauthorized`: missing or invalid API key.
- `404 Not Found`: API key does not exist.
- `409 Conflict`: the requested key is the last active API key.

## Error Format

Errors use a stable machine-readable `error` string:

```json
{
  "error": "not_found"
}
```

Common values include `unauthorized`, `source_forbidden`, `invalid_json`, `not_found`, `already_exists`, `last_active_api_key`, `method_not_allowed`, and `internal_error`.
