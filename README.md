# radius-go

radius-go is a small RADIUS authentication server written in Go. It is designed for teams that need a simple access-authentication system before a full identity platform is available.

Typical uses include:

- Lab or small-office access authentication where a RADIUS PAP backend is accepted by the network device.
- Temporary VPN, Wi-Fi, or network-device authentication during an infrastructure migration.
- A tightly scoped internal authentication service for a small number of users and network access clients.

The server stores users and API keys in SQLite, hashes user passwords with bcrypt, hashes API keys with SHA-256, exposes a protected Gin API, and only accepts RADIUS packets from explicitly configured client CIDR ranges.

## Features

- RADIUS Access-Request handling for PAP `User-Name` and `User-Password`.
- Multiple configured RADIUS clients, each with its own CIDR range and shared secret.
- Unknown RADIUS clients are silently dropped.
- User management API for creating, suspending, deleting, and changing passwords.
- API key management API for creating, suspending, and deleting API keys.
- Mandatory `X-API-Key` authentication for every `/api` request.
- SQLite database creation on first startup.
- One-time bootstrap API key printed when a new database is created.
- zap logging with lumberjack rotation. Daily rotation is enabled by default.
- YAML configuration.

## Requirements

- Go 1.25.0.
- SQLite support through `github.com/mattn/go-sqlite3`, which requires CGO.

## Build

```sh
go mod tidy
go test ./...
go build -o radius-go ./cmd/radius-go
```

## Configuration

Create a working config from the example:

```sh
cp config.example.yaml config.yaml
```

Edit `config.yaml` before running. At minimum, replace every RADIUS client secret with a long random value and set each client `network` to the exact CIDR range that should be allowed to send RADIUS requests.

Example:

```yaml
server:
  api_addr: ":8080"
  radius_addr: ":1812"

database:
  path: "data/radius-go.db"

logging:
  level: "info"
  file: "logs/radius-go.log"
  rotate_daily: true
  max_size_mb: 100
  max_backups: 14
  max_age_days: 30
  compress: true

security:
  bcrypt_cost: 12

clients:
  - name: "switch-01"
    network: "192.0.2.10/32"
    secret: "replace-with-a-long-random-shared-secret"
  - name: "wifi-controllers"
    network: "198.51.100.0/24"
    secret: "replace-with-a-different-long-random-secret"
```

## Run

```sh
./radius-go -config config.yaml
```

On the first startup, if the configured SQLite database file does not exist, radius-go creates the schema, generates a bootstrap API key, stores only its SHA-256 hash, and prints the plaintext key once:

```text
Initial API key (shown once): rg_...
```

Keep this key secure. It cannot be recovered from the database.

## Create a User

```sh
curl -X POST http://127.0.0.1:8080/api/users \
  -H "Content-Type: application/json" \
  -H "X-API-Key: rg_your_bootstrap_key" \
  -d '{"username":"alice","password":"correct-password"}'
```

After the user is created, a configured RADIUS client can authenticate `alice` with PAP using the configured shared secret.

## Security Notes

- Every `/api` route requires `X-API-Key`.
- API keys are shown only once at creation time.
- The service prevents suspending or deleting the last active API key.
- RADIUS requests from unknown client networks are dropped without a response.
- RADIUS shared secrets should be long, random, and unique per client entry.
- User passwords must be 8 to 72 bytes because bcrypt only uses the first 72 bytes.

See [API.md](API.md) for the full API reference.
