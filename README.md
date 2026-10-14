# Vault xAI Secrets Plugin

HashiCorp Vault secrets engine that issues short-lived xAI/Grok inference API keys through the [Management API](https://docs.x.ai/developers/management-api-guide).

The plugin creates a key when you read `xai/creds/:role` and deletes it when the Vault lease expires. It does not rotate the management key: xAI only lets you create those keys from the console.

Inspired by [Ricardo Oliveira](https://github.com/gitrgoliveira)'s [Vault OpenAI secrets plugin](https://github.com/gitrgoliveira/vault-plugin-secrets-openai): that project showed how to drive dynamic LLM API keys from Vault leases, and this plugin extends the same pattern to xAI (team-scoped keys, Management API ACLs/rate limits, propagation checks, and no admin-key rotation because xAI management keys are console-only).

Tested as an external (binary) plugin. HashiCorp does not officially support this plugin.

## Requirements

- Go 1.26+
- Vault 1.19+
- A **management key** (Console → Settings → Management Keys), distinct from a Grok inference API key
- The team `team_id` (Console → Team settings), or let the plugin infer it when it validates the management key

### Management key permissions

Create the key in the xAI Console under **Settings → Management Keys**. The plugin only calls the API-key endpoints (validate, create, propagation check, delete). Use this access:

| Endpoint | Access |
| --- | --- |
| API Keys | Read & Write |
| Audit Logs | No access |
| Billing | No access |
| Collections | No access |
| Compliance | No access |
| Computer Use | No access |
| Conversations | No access |
| Files | No access |
| Models | No access |
| Users & Teams | No access |

An inference API key cannot be used here. The Management API rejects it with `Invalid bearer token. Please ensure you use a valid management key.`

## Build

```bash
make build
```

The binary is written to `bin/vault-plugin-secrets-xai`.

For PR workflow conventions and Cursor hooks, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Docker images

`make docker` builds Vault **2.1.2** images for **linux/amd64** and **linux/arm64**. Each image already contains `/vault/plugins/vault-plugin-secrets-xai` built for that architecture, plus its checksum.

| Edition | amd64 | arm64 | Manifest |
| --- | --- | --- | --- |
| Community | `vault-xai:2.1.2-amd64` | `vault-xai:2.1.2-arm64` | `vault-xai:2.1.2` |
| Enterprise | `vault-xai:2.1.2-ent-amd64` | `vault-xai:2.1.2-ent-arm64` | `vault-xai:2.1.2-ent` |

```bash
make docker
# or, with Podman:
make docker CONTAINER_ENGINE=podman
```

`docker run` and `podman run` on the manifest tag pick the image that matches the host. The Minikube notebook loads the tag that matches the node and, after unseal, mounts the secrets engine at `xai/`.

### Dev server

```bash
docker run --rm --cap-add=IPC_LOCK -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=root \
  vault-xai:2.1.2
```

Enterprise dev mode also needs a license:

```bash
docker run --rm --cap-add=IPC_LOCK -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=root \
  -e VAULT_LICENSE="$(cat /path/to/vault.hclic)" \
  vault-xai:2.1.2-ent
```

Register and enable:

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
SHA256=$(docker run --rm --entrypoint cat vault-xai:2.1.2 /vault/plugins/vault-plugin-secrets-xai.sha256)
vault plugin register -sha256="$SHA256" secret vault-plugin-secrets-xai
vault secrets enable -path=xai vault-plugin-secrets-xai
```

### Kubernetes

A volume mounted on `/vault/config` hides `plugins.hcl`. Add the same settings to the server config:

```hcl
plugin_directory = "/vault/plugins"
plugin_tmpdir    = "/vault/plugins/tmp"
api_addr         = "https://vault.example.com:8200"
```

Point the server image at `vault-xai:2.1.2` or `vault-xai:2.1.2-ent`. The plugin file stays on `/vault/plugins` as long as that path is not replaced by a volume.

```bash
make test
```

Optional integration tests:

```bash
XAI_MANAGEMENT_KEY=... XAI_TEAM_ID=... make test-integration
```

## Register on a dev Vault

```bash
vault server -dev -dev-plugin-dir=./bin
```

In another terminal:

```bash
export VAULT_ADDR=http://127.0.0.1:8200
SHA256=$(shasum -a 256 ./bin/vault-plugin-secrets-xai | cut -d' ' -f1)
vault plugin register -sha256="$SHA256" secret vault-plugin-secrets-xai
vault secrets enable -path=xai vault-plugin-secrets-xai
```

## Usage

```bash
vault write xai/config \
  management_api_key="$XAI_MANAGEMENT_KEY" \
  team_id="$XAI_TEAM_ID"

vault write xai/roles/lumen \
  acls="api-key:model:*,api-key:endpoint:chat" \
  ttl=1h \
  max_ttl=24h

vault read xai/creds/lumen
```

Typical response:

```
Key                Value
---                -----
lease_id           xai/creds/lumen/...
lease_duration     1h
lease_renewable    true
api_key            xai-...
api_key_id         ...
name               vault-lumen-abcd1234
```

When the lease expires or is revoked, the plugin calls `DELETE /auth/api-keys/{apiKeyId}`.

`vault read xai/config` does not return the management key.

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `management_api_key` | yes | xAI management key |
| `team_id` | no | If omitted, taken from `GET /auth/management-keys/validation` |
| `api_endpoint` | no | Default `https://management-api.x.ai` |

## Roles

| Field | Default | Description |
| --- | --- | --- |
| `name_template` | `vault-{{.RoleName}}-{{.RandomSuffix}}` | Name of the key in xAI |
| `acls` | `api-key:model:*`, `api-key:endpoint:*` | Model and endpoint permissions |
| `ttl` | `1h` | Lease TTL |
| `max_ttl` | `24h` | Maximum TTL |
| `qps` / `qpm` / `tpm` | unset | Management API rate limits |
| `set_native_expiry` | `true` | Sends `expireTime` to xAI matching the Vault TTL |

## Differences from the OpenAI plugin

Compared with [gitrgoliveira/vault-plugin-secrets-openai](https://github.com/gitrgoliveira/vault-plugin-secrets-openai):

- There are no per-project service accounts: keys belong to the team.
- There is no root credential rotation (`config/rotate`): management keys are created only in the console.
- xAI does support ACLs, rate limits, and native expiry (`expireTime`).
- After creating a key, the plugin waits for propagation (`GET /auth/api-keys/{id}/propagation`, 10s). If it does not finish in time, the plugin still returns the credential and adds a warning.

## xAI endpoints used

- `GET /auth/management-keys/validation`
- `POST /auth/teams/{teamId}/api-keys`
- `GET /auth/api-keys/{apiKeyId}/propagation`
- `DELETE /auth/api-keys/{apiKeyId}`
