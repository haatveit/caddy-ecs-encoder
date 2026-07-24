# caddy-ecs-encoder

A [Caddy](https://caddyserver.com) log encoder that emits access and runtime logs
in **[Elastic Common Schema (ECS)](https://www.elastic.co/docs/reference/ecs)**
format, with **properly nested** objects:

```json
{ "http": { "request": { "method": "GET" } }, "url": { "path": "/ok" } }
```

rather than flat dotted keys (`{"http.request.method": "GET"}`). It remaps
Caddy's native log fields to their ECS equivalents, converting units and types
along the way (durations → nanoseconds, TLS version enums → `"1.3"`, status →
integer, etc.), and never drops data.

Module ID: `caddy.logging.encoders.ecs` · Caddyfile name: `ecs`

## Why

Caddy logs structured JSON, but under its own field names/shape. Log aggregation
systems that index by ECS (Elasticsearch, etc.) can't unpack that directly.
This module implements an `EncodeEntry` that restructures the whole payload into
nested ECS.

## Install

Build Caddy with the module using [xcaddy](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build --with github.com/haatveit/caddy-ecs-encoder
```

## Usage

Caddyfile:

```caddyfile
example.com {
	log {
		output file /var/log/caddy/access.log
		format ecs
	}
	# ...
}
```

Options (all optional):

```caddyfile
format ecs {
	ecs_version   8.11.0        # value written to ecs.version (default 8.11.0)
	event_dataset caddy.access  # event.dataset (default caddy.access)
	event_module  caddy         # event.module (default caddy)
}
```

Equivalent JSON config:

```json
{ "encoder": { "format": "ecs", "ecs_version": "8.11.0" } }
```

## Redacting or filtering fields

`ecs` composes with Caddy's built-in
[`filter`](https://caddyserver.com/docs/caddyfile/directives/log#filter) encoder,
so you can redact/hash/delete fields **before** they're remapped to ECS. Put
`filter` on the outside and `wrap ecs` on the inside. `filter` operates on
Caddy's native field paths (e.g. `request>headers>Api-Key`), then hands the
result to `ecs` for ECS remapping:

```caddyfile
example.com {
	log {
		output file /var/log/caddy/access.log
		format filter {
			request>headers>Api-Key     replace REDACTED
			request>headers>Api-Nonce   hash
			request>headers>Cookie      delete
			wrap ecs
		}
	}
}
```

The redactions land in the correct nested location
(`http.request.headers.Api-Key`), and everything else is remapped as usual.
(Caddy already redacts `Authorization`, `Cookie`, `Set-Cookie`, and
`Proxy-Authorization` on the request by default.)

## Field mapping

Envelope and constants:

| Caddy           | ECS                                                                                             |
| --------------- | ----------------------------------------------------------------------------------------------- |
| entry timestamp | `@timestamp` (ISO8601, UTC, ms)                                                                 |
| entry level     | `log.level`                                                                                     |
| logger name     | `log.logger`                                                                                    |
| message         | `message`                                                                                       |
| stack trace     | `error.stack_trace`                                                                             |
| —               | `ecs.version`, `event.kind=event`, `event.dataset`, `event.module`                              |
| — (access only) | `event.category=[web]`, `event.type=[access]`, `network.protocol=http`, `network.transport=tcp` |

Access-log fields:

| Caddy                               | ECS                                                       | Notes                                     |
| ----------------------------------- | --------------------------------------------------------- | ----------------------------------------- |
| `request.method`                    | `http.request.method`                                     |                                           |
| `request.proto`                     | `http.version`                                            | `HTTP/` prefix stripped                   |
| `request.host`                      | `url.domain`, `url.port`, `server.address`, `server.port` | host/port split                           |
| `request.uri`                       | `url.original`, `url.path`, `url.query`                   | plus derived `url.scheme`, `url.full`     |
| `request.remote_ip` / `remote_port` | `source.ip`, `source.address`, `source.port`              | plus derived `network.type`               |
| `request.client_ip`                 | `client.ip`, `client.address`                             | falls back to peer IP                     |
| `request.headers`                   | `http.request.headers`                                    | full map preserved                        |
| `request.headers.User-Agent`        | `user_agent.original`                                     | parsed sub-fields left to Elastic ingest  |
| `request.headers.Referer`           | `http.request.referrer`                                   |                                           |
| `bytes_read`                        | `http.request.body.bytes`                                 |                                           |
| `size`                              | `http.response.body.bytes`                                |                                           |
| `status`                            | `http.response.status_code`                               | derives `event.outcome` (success/failure) |
| `duration`                          | `event.duration`                                          | **nanoseconds (integer)**                 |
| `user_id`                           | `user.name`                                               | omitted if empty                          |
| `resp_headers`                      | `http.response.headers`                                   | full map preserved                        |
| `error`                             | `error.message`                                           | on errored requests                       |

TLS (`request.tls.*`):

| Caddy                        | ECS                                                       | Notes                            |
| ---------------------------- | --------------------------------------------------------- | -------------------------------- |
| `version` (e.g. `772`)       | `tls.version` (`"1.3"`), `tls.version_protocol` (`"tls"`) | numeric enum normalized          |
| `cipher_suite` (e.g. `4865`) | `tls.cipher` (`TLS_AES_128_GCM_SHA256`)                   | via `crypto/tls.CipherSuiteName` |
| `proto`                      | `tls.next_protocol`                                       |                                  |
| `server_name`                | `tls.client.server_name`                                  | SNI                              |
| `resumed`                    | `tls.resumed`                                             | plus `tls.established=true`      |
| `client_common_name`         | `tls.client.subject`                                      | mTLS                             |
| `client_serial`              | `tls.client.x509.serial_number`                           | mTLS                             |

### Nothing is dropped

Fields with no ECS home are preserved losslessly:

* **Custom scalars** (e.g. from `log_append`) → `labels.*` (ECS-sanctioned).
* **Structured / unknown fields** (e.g. runtime-log objects, Caddy's TLS `ech`
  flag) → `caddy.*`.

Request/response headers are kept under `http.request.headers` /
`http.response.headers`. These aren't part of the ECS spec but are a common
convention (see [elastic/ecs#232](https://github.com/elastic/ecs/issues/232))
and useful to retain; your indexer may treat them as unindexed.

## Enrichment (deferred to Elastic)

To keep the encoder fast and dependency-free, it emits only `user_agent.original`
and `source.ip`. Run Elastic's ingest processors to derive the rest:

* `user_agent` processor → `user_agent.name`, `.version`, `.os.*`, `.device.name`
* `geoip` processor → `source.geo.*`, `source.as.*`

## Notes / limitations

* `@timestamp` is always emitted as UTC ISO8601 (ECS requirement); Caddy's
  `time_format`/`time_local` log options don't affect ECS output.
* URL public-suffix fields (`url.registered_domain`, `url.subdomain`,
  `url.top_level_domain`) are left to ingest-time parsing.
* Implementation decodes each entry into a map, remaps it in Go, and marshals
  the result — marginally more work than streaming JSON encoding, in exchange for
  correct structural remapping. Comparable in cost to `transform-encoder`.

## Development

```sh
go test ./...   # unit + end-to-end mapping tests
go vet ./...
```

## License

Apache License 2.0
