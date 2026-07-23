// Copyright 2026 Eirik Haatveit, University of Oslo
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ecsencoder

import (
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap/zapcore"
)

// ecsConfig carries the configurable constants that end up in every ECS
// document. It is deliberately a plain struct with no Caddy/zap types so that
// toECS stays a pure, easily-testable function.
type ecsConfig struct {
	ECSVersion   string
	EventDataset string
	EventModule  string
}

// toECS is the heart of the module: it takes a decoded Caddy log entry (the
// zapcore.Entry envelope plus the structured fields already flattened into a
// nested map[string]interface{} by a MapObjectEncoder) and returns a new map
// laid out according to the Elastic Common Schema.
//
// It never mutates the input. Anything it does not explicitly understand is
// preserved: scalar leftovers go under labels.*, structured leftovers under
// caddy.*.
func toECS(ent zapcore.Entry, in map[string]interface{}, cfg ecsConfig) map[string]interface{} {
	doc := map[string]interface{}{}

	consumed := map[string]bool{}
	take := func(key string) (interface{}, bool) {
		v, ok := in[key]
		if ok {
			consumed[key] = true
		}
		return v, ok
	}

	// --- ecs.version -------------------------------------------------------
	nest(doc, "ecs.version", cfg.ECSVersion)

	// --- entry-level envelope ---------------------------------------------
	nest(doc, "@timestamp", ent.Time.UTC().Format("2006-01-02T15:04:05.000Z07:00"))
	nest(doc, "log.level", ent.Level.String())
	nest(doc, "log.logger", ent.LoggerName)
	nest(doc, "message", ent.Message)
	nest(doc, "error.stack_trace", ent.Stack)

	// --- request object (access logs) -------------------------------------
	_, isAccess := in["request"].(map[string]interface{})
	if req, ok := take("request"); ok {
		if reqMap, ok := req.(map[string]interface{}); ok {
			mapRequest(doc, reqMap)
		} else {
			isAccess = false
		}
	}

	// --- top-level access fields ------------------------------------------
	if v, ok := take("bytes_read"); ok {
		if n, ok := asInt64(v); ok {
			nest(doc, "http.request.body.bytes", n)
		}
	}
	if v, ok := take("size"); ok {
		if n, ok := asInt64(v); ok {
			nest(doc, "http.response.body.bytes", n)
		}
	}
	if v, ok := take("status"); ok {
		if n, ok := asInt64(v); ok {
			nest(doc, "http.response.status_code", n)
			nest(doc, "event.outcome", outcome(n))
		}
	}
	if v, ok := take("duration"); ok {
		if ns, ok := durationNanos(v); ok {
			nest(doc, "event.duration", ns)
		}
	}
	if v, ok := take("user_id"); ok {
		if s, ok := asString(v); ok {
			nest(doc, "user.name", s)
		}
	}
	if v, ok := take("resp_headers"); ok {
		if hdr, ok := v.(map[string]interface{}); ok {
			nest(doc, "http.response.headers", hdr)
		}
	}
	if v, ok := take("error"); ok {
		if s, ok := asString(v); ok {
			nest(doc, "error.message", s)
		}
	}

	// --- constants ---------------------------------------------------------
	nest(doc, "event.kind", "event")
	nest(doc, "event.dataset", cfg.EventDataset)
	nest(doc, "event.module", cfg.EventModule)
	if isAccess {
		nest(doc, "event.category", []string{"web"})
		nest(doc, "event.type", []string{"access"})
		nest(doc, "network.protocol", "http")
		nest(doc, "network.transport", "tcp")
	}

	// --- residual (lossless) ----------------------------------------------
	// Scalars -> labels.* (ECS-sanctioned); structured -> caddy.*.
	for k, v := range in {
		if consumed[k] {
			continue
		}
		switch v.(type) {
		case map[string]interface{}, []interface{}, []string:
			nest(doc, "caddy."+k, v)
		default:
			setLabel(doc, k, v)
		}
	}

	return doc
}

// mapRequest remaps Caddy's nested "request" object into ECS url.*, http.*,
// source.*, client.*, user_agent.* and tls.* fields.
func mapRequest(doc, req map[string]interface{}) {
	consumed := map[string]bool{}
	take := func(key string) (interface{}, bool) {
		v, ok := req[key]
		if ok {
			consumed[key] = true
		}
		return v, ok
	}

	if v, ok := take("method"); ok {
		if s, ok := asString(v); ok {
			nest(doc, "http.request.method", s)
		}
	}

	// TLS presence decides the scheme.
	scheme := "http"
	if v, ok := take("tls"); ok {
		if tlsMap, ok := v.(map[string]interface{}); ok {
			scheme = "https"
			mapTLS(doc, tlsMap)
		}
	}

	if v, ok := take("proto"); ok {
		if s, ok := asString(v); ok {
			nest(doc, "http.version", strings.TrimPrefix(s, "HTTP/"))
		}
	}

	var domain string
	var port int
	if v, ok := take("host"); ok {
		if s, ok := asString(v); ok {
			domain, port = splitHostPort(s)
			nest(doc, "url.domain", domain)
			nest(doc, "server.address", domain)
			if port > 0 {
				nest(doc, "url.port", int64(port))
				nest(doc, "server.port", int64(port))
			}
		}
	}

	var uri string
	if v, ok := take("uri"); ok {
		if s, ok := asString(v); ok {
			uri = s
			nest(doc, "url.original", s)
			path, query := splitURI(s)
			nest(doc, "url.path", path)
			nest(doc, "url.query", query)
		}
	}

	nest(doc, "url.scheme", scheme)
	if domain != "" && uri != "" {
		full := scheme + "://" + domain
		if port > 0 && !defaultPort(scheme, port) {
			full += ":" + strconv.Itoa(port)
		}
		nest(doc, "url.full", full+uri)
	}

	// Peer socket -> source.*; also the network address family.
	if v, ok := take("remote_ip"); ok {
		if s, ok := asString(v); ok {
			nest(doc, "source.ip", s)
			nest(doc, "source.address", s)
			nest(doc, "network.type", ipType(s))
		}
	}
	if v, ok := take("remote_port"); ok {
		if p, ok := asInt64(v); ok {
			nest(doc, "source.port", p)
		}
	}

	// "Real" client (after trusted_proxies) -> client.*; fall back to peer.
	clientIP, _ := asString(req["remote_ip"])
	if v, ok := take("client_ip"); ok {
		if s, ok := asString(v); ok {
			clientIP = s
		}
	}
	if clientIP != "" {
		nest(doc, "client.ip", clientIP)
		nest(doc, "client.address", clientIP)
	}

	if v, ok := take("headers"); ok {
		if hdr, ok := v.(map[string]interface{}); ok {
			nest(doc, "http.request.headers", hdr)
			if ua := firstHeader(hdr, "User-Agent"); ua != "" {
				nest(doc, "user_agent.original", ua)
			}
			if ref := firstHeader(hdr, "Referer"); ref != "" {
				nest(doc, "http.request.referrer", ref)
			}
		}
	}

	// Anything else Caddy put on the request (e.g. transfer_encoding) is kept.
	for k, v := range req {
		if !consumed[k] {
			nest(doc, "caddy.request."+k, v)
		}
	}
}

// mapTLS remaps Caddy's request.tls object into the ECS tls.* field set,
// normalizing the numeric version/cipher enums into their canonical strings.
func mapTLS(doc, t map[string]interface{}) {
	consumed := map[string]bool{}
	take := func(key string) (interface{}, bool) {
		v, ok := t[key]
		if ok {
			consumed[key] = true
		}
		return v, ok
	}

	if v, ok := take("version"); ok {
		if ver, ok := asInt64(v); ok {
			s, proto := tlsVersionString(uint16(ver))
			nest(doc, "tls.version", s)
			nest(doc, "tls.version_protocol", proto)
		}
	}
	if v, ok := take("cipher_suite"); ok {
		if cs, ok := asInt64(v); ok {
			nest(doc, "tls.cipher", tls.CipherSuiteName(uint16(cs)))
		}
	}
	if v, ok := take("proto"); ok {
		if s, ok := asString(v); ok {
			nest(doc, "tls.next_protocol", strings.ToLower(s))
		}
	}
	if v, ok := take("server_name"); ok {
		if s, ok := asString(v); ok {
			nest(doc, "tls.client.server_name", s)
		}
	}
	if v, ok := take("resumed"); ok {
		if b, ok := v.(bool); ok {
			nest(doc, "tls.resumed", b)
		}
	}
	if v, ok := take("client_common_name"); ok {
		if s, ok := asString(v); ok {
			nest(doc, "tls.client.subject", "CN="+s)
		}
	}
	if v, ok := take("client_serial"); ok {
		if s, ok := asString(v); ok {
			nest(doc, "tls.client.x509.serial_number", s)
		}
	}
	nest(doc, "tls.established", true)

	for k, v := range t {
		if !consumed[k] {
			nest(doc, "caddy.request.tls."+k, v)
		}
	}
}

// nest assigns val at a dotted path within doc, creating intermediate maps as
// needed (e.g. "http.request.method" -> {"http":{"request":{"method":val}}}).
// Empty strings and nil values are skipped so we don't emit noise like "".
func nest(doc map[string]interface{}, path string, val interface{}) {
	if val == nil {
		return
	}
	if s, ok := val.(string); ok && s == "" {
		return
	}
	parts := strings.Split(path, ".")
	m := doc
	for _, p := range parts[:len(parts)-1] {
		next, ok := m[p].(map[string]interface{})
		if !ok {
			next = map[string]interface{}{}
			m[p] = next
		}
		m = next
	}
	m[parts[len(parts)-1]] = val
}

// setLabel stores a custom scalar under labels.* with a de-dotted key, as ECS
// forbids dots in label keys.
func setLabel(doc map[string]interface{}, key string, val interface{}) {
	labels, ok := doc["labels"].(map[string]interface{})
	if !ok {
		labels = map[string]interface{}{}
		doc["labels"] = labels
	}
	labels[strings.ReplaceAll(key, ".", "_")] = val
}

// tlsVersionString maps a crypto/tls numeric version constant to the ECS
// tls.version string and its tls.version_protocol. Returns empty strings for
// unknown versions.
func tlsVersionString(v uint16) (version, protocol string) {
	switch v {
	case 0x0300: // SSL 3.0
		return "3.0", "ssl"
	case tls.VersionTLS10:
		return "1.0", "tls"
	case tls.VersionTLS11:
		return "1.1", "tls"
	case tls.VersionTLS12:
		return "1.2", "tls"
	case tls.VersionTLS13:
		return "1.3", "tls"
	}
	return "", ""
}

// durationNanos converts a Caddy "duration" field to ECS event.duration
// (integer nanoseconds). Caddy emits it as a time.Duration; a float is treated
// as seconds for robustness.
func durationNanos(v interface{}) (int64, bool) {
	switch d := v.(type) {
	case time.Duration:
		return d.Nanoseconds(), true
	case float64:
		return int64(d * float64(time.Second)), true
	case float32:
		return int64(float64(d) * float64(time.Second)), true
	}
	return 0, false
}

// outcome derives ECS event.outcome from an HTTP status code.
func outcome(status int64) string {
	switch {
	case status >= 400:
		return "failure"
	case status > 0:
		return "success"
	default:
		return "unknown"
	}
}

// ipType returns the ECS network.type ("ipv4"/"ipv6") for an IP string, or ""
// if it does not parse.
func ipType(s string) string {
	ip := net.ParseIP(s)
	switch {
	case ip == nil:
		return ""
	case ip.To4() != nil:
		return "ipv4"
	default:
		return "ipv6"
	}
}

// splitHostPort splits a "host[:port]" value, tolerating a bare host and IPv6
// literals. Returns port 0 when absent or unparseable.
func splitHostPort(host string) (string, int) {
	if host == "" {
		return "", 0
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		port, _ := strconv.Atoi(p)
		return h, port
	}
	return host, 0
}

// splitURI splits a request URI into path and query (without the leading "?").
func splitURI(uri string) (path, query string) {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[:i], uri[i+1:]
	}
	return uri, ""
}

// defaultPort reports whether port is the default for the given scheme, so it
// can be omitted from url.full.
func defaultPort(scheme string, port int) bool {
	return (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

// firstHeader returns the first value of a header from Caddy's
// map[string][]string-shaped header object (decoded as []interface{}).
func firstHeader(headers map[string]interface{}, name string) string {
	v, ok := headers[name]
	if !ok {
		return ""
	}
	switch arr := v.(type) {
	case []interface{}:
		if len(arr) > 0 {
			if s, ok := arr[0].(string); ok {
				return s
			}
		}
	case []string:
		if len(arr) > 0 {
			return arr[0]
		}
	case string:
		return arr
	}
	return ""
}

// asString returns v as a string if it is one.
func asString(v interface{}) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// asInt64 coerces any numeric (or numeric-string) value to int64.
func asInt64(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		return int64(n), true
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		return int64(n), true
	case float32:
		return int64(n), true
	case float64:
		return int64(n), true
	case string:
		if i, err := strconv.ParseInt(n, 10, 64); err == nil {
			return i, true
		}
	}
	return 0, false
}
