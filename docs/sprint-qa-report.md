# Protocol Chaos Sprint -- QA Report

**Date**: 2026-03-05
**Reviewer**: QA Agent
**Scope**: TLS chaos engine, slow HTTP attacks, TLS scanner module, H2 frame chaos, HSTS chaos, destroyer profile, integration tests

---

## Findings

| # | Severity | File | Description |
|---|----------|------|-------------|
| 1 | **High** | `internal/tlschaos/chaos.go:220` | **Infinite recursion risk in `getConfigForClient`.** The method calls `e.TLSConfig()` which returns a config with `GetConfigForClient: e.getConfigForClient` set. While Go's `crypto/tls` does not call `GetConfigForClient` on the *returned* config (only the original), the returned config carries a self-referential callback. If any future code or library version invokes it, this will stack overflow. The returned config should have `GetConfigForClient: nil` to be safe. |
| 2 | **High** | `internal/tlschaos/chaos.go:164` | **`RenegotiateOnceAsClient` is a client-side setting, not a server setting.** In `LevelNightmare`, `cfg.Renegotiation = tls.RenegotiateOnceAsClient` is set on a server `tls.Config`. This field only affects TLS clients (controlling whether they accept renegotiation from a server). On a server config it is silently ignored and has no effect. This represents dead code that misleads readers about what nightmare mode actually does. |
| 3 | **High** | `internal/tlschaos/chaos.go:246-276` | **`SaveCert` ignores `pem.Encode` errors.** Both calls to `pem.Encode` (lines 256 and 273) discard the returned error. If the write fails (disk full, permission denied), the function returns `nil` suggesting success while producing a corrupt or truncated file. |
| 4 | **High** | `internal/dashboard/admin.go:2020-2026` | **`globalTLSEngine` has no synchronization.** `SetTLSChaosEngine` and `GetTLSChaosEngine` read/write the `globalTLSEngine` variable without any mutex. The `Set()` method in `AdminConfig` also accesses it (lines 757, 774) while holding the AdminConfig mutex, but `SetTLSChaosEngine` does not hold that mutex. In practice, `SetTLSChaosEngine` is called once at startup before concurrent access begins, but this is fragile and violates Go's race detector. |
| 5 | **Medium** | `internal/tlschaos/chaos.go:48` | **`requestCount` uses `sync.Mutex` instead of `sync/atomic`.** The `requestCount` field is an `int64` protected by the general `mu` mutex. In `getCertificate` (lines 184-187), it acquires a write lock just to increment this counter, which creates lock contention on every TLS handshake at cert chaos levels. Should use `atomic.AddInt64` instead. |
| 6 | **Medium** | `internal/errors/generator.go:652-670` | **H2 GOAWAY fallback hijacks without writing.** When `ErrH2GoAway` fires on HTTP/1.1 (the `else` branch at line 665), the connection is hijacked and immediately closed without writing any HTTP response. The client receives a connection reset with no indication of what happened. While this may be intentional as a chaos behavior, other similar fallbacks (e.g., `ErrH2RstStream` at line 686-690) at least write a partial response. Inconsistent behavior. |
| 7 | **Medium** | `internal/errors/generator.go:714` | **`ErrH2WindowExhaust` allocates a 64KB chunk per request.** `make([]byte, 65536)` is allocated on every invocation. For a high-traffic chaos server, this creates GC pressure. The chunk could be a `sync.Pool` item or a package-level `var`. |
| 8 | **Medium** | `internal/scanner/attacks/slowhttp.go:611-681` | **Compression bomb builds 10MB+ in memory at module init time.** `compressionBomb()` is called from `GenerateRequests()`, which writes 10MB of zeros, gzip-compresses them, then double-compresses. The resulting `AttackRequest` objects hold these large payloads in memory. If multiple `SlowHTTPModule` instances or repeated calls occur, this compounds. Consider lazy generation or limiting payload size. |
| 9 | **Medium** | `internal/scanner/profiles/profiles.go:179-180` | **Destroyer profile `RateLimit: 0` silently becomes 100 req/s.** The scanner engine treats `RateLimit <= 0` as a default of 100 (engine.go line 410-411). The destroyer profile sets `RateLimit: 0` intending "unlimited", but the engine clamps it to 100. This is also true for the nightmare profile. The "unlimited" intent is silently defeated. |
| 10 | **Medium** | `internal/scanner/attacks/tls.go:201` | **Unused parsed URL variable.** In `httpToHTTPSRedirect`, the parsed URL `u` is assigned (line 141) and used only at the end via `_ = u` (line 201), which is a no-op placeholder. The function claims to construct HTTP variants but never actually uses the parsed URL for that purpose. Dead code. |
| 11 | **Medium** | `internal/scanner/attacks/tls.go:509-537` | **`classifyKey` has unreachable branch.** The type switch case at lines 515-524 attempts to match an interface with anonymous struct methods, which will never match any real Go crypto key type. The comment on line 523 acknowledges this: "This won't match." Dead code that adds confusion. |
| 12 | **Low** | `internal/tlschaos/chaos.go:88-96` | **P-224 as "RSA-1024 equivalent" is misleading.** The comment says P-224 is equivalent to RSA-1024 in weakness, but P-224 provides approximately 112-bit security (equivalent to RSA-2048). P-224 is deprecated by NIST but not nearly as weak as RSA-1024 (~80-bit security). The comment overstates the weakness. |
| 13 | **Low** | `internal/tlschaos/chaos_test.go:184-187` | **HTTP/2 test has no assertion.** `TestTLSServer_HTTP2` logs the protocol but does not fail when HTTP/2 is not negotiated (uses `t.Logf` instead of `t.Errorf`). The test passes regardless of the result, providing no regression protection. |
| 14 | **Low** | `internal/server/handler.go:296` | **HSTS chaos check uses `== true` instead of truthiness.** `enabled == true` works because the map value is `interface{}` and `Set()` stores a `bool`, but if `Set()` logic changes to store `int(1)` instead, this comparison will silently fail. Should use a type switch or explicit bool conversion like other config checks. |
| 15 | **Low** | `internal/scanner/profiles/profiles.go:186-193` | **Destroyer profile `EnabledModules: nil` does not include "slowhttp" or "tls" explicitly.** The profile description says it enables slow HTTP, compression bombs, etc., but `EnabledModules: nil` means "all modules" which relies on every module being registered. The nightmare profile explicitly lists these modules. If module registration order or availability changes, destroyer behavior becomes unpredictable. |
| 16 | **Low** | `internal/scanner/attacks/tls.go:419` | **RC4 cipher probes will fail on Go 1.22+.** Go removed RC4 support from `crypto/tls` starting in Go 1.22. The `TLS_RSA_WITH_RC4_128_SHA` and `TLS_ECDHE_RSA_WITH_RC4_128_SHA` constants still exist but attempting to configure them will fail. The probe will always report "not accepted" regardless of the server's actual support. |

---

## Test Gaps

| # | Gap | Impact |
|---|-----|--------|
| G1 | **No test for `getConfigForClient` at nightmare level.** The TLS tests never exercise `LevelNightmare` with an actual TLS connection. `TestTLSConfig_NightmareALPN` only checks the config struct, not the per-client callback behavior. | The recursive config issue (Finding #1) and ALPN lying behavior are completely untested with real connections. |
| G2 | **No test for `SaveCert`.** The cert persistence path is untested. | Error handling bugs (Finding #3) are not caught. |
| G3 | **No test for H2 error types with actual HTTP/2 connections.** `TestIntegration_H2ErrorTypes_Exist` only checks that the types exist in the profile map. No test fires `ErrH2GoAway` or `ErrH2RstStream` over a real H2 connection. | The panic-based GOAWAY mechanism (Finding #6) and all H2 chaos implementations are untested at the protocol level. |
| G4 | **No test for `SlowHTTPModule.GenerateRequests`.** No unit test verifies the module generates requests or that the compression bomb is valid gzip. | Silent failures in payload generation (Finding #8) would go unnoticed. |
| G5 | **No test for `TLSModule.ProbeTarget`.** The active TLS probing code has zero test coverage. All sub-functions (`probeVersions`, `probeWeakCiphers`, `analyzeCert`, `probeALPN`, `probeDowngrade`) are untested. | Any regression in the scanner's TLS analysis capability would be invisible. |
| G6 | **No test for destroyer profile.** Only `compliance`, `aggressive`, `stealth`, and `nightmare` profiles are implicitly tested via the registry. No test verifies destroyer's config values or that it can be retrieved. | Profile misconfiguration (Finding #9) is not caught. |
| G7 | **`TestIntegration_HSTSChaos_InjectsHeaders` does not assert a minimum count.** It logs `hstsCount` but never fails if zero headers are injected. | HSTS chaos could be completely broken and the test would still pass. |
| G8 | **No concurrent test for TLS engine.** No test exercises `SetLevel` and `getCertificate` concurrently to verify mutex correctness. | Race conditions (Finding #5) under concurrent TLS handshakes are not caught. |

---

## Recommendations

1. **Fix the `getConfigForClient` recursion risk (Finding #1).** In `getConfigForClient`, after calling `e.TLSConfig()`, set `cfg.GetConfigForClient = nil` on the returned config to prevent any possibility of recursion.

2. **Remove `RenegotiateOnceAsClient` from server config (Finding #2).** This field has no effect on server-side configs. Remove it or replace with a comment explaining that Go's TLS server does not support server-initiated renegotiation.

3. **Check `pem.Encode` errors in `SaveCert` (Finding #3).** Propagate errors from both `pem.Encode` calls.

4. **Add synchronization to `globalTLSEngine` (Finding #4).** Use `sync.Once` for initialization or wrap access in the existing `adminConfigMu` (or equivalent). Alternatively, use `atomic.Value`.

5. **Use `atomic.AddInt64` for `requestCount` (Finding #5).** Replace the mutex-based increment with `atomic.AddInt64(&e.requestCount, 1)` and `atomic.LoadInt64(&e.requestCount)` to reduce lock contention.

6. **Fix `RateLimit: 0` semantics (Finding #9).** Either: (a) change the engine to treat `0` as truly unlimited (skip the ticker), or (b) change the destroyer/nightmare profiles to use a very high value like `1000000`.

7. **Add real connection tests for H2 chaos and TLS nightmare (Gaps G1, G3).** Create tests that start an httptest TLS server and verify GOAWAY, RST_STREAM, and per-client config variation over real connections.

8. **Make `TestIntegration_HSTSChaos_InjectsHeaders` assertive (Gap G7).** Require `hstsCount > 0` instead of just logging.

9. **Add `SlowHTTPModule` and `TLSModule.ProbeTarget` tests (Gaps G4, G5).** At minimum, verify request generation counts and that the compression bomb produces valid gzip.

---

## Overall Quality Assessment

The sprint adds substantial new functionality across three areas (TLS chaos, slow HTTP attacks, H2 frame chaos) with reasonable architectural choices. The code is well-organized and follows existing project conventions.

**Strengths:**
- TLS chaos engine has clean level-based design with proper mutex protection on core state
- H2 chaos implementations are creative and use idiomatic Go patterns (http.ErrAbortHandler for GOAWAY)
- HSTS chaos is deterministic per-client via FNV hash, avoiding flaky behavior
- Admin config wiring is complete: TLS chaos level changes propagate to the engine in real-time
- Integration tests verify the config roundtrip path

**Weaknesses:**
- Test coverage for the new code is shallow -- mostly config-level checks, no protocol-level verification
- The high-severity `SaveCert` error silencing and `getConfigForClient` recursion risk need attention before this code is relied upon
- The destroyer profile's `RateLimit: 0` silently defeating the "unlimited" intent is a usability bug that will confuse users
- Several dead code paths (unused URL variable, unreachable type switch branch) suggest the TLS scanner module was written quickly and needs cleanup

**Verdict:** The code is functional but needs targeted fixes for findings #1, #3, #5, and #9 before production use, and significantly more test coverage (especially protocol-level tests) before this sprint can be considered complete.
