# FRC: Media Content Chaos Engine

**Feature**: Media Content Generation, Corruption & Delivery Chaos
**Status**: Draft
**Date**: 2026-03-02

## 1. Summary

Add a media chaos subsystem that generates valid media content on-the-fly (images, audio, video, streaming playlists) and applies configurable corruption, delivery disruption, and format chaos. All content is generated procedurally in memory — no files stored on disk. Integrates with the existing CDN emulation and admin panel.

## 2. Goals

1. **Generate visually/audibly valid media** — PNG, JPEG, GIF, BMP, WebP, SVG, ICO, TIFF (images); WAV, MP3, OGG, FLAC (audio); MP4, WebM, AVI (video); HLS/DASH (streaming)
2. **Corrupt intelligently** — format-aware corruption that produces interesting glitches, not just random bytes
3. **Delivery chaos** — Content-Length mismatches, chunked encoding tricks, range request abuse, slow drip, infinite streams, mid-stream format switching
4. **Unlimited file sizes** — streaming generation for arbitrarily large files without buffering
5. **CDN integration** — media served through CDN personalities with caching chaos
6. **Full admin control** — every setting configurable via dashboard, all settings verified by tests

## 3. Architecture

### 3.1 Package Structure

```
internal/media/
  generator.go      — Deterministic media generation (images, audio, video containers)
  formats.go        — Pre-computed minimal valid file constants + builders
  streaming.go      — HLS/DASH playlist and segment generation
  infinite.go       — Infinite/streaming content generators (io.Reader implementations)

internal/mediachaos/
  engine.go         — Main chaos engine (probability, category dispatch)
  corruption.go     — Format-aware corruption functions
  delivery.go       — HTTP delivery chaos (range, chunked, slow, Content-Length)
  config.go         — MediaChaosConfig singleton + admin types
```

### 3.2 Integration Points

1. **Handler dispatch** (`server/handler.go`) — intercepts media-path requests
2. **Feature flag** (`dashboard/admin.go`) — `media_chaos` boolean toggle
3. **Admin config** — probability, per-category toggles, delivery settings
4. **CDN engine** (`cdn/cdn.go`) — media requests routed through CDN when enabled
5. **Content pages** — `<img>`, `<audio>`, `<video>` tags embedded in generated HTML
6. **Admin routes** — `/admin/api/mediachaos` GET/POST endpoints
7. **Admin HTML** — Media Chaos section in Server tab with toggles and sliders

## 4. Media Generation

### 4.1 Image Formats

All generated deterministically from URL path (SHA-256 seed → consistent content).

| Format | Generation Method | Stdlib | Sizes |
|--------|------------------|--------|-------|
| PNG | `image/png` encoder | Yes | 1x1 to streaming infinite |
| JPEG | `image/jpeg` encoder | Yes | 1x1 to arbitrary |
| GIF | `image/gif` encoder (animated) | Yes | 1x1 to animated sequences |
| BMP | Hand-crafted bytes (14+40 header + BGR pixels) | No encoder needed | 1x1 to arbitrary |
| WebP | Pre-computed VP8L constant + color patching | Constant | 1x1 fixed |
| SVG | String template generation | N/A (text) | Arbitrary complexity |
| ICO | Directory + embedded PNG | Wrapper | Multi-size |
| TIFF | Hand-crafted IFD + strip data | No encoder needed | 1x1 to arbitrary |

**Visual content types** (deterministic from path seed):
- Solid color blocks
- Gradient patterns (linear, radial)
- Checkerboard / stripe patterns
- Noise / static patterns
- Simple geometric shapes (circles, rectangles, triangles)

### 4.2 Audio Formats

| Format | Generation Method | Content |
|--------|------------------|---------|
| WAV | Hand-crafted RIFF/fmt/data chunks | PCM sine waves, silence, noise, tones |
| MP3 | Pre-computed minimal frame constants | Silent/minimal frames concatenated |
| OGG | Pre-computed Vorbis constant | Minimal valid file |
| FLAC | Pre-computed stream + frame constant | Minimal valid file |

**Audio content types** (deterministic):
- Sine wave (configurable frequency: 220Hz, 440Hz, 880Hz, etc.)
- White noise / pink noise
- Silence
- Multi-tone (chord)
- Sweep (ascending/descending frequency)

### 4.3 Video Formats

| Format | Generation Method | Content |
|--------|------------------|---------|
| MP4 | Hand-crafted ftyp/moov/mdat boxes | Pre-computed H.264 SPS/PPS/IDR constants |
| WebM | Hand-crafted EBML/Segment/Cluster | Pre-computed VP8 keyframe constant |
| AVI | Hand-crafted RIFF/hdrl/movi | Uncompressed BMP frame data |

**Video content**: Single-frame solid color or simple pattern. Multi-frame via repeated keyframes.

### 4.4 Streaming Formats

| Format | Generation Method | Content |
|--------|------------------|---------|
| HLS | Generated `.m3u8` playlists + `.ts` segments | Text playlists, binary TS packets |
| DASH | Generated MPD XML + segments | XML manifests, MP4 segments |

## 5. Chaos Categories

### 5.1 Format Corruption (per-format-type)

**Image corruption:**
- `bad_crc` — Flip CRC bytes in PNG chunks
- `truncated` — Cut file at random point (shows partial render)
- `wrong_dimensions` — Header claims different size than data
- `huge_dimensions` — Header claims enormous size (memory bomb)
- `zero_dimensions` — Width or height = 0
- `corrupt_header` — Corrupt format-specific header fields
- `corrupt_data` — Flip bits in pixel/compressed data
- `missing_terminator` — Omit PNG IEND, JPEG EOI, GIF trailer
- `extra_data` — Append garbage after file end marker
- `channel_swap` — Swap R/G/B channels in pixel data
- `palette_corrupt` — Corrupt GIF/PNG color table entries
- `quantization_corrupt` — Corrupt JPEG quantization tables
- `duplicate_header` — Two PNG IHDR chunks, two JPEG SOI markers
- `invalid_interlace` — Wrong interlace flag
- `comment_bomb` — Huge metadata/comment chunks (megabytes)
- `invalid_compression` — Bad zlib stream in PNG IDAT

**Audio corruption:**
- `sample_rate_zero` — Set sample rate to 0 (division by zero)
- `channels_mismatch` — Header says stereo, data is mono
- `bits_per_sample_invalid` — Unusual values (3, 7, 13)
- `data_size_mismatch` — WAV data chunk size wrong
- `byte_rate_mismatch` — Computed byte rate doesn't match header
- `truncated_frames` — MP3/OGG frames cut short
- `missing_header_packets` — OGG missing comment/setup headers

**Video corruption:**
- `box_size_mismatch` — MP4 box sizes don't match content
- `missing_moov` — MP4 without movie metadata box
- `ftyp_not_first` — MP4 ftyp box not at start
- `codec_mismatch` — Header claims one codec, data is another
- `timescale_zero` — Division by zero in duration calculation
- `offset_past_eof` — Sample offsets point beyond file
- `deep_nesting` — Deeply nested container boxes (stack overflow)

### 5.2 Delivery Chaos

- `content_length_larger` — Content-Length > actual body (client waits)
- `content_length_smaller` — Content-Length < actual body (data bleed)
- `content_length_zero` — Content-Length: 0 but body present
- `content_length_negative` — Content-Length: -1
- `content_length_nonnumeric` — Content-Length: abc
- `duplicate_content_length` — Two Content-Length headers with different values
- `content_type_mismatch` — Serve PNG as video/mp4, etc.
- `content_type_empty` — Empty Content-Type header
- `content_type_invalid` — Non-standard Content-Type value
- `duplicate_content_type` — Two Content-Type headers
- `no_content_type` — Omit Content-Type entirely (forces MIME sniffing)
- `nosniff_wrong_type` — X-Content-Type-Options: nosniff + wrong Content-Type

### 5.3 Range Request Chaos

- `range_ignore` — Accept-Ranges: bytes but serve full content on range request
- `range_wrong_total` — Content-Range total doesn't match file size
- `range_200_for_partial` — Return 200 instead of 206 for range request
- `range_missing_header` — Return 206 without Content-Range header
- `range_less_data` — Content-Range claims N bytes but fewer sent
- `range_overlapping_multipart` — Multipart ranges with overlapping byte regions
- `range_no_boundary` — Multipart byteranges without boundary parameter
- `range_wrong_boundary` — Declared boundary doesn't match actual

### 5.4 Chunked Encoding Chaos

- `chunk_size_mismatch` — Hex size doesn't match actual chunk data
- `chunk_missing_terminator` — No final 0-length chunk
- `chunk_invalid_hex` — Non-hex characters in chunk size
- `chunk_huge_size` — Chunk size claiming gigabytes
- `chunk_lf_only` — \n instead of \r\n
- `chunk_extra_whitespace` — Whitespace in chunk size line
- `chunk_zero_then_more` — Zero-length chunk followed by more data

### 5.5 Slow Delivery

- `byte_at_a_time` — 1 byte per interval (configurable: 10ms–1000ms)
- `slow_start` — First N bytes fast, then ultra-slow
- `random_pauses` — Random delays between chunks (0–5s)
- `stall_midstream` — Stop sending after partial delivery (configurable stall duration)
- `infinite_trickle` — Never finish, keep sending 1 byte/sec

### 5.6 Infinite/Huge Content

- `infinite_png` — Valid PNG header + IHDR, then infinite IDAT chunks
- `infinite_gif` — Valid animated GIF header, infinite frames
- `infinite_wav` — Valid WAV header with max data size, infinite PCM samples
- `infinite_mp4` — Valid ftyp+moov, then infinite mdat data
- `infinite_random` — Valid Content-Type, infinite random bytes
- `huge_metadata` — Valid file with megabytes of metadata/comments
- `huge_claimed_size` — Content-Length claims terabytes

### 5.7 Stream Switching

- `format_switch_midstream` — Start as PNG, switch to JPEG data midway
- `html_injection` — Valid image header, then HTML/script content
- `http_injection` — Valid data, then HTTP response headers mid-body

### 5.8 Cache Poisoning

- `etag_conflict` — ETag says fresh, Last-Modified says stale
- `cache_control_conflict` — public + no-cache + no-store simultaneously
- `vary_star` — Vary: * (nothing cacheable)
- `age_exceeds_maxage` — Age header > max-age
- `expires_past_maxage_future` — Expires in past, max-age in future

### 5.9 HLS/DASH Chaos

- `hls_infinite_playlist` — Live-mode playlist that never ends
- `hls_segment_404` — Playlist references non-existent segments
- `hls_segment_wrong_type` — Segments return HTML instead of TS
- `hls_duration_mismatch` — EXTINF duration vs actual segment duration
- `hls_sequence_gap` — Media sequence number jumps
- `hls_master_recursive` — Master playlist points to itself
- `dash_invalid_xml` — Malformed MPD XML
- `dash_duration_mismatch` — MPD duration vs actual content
- `dash_recursive_mpd` — Location pointing back to same URL

### 5.10 Polyglot/Hybrid

- `gif_html_polyglot` — Valid GIF that also parses as HTML
- `svg_xss` — SVG with embedded script tags
- `svg_xxe` — SVG with XML entity injection
- `svg_billion_laughs` — SVG with nested entity expansion
- `bom_before_binary` — UTF-8 BOM prepended to binary content

## 6. URL Routing

Media content served under `/media/` prefix with format-based subpaths:

```
/media/image/{name}.png          — PNG image
/media/image/{name}.jpg          — JPEG image
/media/image/{name}.gif          — GIF (animated)
/media/image/{name}.bmp          — BMP image
/media/image/{name}.webp         — WebP image
/media/image/{name}.svg          — SVG image
/media/image/{name}.ico          — ICO icon
/media/image/{name}.tiff         — TIFF image
/media/audio/{name}.wav          — WAV audio
/media/audio/{name}.mp3          — MP3 audio
/media/audio/{name}.ogg          — OGG Vorbis audio
/media/audio/{name}.flac         — FLAC audio
/media/video/{name}.mp4          — MP4 video
/media/video/{name}.webm         — WebM video
/media/video/{name}.avi          — AVI video
/media/stream/{name}/playlist.m3u8  — HLS playlist
/media/stream/{name}/segment{n}.ts  — HLS segment
/media/stream/{name}/manifest.mpd   — DASH manifest
/media/stream/{name}/segment{n}.mp4 — DASH segment
/media/infinite/{format}         — Infinite content stream
/media/huge/{format}             — Large generated files
```

Content pages (`internal/content/engine.go`) embed `<img>`, `<audio>`, `<video>` tags pointing to these paths. Scanner discovery via `<link rel="prefetch">` and hidden `<a>` tags.

## 7. Admin Panel Integration

### 7.1 Feature Flag

`media_chaos` — master toggle (default: true)

### 7.2 Admin Config Keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `media_chaos_probability` | float64 | 30.0 | Probability (0-100%) that a media request gets chaos applied |
| `media_chaos_corruption_intensity` | float64 | 50.0 | How aggressive corruption is (0-100%) |
| `media_chaos_slow_min_ms` | float64 | 10.0 | Minimum delay for slow delivery modes (ms) |
| `media_chaos_slow_max_ms` | float64 | 1000.0 | Maximum delay for slow delivery modes (ms) |
| `media_chaos_infinite_max_bytes` | float64 | 104857600.0 | Safety cap for infinite streams (100MB default) |

### 7.3 Per-Category Toggles

All chaos categories from Section 5 are individually toggleable via `MediaChaosConfig` (same pattern as `APIChaosConfig`).

### 7.4 Admin API Endpoints

```
GET  /admin/api/mediachaos         — Current config snapshot
POST /admin/api/mediachaos         — Update categories/probability
```

### 7.5 Dashboard UI

New "Media Chaos" collapsible section in the Server tab:
- Master probability slider (0–100%)
- Corruption intensity slider (0–100%)
- Per-category toggle switches grouped by type (Format Corruption, Delivery, Range, Chunked, Slow, Infinite, Stream, Cache, HLS/DASH, Polyglot)
- Enable All / Disable All buttons

## 8. Config Export/Import

`ConfigExport` struct extended with `MediaChaosConfig map[string]bool` field. Round-trips through JSON export/import and PostgreSQL persistence.

## 9. Implementation Plan

### Phase 1: Media Generation (`internal/media/`)
- `generator.go` — Image generation (PNG, JPEG, GIF via stdlib; BMP, TIFF, ICO hand-crafted; WebP constant; SVG template)
- `formats.go` — Audio generation (WAV hand-crafted PCM; MP3/OGG/FLAC pre-computed constants); Video containers (MP4/WebM/AVI hand-crafted boxes with pre-computed codec constants)
- `streaming.go` — HLS/DASH playlist and segment generation
- `infinite.go` — io.Reader implementations for infinite PNG, GIF, WAV, MP4, random streams

### Phase 2: Media Chaos Engine (`internal/mediachaos/`)
- `engine.go` — Engine struct with probability, category dispatch (follows apichaos pattern)
- `corruption.go` — Format-aware corruption functions for each format
- `delivery.go` — HTTP delivery chaos (Content-Length, Content-Type, range, chunked, slow, infinite)
- `config.go` — MediaChaosConfig singleton, admin types

### Phase 3: Integration
- Handler dispatch in `server/handler.go`
- Feature flag + admin config in `dashboard/admin.go`
- Admin routes in `dashboard/admin_routes.go`
- Admin HTML section in `dashboard/admin_html.go`
- Content page embedding (`<img>`, `<audio>`, `<video>` tags)
- CDN integration (media paths handled by CDN engine when enabled)

### Phase 4: Testing
- Atomic tests: every config setting verified to influence responses
- Format validation: generated media validates as correct format
- Corruption tests: each corruption type produces expected glitch
- Delivery tests: Content-Length mismatches, chunked chaos, slow delivery measurable
- Config round-trip: export/import preserves all media chaos settings
- Integration tests: media paths respond correctly with server running

## 10. Dependencies

Go stdlib only:
- `image`, `image/png`, `image/jpeg`, `image/gif`, `image/color`, `image/draw`
- `compress/zlib`, `compress/flate`
- `hash/crc32`
- `encoding/binary`
- `math`, `math/rand`, `crypto/sha256`
- `bytes`, `io`, `fmt`, `strings`
- `net/http`, `time`, `sync`
