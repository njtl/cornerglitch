package media

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

// allFormats lists every supported Format constant.
var allFormats = []Format{
	FormatPNG, FormatJPEG, FormatGIF, FormatBMP, FormatWebP, FormatSVG,
	FormatICO, FormatTIFF, FormatWAV, FormatMP3, FormatOGG, FormatFLAC,
	FormatMP4, FormatWebM, FormatAVI, FormatHLS, FormatDASH, FormatTS,
}

// ---------------------------------------------------------------------------
// 1. FormatFromPath
// ---------------------------------------------------------------------------

func TestFormatFromPath(t *testing.T) {
	// All 18 recognised extensions (plus aliases like .jpg, .tif, .m4v, .m3u8, .mpd)
	cases := []struct {
		path string
		want Format
	}{
		// Primary extensions
		{"/images/logo.png", FormatPNG},
		{"/images/photo.jpeg", FormatJPEG},
		{"/images/photo.jpg", FormatJPEG},
		{"/images/anim.gif", FormatGIF},
		{"/images/icon.bmp", FormatBMP},
		{"/images/hero.webp", FormatWebP},
		{"/images/vector.svg", FormatSVG},
		{"/images/favicon.ico", FormatICO},
		{"/images/scan.tiff", FormatTIFF},
		{"/images/scan.tif", FormatTIFF},
		{"/audio/track.wav", FormatWAV},
		{"/audio/track.mp3", FormatMP3},
		{"/audio/track.ogg", FormatOGG},
		{"/audio/track.flac", FormatFLAC},
		{"/video/clip.mp4", FormatMP4},
		{"/video/clip.m4v", FormatMP4},
		{"/video/clip.webm", FormatWebM},
		{"/video/clip.avi", FormatAVI},
		{"/stream/live.m3u8", FormatHLS},
		{"/stream/manifest.mpd", FormatDASH},
		{"/stream/segment.ts", FormatTS},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got := FormatFromPath(tc.path)
			if got != tc.want {
				t.Errorf("FormatFromPath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}

	// Edge cases
	t.Run("no_extension", func(t *testing.T) {
		if got := FormatFromPath("/images/noext"); got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})

	t.Run("unknown_extension", func(t *testing.T) {
		if got := FormatFromPath("/file.xyz"); got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})

	t.Run("uppercase_extension", func(t *testing.T) {
		if got := FormatFromPath("/images/logo.PNG"); got != FormatPNG {
			t.Errorf("expected FormatPNG, got %q", got)
		}
	})

	t.Run("mixed_case_extension", func(t *testing.T) {
		if got := FormatFromPath("/photo.JpEg"); got != FormatJPEG {
			t.Errorf("expected FormatJPEG, got %q", got)
		}
	})

	t.Run("double_extension", func(t *testing.T) {
		// Should use the last extension
		if got := FormatFromPath("/backup.tar.png"); got != FormatPNG {
			t.Errorf("expected FormatPNG for double extension, got %q", got)
		}
	})

	t.Run("dot_only", func(t *testing.T) {
		if got := FormatFromPath("/files/."); got != "" {
			t.Errorf("expected empty for dot-only, got %q", got)
		}
	})

	t.Run("empty_path", func(t *testing.T) {
		if got := FormatFromPath(""); got != "" {
			t.Errorf("expected empty for empty path, got %q", got)
		}
	})

	t.Run("bare_filename", func(t *testing.T) {
		if got := FormatFromPath("file.wav"); got != FormatWAV {
			t.Errorf("expected FormatWAV, got %q", got)
		}
	})
}

// ---------------------------------------------------------------------------
// 2. ContentType
// ---------------------------------------------------------------------------

func TestContentType(t *testing.T) {
	expected := map[Format]string{
		FormatPNG:  "image/png",
		FormatJPEG: "image/jpeg",
		FormatGIF:  "image/gif",
		FormatBMP:  "image/bmp",
		FormatWebP: "image/webp",
		FormatSVG:  "image/svg+xml",
		FormatICO:  "image/x-icon",
		FormatTIFF: "image/tiff",
		FormatWAV:  "audio/wav",
		FormatMP3:  "audio/mpeg",
		FormatOGG:  "audio/ogg",
		FormatFLAC: "audio/flac",
		FormatMP4:  "video/mp4",
		FormatWebM: "video/webm",
		FormatAVI:  "video/x-msvideo",
		FormatHLS:  "application/vnd.apple.mpegurl",
		FormatDASH: "application/dash+xml",
		FormatTS:   "video/mp2t",
	}

	for fmt, want := range expected {
		t.Run(string(fmt), func(t *testing.T) {
			got := fmt.ContentType()
			if got != want {
				t.Errorf("Format(%q).ContentType() = %q, want %q", fmt, got, want)
			}
		})
	}

	t.Run("unknown_format", func(t *testing.T) {
		got := Format("unknown").ContentType()
		if got != "application/octet-stream" {
			t.Errorf("unknown format ContentType = %q, want application/octet-stream", got)
		}
	})
}

// ---------------------------------------------------------------------------
// 3. Generate — magic bytes / signatures
// ---------------------------------------------------------------------------

func TestGenerate_AllFormats_NonEmpty(t *testing.T) {
	gen := New()
	for _, fmt := range allFormats {
		t.Run(string(fmt), func(t *testing.T) {
			data, ct := gen.Generate(fmt, "/test/path."+string(fmt))
			if data == nil {
				t.Fatal("Generate returned nil data")
			}
			if len(data) == 0 {
				t.Fatal("Generate returned empty data")
			}
			if ct == "" {
				t.Fatal("Generate returned empty content type")
			}
			if ct != fmt.ContentType() {
				t.Errorf("content type = %q, want %q", ct, fmt.ContentType())
			}
		})
	}
}

func TestGenerate_MagicBytes(t *testing.T) {
	gen := New()
	path := "/media/test/sample"

	t.Run("PNG", func(t *testing.T) {
		data, _ := gen.Generate(FormatPNG, path+".png")
		if len(data) < 8 {
			t.Fatal("PNG data too short")
		}
		// PNG signature: \x89PNG\r\n\x1A\n
		want := []byte{0x89, 0x50, 0x4E, 0x47}
		if !bytes.HasPrefix(data, want) {
			t.Errorf("PNG magic = %x, want prefix %x", data[:4], want)
		}
	})

	t.Run("JPEG", func(t *testing.T) {
		data, _ := gen.Generate(FormatJPEG, path+".jpeg")
		if len(data) < 2 {
			t.Fatal("JPEG data too short")
		}
		if data[0] != 0xFF || data[1] != 0xD8 {
			t.Errorf("JPEG magic = %02x %02x, want FF D8", data[0], data[1])
		}
	})

	t.Run("GIF", func(t *testing.T) {
		data, _ := gen.Generate(FormatGIF, path+".gif")
		if len(data) < 6 {
			t.Fatal("GIF data too short")
		}
		header := string(data[:6])
		if header != "GIF89a" && header != "GIF87a" {
			t.Errorf("GIF header = %q, want GIF89a or GIF87a", header)
		}
	})

	t.Run("BMP", func(t *testing.T) {
		data, _ := gen.Generate(FormatBMP, path+".bmp")
		if len(data) < 2 {
			t.Fatal("BMP data too short")
		}
		if data[0] != 'B' || data[1] != 'M' {
			t.Errorf("BMP magic = %c%c, want BM", data[0], data[1])
		}
	})

	t.Run("WebP", func(t *testing.T) {
		data, _ := gen.Generate(FormatWebP, path+".webp")
		if len(data) < 12 {
			t.Fatal("WebP data too short")
		}
		if string(data[:4]) != "RIFF" {
			t.Errorf("WebP: first 4 bytes = %q, want RIFF", string(data[:4]))
		}
		if string(data[8:12]) != "WEBP" {
			t.Errorf("WebP: bytes 8-12 = %q, want WEBP", string(data[8:12]))
		}
	})

	t.Run("SVG", func(t *testing.T) {
		data, _ := gen.Generate(FormatSVG, path+".svg")
		s := string(data)
		if !strings.HasPrefix(s, "<?xml") && !strings.HasPrefix(s, "<svg") {
			t.Errorf("SVG does not start with <?xml or <svg, got prefix %q", s[:min(50, len(s))])
		}
	})

	t.Run("ICO", func(t *testing.T) {
		data, _ := gen.Generate(FormatICO, path+".ico")
		if len(data) < 4 {
			t.Fatal("ICO data too short")
		}
		// ICO: 00 00 01 00
		if data[0] != 0x00 || data[1] != 0x00 || data[2] != 0x01 || data[3] != 0x00 {
			t.Errorf("ICO magic = %02x %02x %02x %02x, want 00 00 01 00",
				data[0], data[1], data[2], data[3])
		}
	})

	t.Run("TIFF", func(t *testing.T) {
		data, _ := gen.Generate(FormatTIFF, path+".tiff")
		if len(data) < 4 {
			t.Fatal("TIFF data too short")
		}
		// Little-endian: II\x2A\x00  or big-endian: MM\x00\x2A
		le := data[0] == 'I' && data[1] == 'I' && data[2] == 0x2A && data[3] == 0x00
		be := data[0] == 'M' && data[1] == 'M' && data[2] == 0x00 && data[3] == 0x2A
		if !le && !be {
			t.Errorf("TIFF magic = %02x %02x %02x %02x, want II2A00 or MM002A",
				data[0], data[1], data[2], data[3])
		}
	})

	t.Run("WAV", func(t *testing.T) {
		data, _ := gen.Generate(FormatWAV, path+".wav")
		if len(data) < 12 {
			t.Fatal("WAV data too short")
		}
		if string(data[:4]) != "RIFF" {
			t.Errorf("WAV: first 4 bytes = %q, want RIFF", string(data[:4]))
		}
		if string(data[8:12]) != "WAVE" {
			t.Errorf("WAV: bytes 8-12 = %q, want WAVE", string(data[8:12]))
		}
	})

	t.Run("MP3", func(t *testing.T) {
		data, _ := gen.Generate(FormatMP3, path+".mp3")
		if len(data) < 3 {
			t.Fatal("MP3 data too short")
		}
		// Can start with FF FB (sync) or ID3 tag
		hasSync := data[0] == 0xFF && (data[1]&0xE0) == 0xE0
		hasID3 := string(data[:3]) == "ID3"
		if !hasSync && !hasID3 {
			t.Errorf("MP3 starts with %02x %02x %02x, want FF Fx or ID3",
				data[0], data[1], data[2])
		}
	})

	t.Run("OGG", func(t *testing.T) {
		data, _ := gen.Generate(FormatOGG, path+".ogg")
		if len(data) < 4 {
			t.Fatal("OGG data too short")
		}
		if string(data[:4]) != "OggS" {
			t.Errorf("OGG magic = %q, want OggS", string(data[:4]))
		}
	})

	t.Run("FLAC", func(t *testing.T) {
		data, _ := gen.Generate(FormatFLAC, path+".flac")
		if len(data) < 4 {
			t.Fatal("FLAC data too short")
		}
		if string(data[:4]) != "fLaC" {
			t.Errorf("FLAC magic = %q, want fLaC", string(data[:4]))
		}
	})

	t.Run("MP4", func(t *testing.T) {
		data, _ := gen.Generate(FormatMP4, path+".mp4")
		if len(data) < 8 {
			t.Fatal("MP4 data too short")
		}
		// bytes 4-7 should be "ftyp"
		if string(data[4:8]) != "ftyp" {
			t.Errorf("MP4 bytes 4-8 = %q, want ftyp", string(data[4:8]))
		}
	})

	t.Run("WebM", func(t *testing.T) {
		data, _ := gen.Generate(FormatWebM, path+".webm")
		if len(data) < 4 {
			t.Fatal("WebM data too short")
		}
		// EBML header: 0x1A 0x45 0xDF 0xA3
		if data[0] != 0x1A || data[1] != 0x45 || data[2] != 0xDF || data[3] != 0xA3 {
			t.Errorf("WebM magic = %02x %02x %02x %02x, want 1A 45 DF A3",
				data[0], data[1], data[2], data[3])
		}
	})

	t.Run("AVI", func(t *testing.T) {
		data, _ := gen.Generate(FormatAVI, path+".avi")
		if len(data) < 12 {
			t.Fatal("AVI data too short")
		}
		if string(data[:4]) != "RIFF" {
			t.Errorf("AVI: first 4 bytes = %q, want RIFF", string(data[:4]))
		}
		if string(data[8:12]) != "AVI " {
			t.Errorf("AVI: bytes 8-12 = %q, want 'AVI '", string(data[8:12]))
		}
	})

	t.Run("HLS", func(t *testing.T) {
		data, _ := gen.Generate(FormatHLS, path+".m3u8")
		s := string(data)
		if !strings.HasPrefix(s, "#EXTM3U") {
			t.Errorf("HLS does not start with #EXTM3U, got prefix %q", s[:min(30, len(s))])
		}
	})

	t.Run("DASH", func(t *testing.T) {
		data, _ := gen.Generate(FormatDASH, path+".mpd")
		s := string(data)
		if !strings.HasPrefix(s, "<?xml") {
			t.Errorf("DASH does not start with <?xml, got prefix %q", s[:min(30, len(s))])
		}
	})

	t.Run("TS", func(t *testing.T) {
		data, _ := gen.Generate(FormatTS, path+".ts")
		if len(data) < 1 {
			t.Fatal("TS data too short")
		}
		if data[0] != 0x47 {
			t.Errorf("TS sync byte = 0x%02x, want 0x47", data[0])
		}
		// Every 188 bytes should start with 0x47
		for offset := 0; offset+188 <= len(data); offset += 188 {
			if data[offset] != 0x47 {
				t.Errorf("TS sync byte at offset %d = 0x%02x, want 0x47", offset, data[offset])
			}
		}
		// Total length should be a multiple of 188
		if len(data)%188 != 0 {
			t.Errorf("TS data length %d is not a multiple of 188", len(data))
		}
	})
}

// ---------------------------------------------------------------------------
// 4. Determinism
// ---------------------------------------------------------------------------

func TestGenerate_Determinism(t *testing.T) {
	gen := New()
	for _, fmt := range allFormats {
		t.Run(string(fmt), func(t *testing.T) {
			path := "/determinism/test." + string(fmt)
			data1, ct1 := gen.Generate(fmt, path)
			data2, ct2 := gen.Generate(fmt, path)
			if ct1 != ct2 {
				t.Errorf("content types differ: %q vs %q", ct1, ct2)
			}
			if !bytes.Equal(data1, data2) {
				t.Errorf("outputs differ for same path (format %s): len %d vs %d", fmt, len(data1), len(data2))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 5. Different paths produce different output
// ---------------------------------------------------------------------------

func TestGenerate_DifferentPathsDifferentOutput(t *testing.T) {
	gen := New()
	// Test formats where content varies by path (excludes MP4, WebM, AVI
	// which use fixed codec payloads and produce identical containers)
	formatsToTest := []Format{
		FormatPNG, FormatJPEG, FormatGIF, FormatBMP, FormatSVG,
		FormatWAV, FormatOGG, FormatFLAC, FormatTS,
		FormatHLS, FormatDASH,
	}

	for _, fmt := range formatsToTest {
		t.Run(string(fmt), func(t *testing.T) {
			path1 := "/path/alpha." + string(fmt)
			path2 := "/path/beta." + string(fmt)
			data1, _ := gen.Generate(fmt, path1)
			data2, _ := gen.Generate(fmt, path2)
			if bytes.Equal(data1, data2) {
				t.Errorf("format %s produced identical output for different paths", fmt)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 6. GenerateStream (InfiniteReader)
// ---------------------------------------------------------------------------

func TestGenerateStream_ReturnsNonNil(t *testing.T) {
	gen := New()
	for _, fmt := range allFormats {
		t.Run(string(fmt), func(t *testing.T) {
			r := gen.GenerateStream(fmt, "/stream/test", 4096)
			if r == nil {
				t.Fatal("GenerateStream returned nil")
			}
		})
	}
}

func TestGenerateStream_ProducesData(t *testing.T) {
	gen := New()
	formatsToTest := []Format{FormatPNG, FormatMP4, FormatWAV, FormatTS, FormatHLS}

	for _, fmt := range formatsToTest {
		t.Run(string(fmt), func(t *testing.T) {
			r := gen.GenerateStream(fmt, "/stream/produce", 8192)
			buf := make([]byte, 1024)
			totalRead := 0
			for totalRead < 1024 {
				n, err := r.Read(buf[totalRead:])
				totalRead += n
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("Read error: %v", err)
				}
			}
			if totalRead < 1 {
				t.Errorf("expected at least some data, got %d bytes", totalRead)
			}
		})
	}
}

func TestGenerateStream_RespectsMaxBytes(t *testing.T) {
	gen := New()
	formatsToTest := []Format{FormatPNG, FormatMP4, FormatWAV, FormatTS, FormatHLS}

	for _, fmt := range formatsToTest {
		t.Run(string(fmt), func(t *testing.T) {
			maxBytes := int64(2048)
			r := gen.GenerateStream(fmt, "/stream/limit", maxBytes)

			var total int64
			buf := make([]byte, 512)
			for {
				n, err := r.Read(buf)
				total += int64(n)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("Read error: %v", err)
				}
			}

			if total > maxBytes {
				t.Errorf("read %d bytes exceeding maxBytes %d", total, maxBytes)
			}
			if total == 0 {
				t.Error("read 0 bytes, expected some data")
			}
		})
	}
}

func TestGenerateStream_DefaultMaxBytes(t *testing.T) {
	// When maxBytes is 0, the reader should use 10MB default
	r := NewInfiniteReader(FormatPNG, "seed", 0)
	if r.maxBytes != 10*1024*1024 {
		t.Errorf("default maxBytes = %d, want %d", r.maxBytes, 10*1024*1024)
	}
}

func TestGenerateStream_DeterministicAcrossReads(t *testing.T) {
	gen := New()
	maxBytes := int64(4096)

	readAll := func() []byte {
		r := gen.GenerateStream(FormatWAV, "/stream/det", maxBytes)
		var out bytes.Buffer
		buf := make([]byte, 512)
		for {
			n, err := r.Read(buf)
			out.Write(buf[:n])
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
		}
		return out.Bytes()
	}

	d1 := readAll()
	d2 := readAll()
	if !bytes.Equal(d1, d2) {
		t.Errorf("streaming output not deterministic: len %d vs %d", len(d1), len(d2))
	}
}

func TestGenerateStream_StreamMagicBytes(t *testing.T) {
	gen := New()
	maxBytes := int64(4096)

	t.Run("PNG_stream", func(t *testing.T) {
		r := gen.GenerateStream(FormatPNG, "/stream/magic.png", maxBytes)
		buf := make([]byte, 8)
		n, _ := io.ReadAtLeast(r, buf, 8)
		if n < 8 {
			t.Fatal("could not read 8 bytes for PNG stream")
		}
		want := []byte{0x89, 0x50, 0x4E, 0x47}
		if !bytes.HasPrefix(buf, want) {
			t.Errorf("PNG stream magic = %x, want prefix %x", buf[:4], want)
		}
	})

	t.Run("WAV_stream", func(t *testing.T) {
		r := gen.GenerateStream(FormatWAV, "/stream/magic.wav", maxBytes)
		buf := make([]byte, 12)
		n, _ := io.ReadAtLeast(r, buf, 12)
		if n < 12 {
			t.Fatal("could not read 12 bytes for WAV stream")
		}
		if string(buf[:4]) != "RIFF" {
			t.Errorf("WAV stream: first 4 bytes = %q, want RIFF", string(buf[:4]))
		}
		if string(buf[8:12]) != "WAVE" {
			t.Errorf("WAV stream: bytes 8-12 = %q, want WAVE", string(buf[8:12]))
		}
	})

	t.Run("TS_stream", func(t *testing.T) {
		r := gen.GenerateStream(FormatTS, "/stream/magic.ts", maxBytes)
		buf := make([]byte, 188)
		n, _ := io.ReadAtLeast(r, buf, 1)
		if n < 1 {
			t.Fatal("could not read 1 byte for TS stream")
		}
		if buf[0] != 0x47 {
			t.Errorf("TS stream sync byte = 0x%02x, want 0x47", buf[0])
		}
	})

	t.Run("HLS_stream", func(t *testing.T) {
		r := gen.GenerateStream(FormatHLS, "/stream/magic.m3u8", maxBytes)
		buf := make([]byte, 64)
		n, _ := io.ReadAtLeast(r, buf, 7)
		if n < 7 {
			t.Fatal("could not read 7 bytes for HLS stream")
		}
		if !strings.HasPrefix(string(buf[:n]), "#EXTM3U") {
			t.Errorf("HLS stream does not start with #EXTM3U")
		}
	})

	t.Run("MP4_stream", func(t *testing.T) {
		r := gen.GenerateStream(FormatMP4, "/stream/magic.mp4", maxBytes)
		buf := make([]byte, 64)
		n, _ := io.ReadAtLeast(r, buf, 8)
		if n < 8 {
			t.Fatal("could not read 8 bytes for MP4 stream")
		}
		// The MP4 stream should start with ftyp box (bytes 4-7 = "ftyp")
		if string(buf[4:8]) != "ftyp" {
			t.Errorf("MP4 stream bytes 4-8 = %q, want ftyp", string(buf[4:8]))
		}
	})
}

// ---------------------------------------------------------------------------
// 7. SetDimensions
// ---------------------------------------------------------------------------

func TestSetDimensions(t *testing.T) {
	gen := New()

	// Default dimensions are 320x240
	data1, _ := gen.Generate(FormatBMP, "/dim/default.bmp")
	w1, h1 := bmpDimensions(data1)
	if w1 != 320 || h1 != 240 {
		t.Errorf("default BMP dims = %dx%d, want 320x240", w1, h1)
	}

	// Change dimensions
	gen.SetDimensions(160, 120)
	data2, _ := gen.Generate(FormatBMP, "/dim/small.bmp")
	w2, h2 := bmpDimensions(data2)
	if w2 != 160 || h2 != 120 {
		t.Errorf("small BMP dims = %dx%d, want 160x120", w2, h2)
	}

	// Verify that the outputs are different sizes
	if len(data1) == len(data2) {
		t.Error("expected different data sizes for different dimensions")
	}
}

func TestSetDimensions_ZeroIgnored(t *testing.T) {
	gen := New()
	gen.SetDimensions(0, 0) // should not change from default
	data, _ := gen.Generate(FormatBMP, "/dim/zero.bmp")
	w, h := bmpDimensions(data)
	if w != 320 || h != 240 {
		t.Errorf("after SetDimensions(0,0) BMP dims = %dx%d, want 320x240 (unchanged)", w, h)
	}
}

func TestSetDimensions_PartialUpdate(t *testing.T) {
	gen := New()
	gen.SetDimensions(100, 0) // only width changes
	data, _ := gen.Generate(FormatBMP, "/dim/partial.bmp")
	w, h := bmpDimensions(data)
	if w != 100 {
		t.Errorf("width = %d, want 100", w)
	}
	if h != 240 {
		t.Errorf("height = %d, want 240 (unchanged)", h)
	}
}

// bmpDimensions extracts width and height from BMP data.
// BMP BITMAPINFOHEADER: width at offset 18, height at offset 22 (little-endian int32).
func bmpDimensions(data []byte) (int, int) {
	if len(data) < 26 {
		return 0, 0
	}
	w := int(binary.LittleEndian.Uint32(data[18:22]))
	h := int(int32(binary.LittleEndian.Uint32(data[22:26])))
	if h < 0 {
		h = -h // top-down BMP uses negative height
	}
	return w, h
}

// ---------------------------------------------------------------------------
// 8. Edge cases
// ---------------------------------------------------------------------------

func TestGenerate_EmptyPath(t *testing.T) {
	gen := New()
	for _, fmt := range allFormats {
		t.Run(string(fmt), func(t *testing.T) {
			data, ct := gen.Generate(fmt, "")
			if data == nil || len(data) == 0 {
				t.Error("Generate with empty path returned nil/empty data")
			}
			if ct == "" {
				t.Error("Generate with empty path returned empty content type")
			}
		})
	}
}

func TestGenerate_VeryLongPath(t *testing.T) {
	gen := New()
	longPath := "/" + strings.Repeat("a", 10000) + ".png"
	data, ct := gen.Generate(FormatPNG, longPath)
	if data == nil || len(data) == 0 {
		t.Fatal("Generate with very long path returned nil/empty data")
	}
	if ct != "image/png" {
		t.Errorf("content type = %q, want image/png", ct)
	}
	// Should still be valid PNG
	if !bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4E, 0x47}) {
		t.Error("long-path PNG missing magic bytes")
	}
}

func TestGenerate_SpecialCharactersInPath(t *testing.T) {
	gen := New()
	specialPaths := []string{
		"/path/with spaces/file.png",
		"/path/with%20encoding/file.jpeg",
		"/path/with/日本語/ファイル.gif",
		"/path/with/emoji/🎵.wav",
		"/path/../traversal/../../file.mp4",
		"/path/with?query=1&foo=bar.webm",
		"/path/with#fragment.ogg",
	}

	for _, p := range specialPaths {
		t.Run(p, func(t *testing.T) {
			// These should not panic or return nil
			fmt := FormatFromPath(p)
			if fmt == "" {
				// Use a known format if the special path doesn't resolve
				fmt = FormatPNG
			}
			data, _ := gen.Generate(fmt, p)
			if data == nil || len(data) == 0 {
				t.Errorf("Generate returned nil/empty for special path %q", p)
			}
		})
	}
}

func TestGenerate_UnknownFormat(t *testing.T) {
	gen := New()
	data, ct := gen.Generate(Format("unknown"), "/test/file.xyz")
	if data == nil {
		t.Fatal("Generate returned nil for unknown format")
	}
	// Unknown format should return empty data per the switch default
	if len(data) != 0 {
		t.Errorf("expected empty data for unknown format, got %d bytes", len(data))
	}
	if ct != "application/octet-stream" {
		t.Errorf("content type = %q, want application/octet-stream", ct)
	}
}

// ---------------------------------------------------------------------------
// Additional structural validations
// ---------------------------------------------------------------------------

func TestGenerate_BMP_StructuralValidity(t *testing.T) {
	gen := New()
	data, _ := gen.Generate(FormatBMP, "/struct/test.bmp")

	if len(data) < 54 {
		t.Fatal("BMP data too short for headers")
	}

	// File header
	if string(data[:2]) != "BM" {
		t.Error("BMP missing BM signature")
	}
	fileSize := binary.LittleEndian.Uint32(data[2:6])
	if int(fileSize) != len(data) {
		t.Errorf("BMP file size header = %d, actual = %d", fileSize, len(data))
	}
	pixelOffset := binary.LittleEndian.Uint32(data[10:14])
	if pixelOffset != 54 {
		t.Errorf("BMP pixel data offset = %d, want 54", pixelOffset)
	}

	// DIB header
	dibSize := binary.LittleEndian.Uint32(data[14:18])
	if dibSize != 40 {
		t.Errorf("BMP DIB header size = %d, want 40", dibSize)
	}
	bpp := binary.LittleEndian.Uint16(data[28:30])
	if bpp != 24 {
		t.Errorf("BMP bits per pixel = %d, want 24", bpp)
	}
}

func TestGenerate_WAV_StructuralValidity(t *testing.T) {
	gen := New()
	data, _ := gen.Generate(FormatWAV, "/struct/test.wav")

	if len(data) < 44 {
		t.Fatal("WAV data too short")
	}

	// RIFF header
	if string(data[:4]) != "RIFF" {
		t.Error("WAV missing RIFF")
	}
	if string(data[8:12]) != "WAVE" {
		t.Error("WAV missing WAVE")
	}
	if string(data[12:16]) != "fmt " {
		t.Error("WAV missing fmt chunk")
	}
	// PCM format = 1
	audioFormat := binary.LittleEndian.Uint16(data[20:22])
	if audioFormat != 1 {
		t.Errorf("WAV audio format = %d, want 1 (PCM)", audioFormat)
	}
}

func TestGenerate_MP4_FtypBox(t *testing.T) {
	gen := New()
	data, _ := gen.Generate(FormatMP4, "/struct/test.mp4")

	if len(data) < 24 {
		t.Fatal("MP4 data too short")
	}

	// ftyp box
	boxSize := binary.BigEndian.Uint32(data[:4])
	if string(data[4:8]) != "ftyp" {
		t.Fatal("MP4 first box is not ftyp")
	}
	if int(boxSize) > len(data) {
		t.Fatal("ftyp box size exceeds data length")
	}
	// Major brand = "isom"
	if string(data[8:12]) != "isom" {
		t.Errorf("MP4 major brand = %q, want isom", string(data[8:12]))
	}
}

func TestGenerate_ICO_DirectoryEntry(t *testing.T) {
	gen := New()
	data, _ := gen.Generate(FormatICO, "/struct/test.ico")

	if len(data) < 22 {
		t.Fatal("ICO data too short")
	}

	// Header: 2 bytes reserved + 2 bytes type + 2 bytes count
	icoType := binary.LittleEndian.Uint16(data[2:4])
	if icoType != 1 {
		t.Errorf("ICO type = %d, want 1", icoType)
	}
	imageCount := binary.LittleEndian.Uint16(data[4:6])
	if imageCount != 1 {
		t.Errorf("ICO image count = %d, want 1", imageCount)
	}

	// Directory entry at offset 6: width=32, height=32
	if data[6] != 32 {
		t.Errorf("ICO icon width = %d, want 32", data[6])
	}
	if data[7] != 32 {
		t.Errorf("ICO icon height = %d, want 32", data[7])
	}
}

func TestGenerate_OGG_PageStructure(t *testing.T) {
	gen := New()
	data, _ := gen.Generate(FormatOGG, "/struct/test.ogg")

	if len(data) < 27 {
		t.Fatal("OGG data too short")
	}

	// First page capture pattern
	if string(data[:4]) != "OggS" {
		t.Fatal("OGG first page missing OggS capture")
	}
	// Version should be 0
	if data[4] != 0x00 {
		t.Errorf("OGG stream version = %d, want 0", data[4])
	}
	// First page should have BOS (beginning of stream) flag bit 0x02
	if data[5]&0x02 == 0 {
		t.Error("OGG first page missing BOS flag")
	}
}

func TestGenerate_FLAC_StreamInfo(t *testing.T) {
	gen := New()
	data, _ := gen.Generate(FormatFLAC, "/struct/test.flac")

	if len(data) < 42 {
		t.Fatal("FLAC data too short")
	}

	// fLaC marker
	if string(data[:4]) != "fLaC" {
		t.Fatal("FLAC missing fLaC marker")
	}

	// First metadata block type should be STREAMINFO (type 0)
	blockType := data[4] & 0x7F
	if blockType != 0 {
		t.Errorf("FLAC first metadata block type = %d, want 0 (STREAMINFO)", blockType)
	}

	// STREAMINFO length should be 34 bytes
	blockLen := int(data[5])<<16 | int(data[6])<<8 | int(data[7])
	if blockLen != 34 {
		t.Errorf("FLAC STREAMINFO length = %d, want 34", blockLen)
	}
}

func TestGenerate_WebM_EBMLHeader(t *testing.T) {
	gen := New()
	data, _ := gen.Generate(FormatWebM, "/struct/test.webm")

	if len(data) < 40 {
		t.Fatal("WebM data too short")
	}

	// EBML header element ID: 0x1A 0x45 0xDF 0xA3
	if data[0] != 0x1A || data[1] != 0x45 || data[2] != 0xDF || data[3] != 0xA3 {
		t.Error("WebM missing EBML header element")
	}

	// Verify the DocType is "webm" somewhere in the first 100 bytes
	if !bytes.Contains(data[:min(100, len(data))], []byte("webm")) {
		t.Error("WebM EBML header does not contain 'webm' DocType")
	}
}

func TestGenerate_AVI_Structure(t *testing.T) {
	gen := New()
	data, _ := gen.Generate(FormatAVI, "/struct/test.avi")

	if len(data) < 12 {
		t.Fatal("AVI data too short")
	}

	if string(data[:4]) != "RIFF" {
		t.Error("AVI missing RIFF header")
	}
	if string(data[8:12]) != "AVI " {
		t.Error("AVI missing AVI  type")
	}

	// Should contain hdrl, movi, idx1 chunks somewhere in the data
	if !bytes.Contains(data, []byte("hdrl")) {
		t.Error("AVI missing hdrl list")
	}
	if !bytes.Contains(data, []byte("movi")) {
		t.Error("AVI missing movi list")
	}
	if !bytes.Contains(data, []byte("idx1")) {
		t.Error("AVI missing idx1 index")
	}
}

func TestGenerate_HLS_PlaylistContent(t *testing.T) {
	gen := New()
	data, _ := gen.Generate(FormatHLS, "/struct/test.m3u8")
	s := string(data)

	if !strings.HasPrefix(s, "#EXTM3U") {
		t.Error("HLS missing #EXTM3U header")
	}
	if !strings.Contains(s, "#EXT-X-VERSION") {
		t.Error("HLS missing #EXT-X-VERSION")
	}
	// Should contain segment info (EXTINF) or stream info
	if !strings.Contains(s, "#EXTINF") && !strings.Contains(s, "#EXT-X-STREAM-INF") {
		t.Error("HLS missing #EXTINF or #EXT-X-STREAM-INF")
	}
}

func TestGenerate_DASH_ManifestContent(t *testing.T) {
	gen := New()
	data, _ := gen.Generate(FormatDASH, "/struct/test.mpd")
	s := string(data)

	if !strings.HasPrefix(s, "<?xml") {
		t.Error("DASH missing XML declaration")
	}
	if !strings.Contains(s, "<MPD") {
		t.Error("DASH missing MPD element")
	}
	if !strings.Contains(s, "AdaptationSet") {
		t.Error("DASH missing AdaptationSet")
	}
	if !strings.Contains(s, "Representation") {
		t.Error("DASH missing Representation")
	}
}

func TestGenerate_TS_PacketSize(t *testing.T) {
	gen := New()
	data, _ := gen.Generate(FormatTS, "/struct/test.ts")

	if len(data) < 188 {
		t.Fatal("TS data too short for even one packet")
	}
	if len(data)%188 != 0 {
		t.Errorf("TS data length = %d, not a multiple of 188", len(data))
	}

	// Verify all packets start with sync byte
	numPackets := len(data) / 188
	for i := 0; i < numPackets; i++ {
		offset := i * 188
		if data[offset] != 0x47 {
			t.Errorf("TS packet %d at offset %d has sync byte 0x%02x, want 0x47",
				i, offset, data[offset])
		}
	}
}

// min returns the smaller of a or b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
