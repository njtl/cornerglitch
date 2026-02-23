package spider

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"net/http"
)

// serveFavicon serves /favicon.ico as a valid 16x16 ICO file or garbage bytes.
// Valid ICO structure:
//   - ICO header (6 bytes)
//   - ICO directory entry (16 bytes)
//   - BMP info header (40 bytes)
//   - Pixel data (16*16*4 = 1024 bytes for 32-bit BGRA)
func (h *Handler) serveFavicon(w http.ResponseWriter, r *http.Request) int {
	h.cfg.mu.RLock()
	errorRate := h.cfg.FaviconErrorRate
	h.cfg.mu.RUnlock()

	if shouldError(r.URL.Path, "favicon_error", errorRate) {
		return h.serveBrokenFavicon(w, r)
	}

	ico := buildICO()

	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=604800")
	w.WriteHeader(200)
	w.Write(ico)
	return 200
}

// serveAppleTouchIcon serves apple-touch-icon.png or apple-touch-icon-precomposed.png
// as a valid 1x1 PNG or garbage bytes.
func (h *Handler) serveAppleTouchIcon(w http.ResponseWriter, r *http.Request) int {
	h.cfg.mu.RLock()
	errorRate := h.cfg.FaviconErrorRate
	h.cfg.mu.RUnlock()

	if shouldError(r.URL.Path, "touchicon_error", errorRate) {
		return h.serveBrokenPNG(w, r)
	}

	png := buildMinimalPNG(0x33, 0x99, 0xFF) // nice blue color

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=604800")
	w.WriteHeader(200)
	w.Write(png)
	return 200
}

// serveBrokenFavicon writes garbage bytes with an image/x-icon content type.
func (h *Handler) serveBrokenFavicon(w http.ResponseWriter, r *http.Request) int {
	rng := seedRand(r.URL.Path + "broken_favicon")
	mode := rng.Intn(3)

	switch mode {
	case 0:
		// Random garbage bytes
		w.Header().Set("Content-Type", "image/x-icon")
		w.WriteHeader(200)
		garbage := make([]byte, 128)
		for i := range garbage {
			garbage[i] = byte(rng.Intn(256))
		}
		w.Write(garbage)
	case 1:
		// ICO header but truncated (no pixel data)
		w.Header().Set("Content-Type", "image/x-icon")
		w.WriteHeader(200)
		// Just write the 6-byte ICO header
		w.Write([]byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00})
	case 2:
		// Empty response with wrong content type
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte("<html><body>Not an icon</body></html>"))
	}
	return 200
}

// serveBrokenPNG writes garbage bytes with an image/png content type.
func (h *Handler) serveBrokenPNG(w http.ResponseWriter, r *http.Request) int {
	rng := seedRand(r.URL.Path + "broken_png")
	mode := rng.Intn(3)

	switch mode {
	case 0:
		// Random bytes
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(200)
		garbage := make([]byte, 64)
		for i := range garbage {
			garbage[i] = byte(rng.Intn(256))
		}
		w.Write(garbage)
	case 1:
		// PNG signature but truncated
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(200)
		w.Write([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
	case 2:
		// 404
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(404)
		w.Write([]byte("Not Found"))
		return 404
	}
	return 200
}

// buildICO creates a valid 16x16 ICO file with a colored square.
// Format: ICO header (6B) + dir entry (16B) + BMP header (40B) + pixel data (1024B).
func buildICO() []byte {
	const (
		width   = 16
		height  = 16
		bpp     = 32
		pixSize = width * height * (bpp / 8) // 1024
		bmpHdr  = 40
		dirOff  = 6 + 16 // offset to image data
		imgSize = bmpHdr + pixSize
	)

	buf := &bytes.Buffer{}

	// ICO Header (6 bytes)
	binary.Write(buf, binary.LittleEndian, uint16(0))    // reserved
	binary.Write(buf, binary.LittleEndian, uint16(1))    // type: ICO
	binary.Write(buf, binary.LittleEndian, uint16(1))    // image count

	// ICO Directory Entry (16 bytes)
	buf.WriteByte(width)                                   // width
	buf.WriteByte(height)                                  // height
	buf.WriteByte(0)                                       // color palette count
	buf.WriteByte(0)                                       // reserved
	binary.Write(buf, binary.LittleEndian, uint16(1))     // color planes
	binary.Write(buf, binary.LittleEndian, uint16(bpp))   // bits per pixel
	binary.Write(buf, binary.LittleEndian, uint32(imgSize)) // image data size
	binary.Write(buf, binary.LittleEndian, uint32(dirOff))  // offset to image data

	// BMP Info Header (BITMAPINFOHEADER, 40 bytes)
	binary.Write(buf, binary.LittleEndian, uint32(bmpHdr))      // header size
	binary.Write(buf, binary.LittleEndian, int32(width))         // width
	binary.Write(buf, binary.LittleEndian, int32(height*2))      // height (doubled for ICO: XOR + AND mask)
	binary.Write(buf, binary.LittleEndian, uint16(1))            // planes
	binary.Write(buf, binary.LittleEndian, uint16(bpp))          // bits per pixel
	binary.Write(buf, binary.LittleEndian, uint32(0))            // compression (none)
	binary.Write(buf, binary.LittleEndian, uint32(pixSize))      // image size
	binary.Write(buf, binary.LittleEndian, int32(2835))          // X ppm (~72 DPI)
	binary.Write(buf, binary.LittleEndian, int32(2835))          // Y ppm
	binary.Write(buf, binary.LittleEndian, uint32(0))            // colors used
	binary.Write(buf, binary.LittleEndian, uint32(0))            // important colors

	// Pixel data: 16x16 BGRA (blue=0x66, green=0x33, red=0xCC, alpha=0xFF)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			buf.WriteByte(0x66) // B
			buf.WriteByte(0x33) // G
			buf.WriteByte(0xCC) // R
			buf.WriteByte(0xFF) // A
		}
	}

	return buf.Bytes()
}

// buildMinimalPNG creates a valid 1x1 PNG with the given RGB color.
// Structure: signature (8B) + IHDR chunk + IDAT chunk + IEND chunk.
func buildMinimalPNG(r, g, b byte) []byte {
	buf := &bytes.Buffer{}

	// PNG Signature (8 bytes)
	buf.Write([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})

	// IHDR chunk: 13 bytes of data
	ihdrData := &bytes.Buffer{}
	binary.Write(ihdrData, binary.BigEndian, uint32(1))  // width
	binary.Write(ihdrData, binary.BigEndian, uint32(1))  // height
	ihdrData.WriteByte(8)                                 // bit depth
	ihdrData.WriteByte(2)                                 // color type: RGB
	ihdrData.WriteByte(0)                                 // compression
	ihdrData.WriteByte(0)                                 // filter
	ihdrData.WriteByte(0)                                 // interlace
	writeChunk(buf, "IHDR", ihdrData.Bytes())

	// IDAT chunk: deflate-compressed scanline
	// For 1x1 RGB: filter byte (0x00) + R + G + B
	// We use a raw deflate block (no compression):
	// 0x78 0x01 = zlib header (CM=8 deflate, CINFO=7, FCHECK=1)
	// Then a stored block: 0x01 (final block, stored), 0x04 0x00 (length=4), 0xFB 0xFF (one's complement)
	// Then the 4 data bytes: filter=0, R, G, B
	// Then Adler-32 checksum of the uncompressed data

	// Compute Adler-32 of the raw scanline [0x00, r, g, b]
	rawData := []byte{0x00, r, g, b}
	adler := adler32(rawData)

	idatData := &bytes.Buffer{}
	idatData.WriteByte(0x78) // zlib CMF
	idatData.WriteByte(0x01) // zlib FLG
	idatData.WriteByte(0x01) // BFINAL=1, BTYPE=00 (stored)
	// Length of stored block = 4 bytes (little-endian)
	idatData.WriteByte(0x04)
	idatData.WriteByte(0x00)
	// One's complement of length
	idatData.WriteByte(0xFB)
	idatData.WriteByte(0xFF)
	// Raw data
	idatData.Write(rawData)
	// Adler-32 (big-endian)
	binary.Write(idatData, binary.BigEndian, adler)
	writeChunk(buf, "IDAT", idatData.Bytes())

	// IEND chunk: no data
	writeChunk(buf, "IEND", nil)

	return buf.Bytes()
}

// writeChunk writes a PNG chunk: length (4B) + type (4B) + data + CRC (4B).
func writeChunk(buf *bytes.Buffer, chunkType string, data []byte) {
	binary.Write(buf, binary.BigEndian, uint32(len(data)))
	buf.WriteString(chunkType)
	if len(data) > 0 {
		buf.Write(data)
	}

	// CRC covers type + data
	crcData := make([]byte, 4+len(data))
	copy(crcData, []byte(chunkType))
	if len(data) > 0 {
		copy(crcData[4:], data)
	}
	crc := crc32.ChecksumIEEE(crcData)
	binary.Write(buf, binary.BigEndian, crc)
}

// adler32 computes the Adler-32 checksum of the given data.
func adler32(data []byte) uint32 {
	const mod = 65521
	var a uint32 = 1
	var bv uint32 = 0
	for _, d := range data {
		a = (a + uint32(d)) % mod
		bv = (bv + a) % mod
	}
	return (bv << 16) | a
}
