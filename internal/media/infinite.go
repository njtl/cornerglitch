package media

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"math/rand"
)

// InfiniteReader generates media content as an unbounded stream.
// It implements io.Reader and generates content on-demand.
type InfiniteReader struct {
	format        Format
	buf           bytes.Buffer
	rng           *rand.Rand
	written       int64
	maxBytes      int64
	phase         int  // tracks generation phase (header done, streaming data, etc.)
	headerWritten bool
	// format-specific state
	frameCount    int
	freq          float64  // for WAV/audio: sine wave frequency
	sampleIndex   int      // for WAV: current sample position
	seqNum        int      // for PNG IDAT / GIF frames
	width         int
	height        int
}

// NewInfiniteReader creates a streaming reader for the given format.
// maxBytes caps total output; 0 means use a 10MB default.
func NewInfiniteReader(format Format, seed string, maxBytes int64) *InfiniteReader {
	if maxBytes <= 0 {
		maxBytes = 10 * 1024 * 1024
	}
	rng := deterministicRng(seed)

	r := &InfiniteReader{
		format:   format,
		rng:      rng,
		maxBytes: maxBytes,
		width:    320,
		height:   240,
	}

	// Pick audio frequency for WAV
	freqs := []float64{220.0, 440.0, 660.0, 880.0}
	r.freq = freqs[rng.Intn(len(freqs))]

	return r
}

// Read implements io.Reader, generating content on-demand.
func (r *InfiniteReader) Read(p []byte) (int, error) {
	if r.written >= r.maxBytes {
		return 0, io.EOF
	}

	// Refill internal buffer if needed
	for r.buf.Len() == 0 {
		if err := r.generate(); err != nil {
			if r.buf.Len() == 0 {
				return 0, err
			}
			break
		}
	}

	// How many bytes can we return?
	remaining := r.maxBytes - r.written
	available := int64(r.buf.Len())
	toRead := int64(len(p))
	if toRead > remaining {
		toRead = remaining
	}
	if toRead > available {
		toRead = available
	}

	n, err := r.buf.Read(p[:toRead])
	r.written += int64(n)

	if r.written >= r.maxBytes {
		return n, io.EOF
	}
	return n, err
}

// generate fills the internal buffer with the next chunk of content.
func (r *InfiniteReader) generate() error {
	switch r.format {
	case FormatPNG:
		return r.generatePNGChunk()
	case FormatGIF:
		return r.generateGIFChunk()
	case FormatWAV:
		return r.generateWAVChunk()
	default:
		return r.generateRandomChunk()
	}
}

// generatePNGChunk generates the PNG header on phase 0, then IDAT chunks.
func (r *InfiniteReader) generatePNGChunk() error {
	if !r.headerWritten {
		// Write PNG signature
		r.buf.Write([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})

		// Write IHDR chunk
		ihdrData := make([]byte, 13)
		binary.BigEndian.PutUint32(ihdrData[0:], uint32(r.width))
		binary.BigEndian.PutUint32(ihdrData[4:], uint32(r.height))
		ihdrData[8] = 8  // bit depth
		ihdrData[9] = 2  // color type = truecolor (RGB)
		ihdrData[10] = 0 // compression method
		ihdrData[11] = 0 // filter method
		ihdrData[12] = 0 // interlace method
		r.writePNGChunk("IHDR", ihdrData)

		r.headerWritten = true
	}

	// Generate an IDAT chunk with one row of pixel data (filtered)
	// PNG IDAT contains zlib-compressed filtered rows.
	// For streaming simplicity, we generate a raw image and encode it via stdlib.
	// Each call generates a new 16-row stripe.
	stripeHeight := 16
	img := image.NewRGBA(image.Rect(0, 0, r.width, stripeHeight))

	// Fill with random or pattern pixels
	c := color.RGBA{
		R: uint8(r.rng.Intn(256)),
		G: uint8(r.rng.Intn(256)),
		B: uint8(r.rng.Intn(256)),
		A: 255,
	}
	for y := 0; y < stripeHeight; y++ {
		for x := 0; x < r.width; x++ {
			// Slight variation per pixel
			img.SetRGBA(x, y, color.RGBA{
				R: uint8(int(c.R) + r.rng.Intn(30) - 15),
				G: uint8(int(c.G) + r.rng.Intn(30) - 15),
				B: uint8(int(c.B) + r.rng.Intn(30) - 15),
				A: 255,
			})
		}
	}

	// Encode the stripe as a standalone PNG and extract its IDAT data
	var stripeBuf bytes.Buffer
	if err := png.Encode(&stripeBuf, img); err != nil {
		return err
	}

	// Extract IDAT chunks from the encoded stripe PNG
	stripeBytes := stripeBuf.Bytes()
	idatData := extractPNGIDATData(stripeBytes)

	if len(idatData) > 0 {
		r.writePNGChunk("IDAT", idatData)
	}

	r.seqNum++

	// After many stripes, write IEND to finish the PNG
	// (this won't be reached under normal streaming, but ensures valid output if capped)
	if r.seqNum > 1000 {
		r.writePNGChunk("IEND", []byte{})
		return io.EOF
	}

	return nil
}

// writePNGChunk writes a PNG chunk to the internal buffer.
func (r *InfiniteReader) writePNGChunk(chunkType string, data []byte) {
	binary.Write(&r.buf, binary.BigEndian, uint32(len(data)))
	r.buf.WriteString(chunkType)
	r.buf.Write(data)
	// CRC over type + data
	crcVal := crc32.NewIEEE()
	crcVal.Write([]byte(chunkType))
	crcVal.Write(data)
	binary.Write(&r.buf, binary.BigEndian, crcVal.Sum32())
}

// extractPNGIDATData extracts the concatenated IDAT payload from a PNG byte slice.
func extractPNGIDATData(pngBytes []byte) []byte {
	var result []byte
	i := 8 // skip PNG signature
	for i+8 <= len(pngBytes) {
		chunkLen := binary.BigEndian.Uint32(pngBytes[i:])
		chunkType := string(pngBytes[i+4 : i+8])
		if chunkType == "IDAT" && i+8+int(chunkLen) <= len(pngBytes) {
			result = append(result, pngBytes[i+8:i+8+int(chunkLen)]...)
		}
		i += 8 + int(chunkLen) + 4 // size + type + data + CRC
	}
	return result
}

// generateGIFChunk writes the GIF header on phase 0, then keeps generating frames.
func (r *InfiniteReader) generateGIFChunk() error {
	if !r.headerWritten {
		// GIF89a header
		r.buf.WriteString("GIF89a")

		// Logical Screen Descriptor (7 bytes)
		binary.Write(&r.buf, binary.LittleEndian, uint16(r.width))
		binary.Write(&r.buf, binary.LittleEndian, uint16(r.height))
		// Packed: Global Color Table Flag=0, Color Resolution=7, Sort=0, GCT size=0
		r.buf.WriteByte(0x70)
		r.buf.WriteByte(0x00) // background color index
		r.buf.WriteByte(0x00) // pixel aspect ratio

		// Netscape Application Extension (loop count = 0 = infinite)
		r.buf.Write([]byte{
			0x21, 0xFF, 0x0B, // Extension introducer, Application Extension, block size
			'N', 'E', 'T', 'S', 'C', 'A', 'P', 'E', '2', '.', '0', // identifier
			0x03, 0x01, 0x00, 0x00, 0x00, // sub-block: loop count = 0
		})

		r.headerWritten = true
	}

	// Generate one GIF frame
	gw, gh := r.width/4, r.height/4
	if gw < 4 {
		gw = 4
	}
	if gh < 4 {
		gh = 4
	}

	// Pick two colors for this frame
	c1 := color.RGBA{
		R: uint8(r.rng.Intn(256)),
		G: uint8(r.rng.Intn(256)),
		B: uint8(r.rng.Intn(256)),
		A: 255,
	}
	c2 := color.RGBA{
		R: uint8(r.rng.Intn(256)),
		G: uint8(r.rng.Intn(256)),
		B: uint8(r.rng.Intn(256)),
		A: 255,
	}

	// Build a 2-color local palette (for simplicity)
	palette := []color.Color{c1, c2}

	// Graphic Control Extension (delay = 10 * 10ms = 100ms)
	r.buf.Write([]byte{
		0x21, 0xF9, 0x04, // GCE introducer, block size
		0x00,       // packed: no disposal, no user input, no transparent color
		0x0A, 0x00, // delay = 10 (10 * 10ms)
		0x00,       // transparent color index
		0x00,       // block terminator
	})

	// Image Descriptor
	r.buf.WriteByte(0x2C) // image separator
	binary.Write(&r.buf, binary.LittleEndian, uint16(0))   // left
	binary.Write(&r.buf, binary.LittleEndian, uint16(0))   // top
	binary.Write(&r.buf, binary.LittleEndian, uint16(gw))  // width
	binary.Write(&r.buf, binary.LittleEndian, uint16(gh))  // height
	// Packed: Local Color Table Flag=1, Interlace=0, Sort=0, LCT Size=0 (2 colors = 2^(0+1))
	r.buf.WriteByte(0x81) // LCT present, size=1 (2^(1+1)=4 colors, min for LZW)

	// Local Color Table (4 entries x 3 bytes = 12 bytes, we use first 2)
	r.buf.Write([]byte{c1.R, c1.G, c1.B})
	r.buf.Write([]byte{c2.R, c2.G, c2.B})
	r.buf.Write([]byte{0, 0, 0})   // pad to 4 entries
	r.buf.Write([]byte{0, 0, 0})

	// LZW-compressed pixel data using stdlib gif encoder
	// Build pixel indices (alternating checkerboard)
	paletted := image.NewPaletted(image.Rect(0, 0, gw, gh), palette)
	for y := 0; y < gh; y++ {
		for x := 0; x < gw; x++ {
			if (x+y)%2 == 0 {
				paletted.SetColorIndex(x, y, 0)
			} else {
				paletted.SetColorIndex(x, y, 1)
			}
		}
	}

	// Encode just the LZW data via a minimal LZW encoder
	lzwData := encodeLZW(paletted.Pix, 2) // LZW minimum code size = 2
	r.buf.Write(lzwData)

	r.frameCount++

	// Never end (caller caps via maxBytes)
	// But write trailer after many frames to be a valid stream if truncated
	if r.frameCount > 10000 {
		r.buf.WriteByte(0x3B) // GIF trailer
		return io.EOF
	}

	return nil
}

// encodeLZW encodes pixel indices using GIF's LZW algorithm.
// minCodeSize is typically 2 for images with <= 4 colors.
func encodeLZW(pixels []byte, minCodeSize int) []byte {
	// Use Go's image/gif package internally by constructing a minimal image
	// and re-extracting. For streaming purposes, we'll do a simple block.
	// Since we don't have direct access to the LZW encoder, we use a workaround:
	// encode a 1x1 gif and extract its LZW block structure.

	// Build minimal paletted image
	pal := make([]color.Color, 4)
	pal[0] = color.RGBA{0, 0, 0, 255}
	pal[1] = color.RGBA{255, 255, 255, 255}
	pal[2] = color.RGBA{128, 128, 128, 255}
	pal[3] = color.RGBA{64, 64, 64, 255}

	n := len(pixels)
	if n == 0 {
		n = 1
	}
	side := int(math.Sqrt(float64(n)))
	if side < 1 {
		side = 1
	}

	img := image.NewPaletted(image.Rect(0, 0, side, side), pal)
	for i, px := range pixels {
		if i < side*side {
			img.Pix[i] = px & 3 // map to 0-3
		}
	}

	var gifBuf bytes.Buffer
	anim := &gifAnim{
		Image: []*image.Paletted{img},
		Delay: []int{10},
	}
	encodeGIF(&gifBuf, anim)

	// Extract LZW block from the GIF output
	// The LZW data starts after: GIF89a(6) + LSD(7) + GCT(6) + GCE(8) + ImgDesc(10)
	// = 37 bytes header, then LZW min code size (1 byte) + blocks
	gifBytes := gifBuf.Bytes()
	// Find image separator 0x2C
	for i := 0; i+1 < len(gifBytes); i++ {
		if gifBytes[i] == 0x2C {
			// Image descriptor: 10 bytes after 0x2C
			// Check if local color table bit is set
			packed := gifBytes[i+9]
			lctSize := 0
			if packed&0x80 != 0 {
				lctSize = 3 * (1 << ((packed & 0x07) + 1))
			}
			lzwStart := i + 10 + lctSize
			if lzwStart < len(gifBytes) {
				return gifBytes[lzwStart : len(gifBytes)-1] // exclude GIF trailer 0x3B
			}
			break
		}
	}

	// Fallback: return a minimal LZW block
	return []byte{byte(minCodeSize), 0x00} // empty LZW
}

// gifAnim is a minimal wrapper to use gif.EncodeAll.
type gifAnim struct {
	Image []*image.Paletted
	Delay []int
}

// encodeGIF uses the gif package to encode a minimal animation.
func encodeGIF(w *bytes.Buffer, anim *gifAnim) {
	// We can't directly call gif.EncodeAll without import cycle issues,
	// so we re-import here. Since we're in the same package and have gif imported
	// in generator.go, we can use the gif package.
	// This function is a trampoline — the actual call happens in the gif_helper.go
	// file to avoid having to re-import. Since both files are in the same package,
	// we call the package-level helper.
	encodeGIFHelper(w, anim)
}

// generateWAVChunk writes the WAV header on phase 0, then generates PCM chunks.
func (r *InfiniteReader) generateWAVChunk() error {
	const (
		sampleRate    = 44100
		channels      = 1
		bitsPerSample = 16
		chunkSamples  = 4410 // 0.1 second per chunk
	)

	if !r.headerWritten {
		// Write RIFF header with maximum data size
		r.buf.WriteString("RIFF")
		binary.Write(&r.buf, binary.LittleEndian, uint32(0xFFFFFFFF-8)) // max size
		r.buf.WriteString("WAVE")

		// fmt chunk
		r.buf.WriteString("fmt ")
		binary.Write(&r.buf, binary.LittleEndian, uint32(16))
		binary.Write(&r.buf, binary.LittleEndian, uint16(1))  // PCM
		binary.Write(&r.buf, binary.LittleEndian, uint16(channels))
		binary.Write(&r.buf, binary.LittleEndian, uint32(sampleRate))
		binary.Write(&r.buf, binary.LittleEndian, uint32(sampleRate*channels*bitsPerSample/8))
		binary.Write(&r.buf, binary.LittleEndian, uint16(channels*bitsPerSample/8))
		binary.Write(&r.buf, binary.LittleEndian, uint16(bitsPerSample))

		// data chunk header with max size
		r.buf.WriteString("data")
		binary.Write(&r.buf, binary.LittleEndian, uint32(0xFFFFFFFF-44))

		r.headerWritten = true
	}

	// Generate one chunk of PCM sine wave samples
	amplitude := float64(1 << 14)
	for i := 0; i < chunkSamples; i++ {
		t := float64(r.sampleIndex) / float64(sampleRate)
		sample := int16(amplitude * math.Sin(2*math.Pi*r.freq*t))
		binary.Write(&r.buf, binary.LittleEndian, sample)
		r.sampleIndex++
	}

	return nil
}

// generateRandomChunk writes a chunk of random bytes.
func (r *InfiniteReader) generateRandomChunk() error {
	const chunkSize = 4096
	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = byte(r.rng.Intn(256))
	}
	r.buf.Write(chunk)
	return nil
}

// Ensure crc32 is used (writePNGChunk uses it).
var _ = crc32.NewIEEE
