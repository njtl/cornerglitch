package media

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"math"
	"math/rand"
)

// InfiniteReader generates media content as an unbounded stream.
// It implements io.Reader and generates content on-demand.
// Thread-safe: each reader is independent and deterministic from its seed.
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
	freq          float64   // for WAV/audio: primary sine wave frequency
	freq2         float64   // secondary frequency for chords
	freq3         float64   // tertiary frequency for chords
	sampleIndex   int       // for audio: current sample position
	seqNum        int       // for PNG IDAT / GIF frames / general sequence
	width         int
	height        int
	pageSeqNo     uint32    // for OGG page sequencing
	granulePos    uint64    // for OGG granule position
	serialNo      uint32    // for OGG stream serial
	contCounter   uint8     // for MPEG-TS continuity counter
	segmentNum    int       // for HLS/DASH segment numbering
	timecodeMs    uint64    // for WebM/general timecodes
	svgClosed     bool      // for SVG: whether closing tag written
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

	// Pick audio frequencies for chords
	freqs := []float64{220.0, 261.63, 329.63, 392.0, 440.0, 523.25, 659.25, 880.0}
	r.freq = freqs[rng.Intn(len(freqs))]
	r.freq2 = freqs[rng.Intn(len(freqs))]
	r.freq3 = freqs[rng.Intn(len(freqs))]

	// OGG serial number
	r.serialNo = rng.Uint32()

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
	case FormatJPEG:
		return r.generateJPEGChunk()
	case FormatGIF:
		return r.generateGIFChunk()
	case FormatBMP:
		return r.generateBMPChunk()
	case FormatWebP:
		return r.generateWebPChunk()
	case FormatSVG:
		return r.generateSVGChunk()
	case FormatICO:
		return r.generateICOChunk()
	case FormatTIFF:
		return r.generateTIFFChunk()
	case FormatWAV:
		return r.generateWAVChunk()
	case FormatMP3:
		return r.generateMP3Chunk()
	case FormatOGG:
		return r.generateOGGChunk()
	case FormatFLAC:
		return r.generateFLACChunk()
	case FormatMP4:
		return r.generateMP4Chunk()
	case FormatWebM:
		return r.generateWebMChunk()
	case FormatAVI:
		return r.generateAVIChunk()
	case FormatTS:
		return r.generateTSChunk()
	case FormatHLS:
		return r.generateHLSChunk()
	case FormatDASH:
		return r.generateDASHChunk()
	default:
		return r.generateRandomChunk()
	}
}

// ---------------------------------------------------------------------------
// PNG streaming (enhanced)
// ---------------------------------------------------------------------------

// generatePNGChunk generates the PNG header on phase 0, then IDAT chunks
// with varied stripe patterns including gradients and noise.
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

	// Vary stripe height between 8 and 64 rows
	stripeHeight := 8 + r.rng.Intn(57) // 8..64
	img := image.NewRGBA(image.Rect(0, 0, r.width, stripeHeight))

	// Pick a pattern type for this stripe
	patternType := r.rng.Intn(5)
	switch patternType {
	case 0: // solid color with noise
		base := color.RGBA{
			R: uint8(r.rng.Intn(256)),
			G: uint8(r.rng.Intn(256)),
			B: uint8(r.rng.Intn(256)),
			A: 255,
		}
		for y := 0; y < stripeHeight; y++ {
			for x := 0; x < r.width; x++ {
				img.SetRGBA(x, y, color.RGBA{
					R: clampU8(int(base.R) + r.rng.Intn(40) - 20),
					G: clampU8(int(base.G) + r.rng.Intn(40) - 20),
					B: clampU8(int(base.B) + r.rng.Intn(40) - 20),
					A: 255,
				})
			}
		}
	case 1: // horizontal gradient
		c1 := color.RGBA{uint8(r.rng.Intn(256)), uint8(r.rng.Intn(256)), uint8(r.rng.Intn(256)), 255}
		c2 := color.RGBA{uint8(r.rng.Intn(256)), uint8(r.rng.Intn(256)), uint8(r.rng.Intn(256)), 255}
		for y := 0; y < stripeHeight; y++ {
			for x := 0; x < r.width; x++ {
				t := float64(x) / float64(r.width)
				img.SetRGBA(x, y, color.RGBA{
					R: uint8(float64(c1.R)*(1-t) + float64(c2.R)*t),
					G: uint8(float64(c1.G)*(1-t) + float64(c2.G)*t),
					B: uint8(float64(c1.B)*(1-t) + float64(c2.B)*t),
					A: 255,
				})
			}
		}
	case 2: // vertical gradient
		c1 := color.RGBA{uint8(r.rng.Intn(256)), uint8(r.rng.Intn(256)), uint8(r.rng.Intn(256)), 255}
		c2 := color.RGBA{uint8(r.rng.Intn(256)), uint8(r.rng.Intn(256)), uint8(r.rng.Intn(256)), 255}
		for y := 0; y < stripeHeight; y++ {
			t := float64(y) / float64(stripeHeight)
			rc := color.RGBA{
				R: uint8(float64(c1.R)*(1-t) + float64(c2.R)*t),
				G: uint8(float64(c1.G)*(1-t) + float64(c2.G)*t),
				B: uint8(float64(c1.B)*(1-t) + float64(c2.B)*t),
				A: 255,
			}
			for x := 0; x < r.width; x++ {
				img.SetRGBA(x, y, rc)
			}
		}
	case 3: // checkerboard
		c1 := color.RGBA{uint8(r.rng.Intn(256)), uint8(r.rng.Intn(256)), uint8(r.rng.Intn(256)), 255}
		c2 := color.RGBA{uint8(r.rng.Intn(256)), uint8(r.rng.Intn(256)), uint8(r.rng.Intn(256)), 255}
		blockSize := 4 + r.rng.Intn(13) // 4..16
		for y := 0; y < stripeHeight; y++ {
			for x := 0; x < r.width; x++ {
				if ((x/blockSize)+(y/blockSize))%2 == 0 {
					img.SetRGBA(x, y, c1)
				} else {
					img.SetRGBA(x, y, c2)
				}
			}
		}
	case 4: // perlin-like noise (simple)
		for y := 0; y < stripeHeight; y++ {
			for x := 0; x < r.width; x++ {
				v := uint8(r.rng.Intn(256))
				img.SetRGBA(x, y, color.RGBA{R: v, G: v, B: v, A: 255})
			}
		}
	}

	// Encode the stripe as a standalone PNG and extract its IDAT data
	var stripeBuf bytes.Buffer
	if err := png.Encode(&stripeBuf, img); err != nil {
		return err
	}

	stripeBytes := stripeBuf.Bytes()
	idatData := extractPNGIDATData(stripeBytes)

	if len(idatData) > 0 {
		r.writePNGChunk("IDAT", idatData)
	}

	// Occasionally add tEXt metadata chunks between IDAT chunks
	if r.seqNum > 0 && r.rng.Intn(5) == 0 {
		keywords := []string{"Comment", "Author", "Description", "Software", "Source"}
		keyword := keywords[r.rng.Intn(len(keywords))]
		text := fmt.Sprintf("Glitch stream chunk %d", r.seqNum)
		textData := append([]byte(keyword), 0)
		textData = append(textData, []byte(text)...)
		r.writePNGChunk("tEXt", textData)
	}

	r.seqNum++

	if r.seqNum > 10000 {
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

// ---------------------------------------------------------------------------
// JPEG streaming
// ---------------------------------------------------------------------------

// generateJPEGChunk generates JPEG data by encoding small tiles.
// Phase 0: encode a full JPEG header with quantization tables.
// Subsequent phases: encode additional tiles and emit the scan data.
func (r *InfiniteReader) generateJPEGChunk() error {
	// Each call encodes a small tile as a full JPEG, and on phase 0 we emit
	// the whole thing; on subsequent phases we extract and emit scan data
	// appended after a new SOS marker.
	tileH := 16
	tileW := r.width
	if tileW > 320 {
		tileW = 320
	}

	img := image.NewRGBA(image.Rect(0, 0, tileW, tileH))

	// Generate tile pixels with varied patterns
	baseR := uint8(r.rng.Intn(256))
	baseG := uint8(r.rng.Intn(256))
	baseB := uint8(r.rng.Intn(256))
	patType := r.rng.Intn(3)

	for y := 0; y < tileH; y++ {
		for x := 0; x < tileW; x++ {
			var cr, cg, cb uint8
			switch patType {
			case 0: // gradient
				t := float64(x) / float64(tileW)
				cr = uint8(float64(baseR) * t)
				cg = uint8(float64(baseG) * (1 - t))
				cb = baseB
			case 1: // noise
				cr = clampU8(int(baseR) + r.rng.Intn(60) - 30)
				cg = clampU8(int(baseG) + r.rng.Intn(60) - 30)
				cb = clampU8(int(baseB) + r.rng.Intn(60) - 30)
			default: // stripes
				if (y/4)%2 == 0 {
					cr, cg, cb = baseR, baseG, baseB
				} else {
					cr, cg, cb = 255-baseR, 255-baseG, 255-baseB
				}
			}
			img.SetRGBA(x, y, color.RGBA{R: cr, G: cg, B: cb, A: 255})
		}
	}

	var tileBuf bytes.Buffer
	quality := 50 + r.rng.Intn(40) // 50..89
	if err := jpeg.Encode(&tileBuf, img, &jpeg.Options{Quality: quality}); err != nil {
		return err
	}

	if !r.headerWritten {
		// First chunk: emit the complete JPEG (without EOI so we can append)
		data := tileBuf.Bytes()
		// Strip the trailing EOI marker (FF D9) so more scans can follow
		if len(data) >= 2 && data[len(data)-2] == 0xFF && data[len(data)-1] == 0xD9 {
			r.buf.Write(data[:len(data)-2])
		} else {
			r.buf.Write(data)
		}
		r.headerWritten = true
	} else {
		// Subsequent chunks: extract the compressed scan data (after SOS marker)
		// and emit it as additional entropy-coded data with a restart marker
		data := tileBuf.Bytes()
		sosIdx := findJPEGSOS(data)
		if sosIdx >= 0 {
			// Write a restart marker (RST0-RST7)
			rstMarker := 0xD0 + (r.seqNum % 8)
			r.buf.Write([]byte{0xFF, byte(rstMarker)})
			// Write the scan data (after SOS header to before EOI)
			scanStart := sosIdx
			scanEnd := len(data)
			if scanEnd >= 2 && data[scanEnd-2] == 0xFF && data[scanEnd-1] == 0xD9 {
				scanEnd -= 2
			}
			// Skip the SOS marker and header to get raw entropy data
			// SOS: FF DA, length(2), components..., then scan data
			if scanStart+2 < len(data) {
				sosLen := int(binary.BigEndian.Uint16(data[scanStart+2 : scanStart+4]))
				rawStart := scanStart + 2 + sosLen
				if rawStart < scanEnd {
					r.buf.Write(data[rawStart:scanEnd])
				}
			}
		}
	}

	r.seqNum++

	if r.seqNum > 10000 {
		// Write EOI marker to finalize
		r.buf.Write([]byte{0xFF, 0xD9})
		return io.EOF
	}

	return nil
}

// findJPEGSOS finds the position of the SOS (Start of Scan) marker FF DA.
func findJPEGSOS(data []byte) int {
	for i := 0; i+1 < len(data); i++ {
		if data[i] == 0xFF && data[i+1] == 0xDA {
			return i
		}
	}
	return -1
}

// ---------------------------------------------------------------------------
// GIF streaming (enhanced)
// ---------------------------------------------------------------------------

// generateGIFChunk writes the GIF header on phase 0, then keeps generating frames
// with varied sizes, positions, delay times, and disposal methods.
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

	// Vary frame dimensions: sub-frame animation (1/4 to full canvas)
	minW := r.width / 4
	minH := r.height / 4
	if minW < 4 {
		minW = 4
	}
	if minH < 4 {
		minH = 4
	}
	gw := minW + r.rng.Intn(r.width-minW+1)
	gh := minH + r.rng.Intn(r.height-minH+1)

	// Random position within canvas
	left := 0
	top := 0
	if r.width-gw > 0 {
		left = r.rng.Intn(r.width - gw)
	}
	if r.height-gh > 0 {
		top = r.rng.Intn(r.height - gh)
	}

	// Pick colors for this frame
	numColors := 2 + r.rng.Intn(3) // 2..4
	colors := make([]color.RGBA, numColors)
	for i := range colors {
		colors[i] = color.RGBA{
			R: uint8(r.rng.Intn(256)),
			G: uint8(r.rng.Intn(256)),
			B: uint8(r.rng.Intn(256)),
			A: 255,
		}
	}

	// Build palette padded to power of 2 (min 4 for LZW)
	palSize := 4
	for palSize < numColors {
		palSize *= 2
	}
	palette := make([]color.Color, palSize)
	for i := 0; i < palSize; i++ {
		if i < numColors {
			palette[i] = colors[i]
		} else {
			palette[i] = color.RGBA{0, 0, 0, 255}
		}
	}

	// lctBits: size of LCT = 2^(n+1), so n = log2(palSize)-1
	lctBits := 0
	for (1 << (lctBits + 1)) < palSize {
		lctBits++
	}

	// Varied delay time: 2..50 centiseconds (20ms to 500ms)
	delay := uint16(2 + r.rng.Intn(49))

	// Disposal method: 0=unspecified, 1=do not dispose, 2=restore to bg, 3=restore to previous
	disposal := uint8(r.rng.Intn(4))

	// Graphic Control Extension
	r.buf.Write([]byte{
		0x21, 0xF9, 0x04,
		(disposal << 2),
		byte(delay), byte(delay >> 8),
		0x00,
		0x00,
	})

	// Image Descriptor
	r.buf.WriteByte(0x2C)
	binary.Write(&r.buf, binary.LittleEndian, uint16(left))
	binary.Write(&r.buf, binary.LittleEndian, uint16(top))
	binary.Write(&r.buf, binary.LittleEndian, uint16(gw))
	binary.Write(&r.buf, binary.LittleEndian, uint16(gh))
	// Packed: Local Color Table Flag=1, Interlace=0, Sort=0, LCT Size=lctBits
	r.buf.WriteByte(0x80 | byte(lctBits))

	// Local Color Table
	for i := 0; i < palSize; i++ {
		c := palette[i].(color.RGBA)
		r.buf.Write([]byte{c.R, c.G, c.B})
	}

	// LZW-compressed pixel data
	// Build pixel indices with varied patterns
	paletted := image.NewPaletted(image.Rect(0, 0, gw, gh), palette)
	patType := r.rng.Intn(4)
	for y := 0; y < gh; y++ {
		for x := 0; x < gw; x++ {
			var idx uint8
			switch patType {
			case 0: // checkerboard
				if (x+y)%2 == 0 {
					idx = 0
				} else {
					idx = 1
				}
			case 1: // horizontal stripes
				idx = uint8(y % numColors)
			case 2: // vertical stripes
				idx = uint8(x % numColors)
			case 3: // random
				idx = uint8(r.rng.Intn(numColors))
			}
			paletted.SetColorIndex(x, y, idx)
		}
	}

	// Encode LZW data using the gif helper approach
	minCodeSize := lctBits + 1
	if minCodeSize < 2 {
		minCodeSize = 2
	}
	lzwData := encodeLZW(paletted.Pix, minCodeSize)
	r.buf.Write(lzwData)

	r.frameCount++

	if r.frameCount > 10000 {
		r.buf.WriteByte(0x3B) // GIF trailer
		return io.EOF
	}

	return nil
}

// encodeLZW encodes pixel indices using GIF's LZW algorithm.
func encodeLZW(pixels []byte, minCodeSize int) []byte {
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
			img.Pix[i] = px & 3
		}
	}

	var gifBuf bytes.Buffer
	anim := &gifAnim{
		Image: []*image.Paletted{img},
		Delay: []int{10},
	}
	encodeGIF(&gifBuf, anim)

	gifBytes := gifBuf.Bytes()
	for i := 0; i+1 < len(gifBytes); i++ {
		if gifBytes[i] == 0x2C {
			packed := gifBytes[i+9]
			lctSize := 0
			if packed&0x80 != 0 {
				lctSize = 3 * (1 << ((packed & 0x07) + 1))
			}
			lzwStart := i + 10 + lctSize
			if lzwStart < len(gifBytes) {
				return gifBytes[lzwStart : len(gifBytes)-1]
			}
			break
		}
	}

	return []byte{byte(minCodeSize), 0x00}
}

// gifAnim is a minimal wrapper to use gif.EncodeAll.
type gifAnim struct {
	Image []*image.Paletted
	Delay []int
}

// encodeGIF uses the gif package to encode a minimal animation.
func encodeGIF(w *bytes.Buffer, anim *gifAnim) {
	encodeGIFHelper(w, anim)
}

// ---------------------------------------------------------------------------
// WAV streaming (enhanced: stereo, chords, envelope)
// ---------------------------------------------------------------------------

// generateWAVChunk writes the WAV header on phase 0, then generates PCM chunks
// with stereo output, chord generation, and fade in/out envelope.
func (r *InfiniteReader) generateWAVChunk() error {
	const (
		sampleRate    = 44100
		channels      = 2 // stereo
		bitsPerSample = 16
		chunkSamples  = 4410 // 0.1 second per chunk
	)

	if !r.headerWritten {
		// Write RIFF header with maximum data size
		r.buf.WriteString("RIFF")
		binary.Write(&r.buf, binary.LittleEndian, uint32(0xFFFFFFFF-8))
		r.buf.WriteString("WAVE")

		// fmt chunk
		r.buf.WriteString("fmt ")
		binary.Write(&r.buf, binary.LittleEndian, uint32(16))
		binary.Write(&r.buf, binary.LittleEndian, uint16(1)) // PCM
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

	// Generate one chunk of stereo PCM sine wave samples with chord and envelope
	amplitude := float64(1 << 13) // reduced for chord headroom
	// Vary chunk size between 2205 and 8820 samples (50ms to 200ms)
	actualSamples := chunkSamples + r.rng.Intn(4411) - 2205

	for i := 0; i < actualSamples; i++ {
		t := float64(r.sampleIndex) / float64(sampleRate)

		// Chord: sum of three frequencies
		s1 := math.Sin(2 * math.Pi * r.freq * t)
		s2 := 0.6 * math.Sin(2*math.Pi*r.freq2*t)
		s3 := 0.3 * math.Sin(2*math.Pi*r.freq3*t)
		raw := s1 + s2 + s3

		// Envelope: fade in for first 4410 samples, periodic fade in/out every ~2 seconds
		envelope := 1.0
		if r.sampleIndex < 4410 {
			envelope = float64(r.sampleIndex) / 4410.0
		}
		cyclePos := r.sampleIndex % (sampleRate * 2) // 2-second cycle
		if cyclePos > sampleRate*2-4410 {
			// Fade out in last 0.1s of cycle
			remaining := float64(sampleRate*2-cyclePos) / 4410.0
			envelope *= remaining
		}

		sampleVal := int16(amplitude * raw * envelope)

		// Left channel: full signal
		binary.Write(&r.buf, binary.LittleEndian, sampleVal)
		// Right channel: slightly phase-shifted
		tR := float64(r.sampleIndex+100) / float64(sampleRate)
		rawR := math.Sin(2*math.Pi*r.freq*tR) + 0.6*math.Sin(2*math.Pi*r.freq2*tR) + 0.3*math.Sin(2*math.Pi*r.freq3*tR)
		sampleR := int16(amplitude * rawR * envelope)
		binary.Write(&r.buf, binary.LittleEndian, sampleR)

		r.sampleIndex++
	}

	return nil
}

// ---------------------------------------------------------------------------
// MP3 streaming
// ---------------------------------------------------------------------------

// generateMP3Chunk generates MP3 frames with ID3v2 header on phase 0.
func (r *InfiniteReader) generateMP3Chunk() error {
	if !r.headerWritten {
		// ID3v2 tag header (10 bytes)
		r.buf.WriteString("ID3")
		r.buf.Write([]byte{
			0x03, 0x00, // version 2.3
			0x00,       // flags
		})
		// Write a TIT2 frame inside the tag
		title := "Glitch Infinite Stream"
		// TIT2 frame: 10-byte frame header + encoding byte + text
		frameDataLen := 1 + len(title) // encoding byte + text
		tagSize := 10 + frameDataLen   // TIT2 frame header + data
		// ID3 size uses syncsafe integers (7 bits per byte)
		r.buf.Write(encodeSyncsafe(uint32(tagSize)))
		// TIT2 frame
		r.buf.WriteString("TIT2")
		binary.Write(&r.buf, binary.BigEndian, uint32(frameDataLen))
		r.buf.Write([]byte{0x00, 0x00}) // flags
		r.buf.WriteByte(0x00)           // ISO-8859-1 encoding
		r.buf.WriteString(title)

		r.headerWritten = true
	}

	// Generate 10-50 MPEG audio frames per call
	numFrames := 10 + r.rng.Intn(41)

	for f := 0; f < numFrames; f++ {
		// MPEG1, Layer 3, 128kbps, 44100Hz, stereo
		// Frame header: 4 bytes
		// Sync: 0xFFE (11 bits)
		// MPEG version: 11 (MPEG1) = bits 19-20
		// Layer: 01 (Layer III) = bits 17-18
		// Protection: 1 (no CRC) = bit 16
		// Bitrate index: 1001 (128kbps for MPEG1 Layer3) = bits 15-12
		// Sample rate: 00 (44100Hz for MPEG1) = bits 11-10
		// Padding: varies = bit 9
		// Private: 0 = bit 8
		// Channel mode: 00 (stereo) = bits 7-6
		// Mode ext: 00 = bits 5-4
		// Copyright: 0 = bit 3
		// Original: 1 = bit 2
		// Emphasis: 00 = bits 1-0

		padding := r.seqNum % 2 // alternate padding for 417/418 byte frames

		// Build header: FF FB 90 00 or FF FB 92 00 (with padding)
		header := [4]byte{0xFF, 0xFB, 0x90, 0x04}
		if padding == 1 {
			header[2] = 0x92 // set padding bit
		}
		r.buf.Write(header[:])

		// Frame size = floor(144 * bitrate / sampleRate) + padding
		// = floor(144 * 128000 / 44100) + padding = 417 + padding
		frameDataSize := 417 + padding - 4 // minus header
		if frameDataSize < 0 {
			frameDataSize = 413
		}

		// Fill frame with sine wave encoded as simple byte patterns
		t := float64(r.sampleIndex) / 44100.0
		for i := 0; i < frameDataSize; i++ {
			// Create audio-like byte patterns (not valid MP3 compression,
			// but fills the frame with deterministic data that avoids
			// false sync words)
			val := math.Sin(2*math.Pi*r.freq*t + float64(i)*0.01)
			b := byte(int(128) + int(val*100))
			// Avoid 0xFF which could be mistaken for sync
			if b == 0xFF {
				b = 0xFE
			}
			r.buf.WriteByte(b)
		}

		r.sampleIndex += 1152 // MPEG1 Layer3 samples per frame
		r.seqNum++
	}

	return nil
}

// encodeSyncsafe encodes a uint32 as a 4-byte syncsafe integer (ID3v2).
func encodeSyncsafe(n uint32) []byte {
	return []byte{
		byte((n >> 21) & 0x7F),
		byte((n >> 14) & 0x7F),
		byte((n >> 7) & 0x7F),
		byte(n & 0x7F),
	}
}

// ---------------------------------------------------------------------------
// OGG streaming
// ---------------------------------------------------------------------------

// generateOGGChunk generates OGG/Vorbis stream with proper page structure.
func (r *InfiniteReader) generateOGGChunk() error {
	switch r.phase {
	case 0:
		// BOS page with Vorbis identification header
		vorbisID := r.buildVorbisIdentHeader()
		r.writeOGGPage(0x02, vorbisID) // BOS flag
		r.phase = 1
	case 1:
		// Vorbis comment header page
		comment := r.buildVorbisCommentHeader()
		r.writeOGGPage(0x00, comment)
		r.phase = 2
	default:
		// Audio data pages
		// Generate a page of pseudo-audio data (1-8 segments of 255 bytes max)
		numSegments := 1 + r.rng.Intn(8)
		var audioData []byte
		for s := 0; s < numSegments; s++ {
			segSize := 64 + r.rng.Intn(192) // 64..255
			seg := make([]byte, segSize)
			t := float64(r.sampleIndex) / 44100.0
			for i := range seg {
				val := math.Sin(2*math.Pi*r.freq*t + float64(i)*0.02)
				seg[i] = byte(int(128) + int(val*100))
			}
			audioData = append(audioData, seg...)
			r.sampleIndex += segSize
		}
		r.granulePos += uint64(numSegments * 256)
		r.writeOGGPage(0x00, audioData)
	}

	return nil
}

// buildVorbisIdentHeader builds a minimal Vorbis identification header.
func (r *InfiniteReader) buildVorbisIdentHeader() []byte {
	var buf bytes.Buffer
	buf.WriteByte(0x01) // packet type: identification
	buf.WriteString("vorbis")
	binary.Write(&buf, binary.LittleEndian, uint32(0))     // version
	buf.WriteByte(2)                                         // channels
	binary.Write(&buf, binary.LittleEndian, uint32(44100))  // sample rate
	binary.Write(&buf, binary.LittleEndian, uint32(0))      // bitrate max
	binary.Write(&buf, binary.LittleEndian, uint32(128000)) // bitrate nominal
	binary.Write(&buf, binary.LittleEndian, uint32(0))      // bitrate min
	buf.WriteByte(0xB8)                                      // blocksize 0=256, 1=2048 (encoded as 4bits each)
	buf.WriteByte(0x01)                                      // framing flag
	return buf.Bytes()
}

// buildVorbisCommentHeader builds a minimal Vorbis comment header.
func (r *InfiniteReader) buildVorbisCommentHeader() []byte {
	var buf bytes.Buffer
	buf.WriteByte(0x03) // packet type: comment
	buf.WriteString("vorbis")
	vendor := "Glitch/1.0"
	binary.Write(&buf, binary.LittleEndian, uint32(len(vendor)))
	buf.WriteString(vendor)
	binary.Write(&buf, binary.LittleEndian, uint32(1)) // 1 comment
	comment := "TITLE=Infinite Glitch Stream"
	binary.Write(&buf, binary.LittleEndian, uint32(len(comment)))
	buf.WriteString(comment)
	buf.WriteByte(0x01) // framing flag
	return buf.Bytes()
}

// writeOGGPage writes a complete OGG page to the buffer.
func (r *InfiniteReader) writeOGGPage(headerType byte, payload []byte) {
	// Segment table: divide payload into segments of up to 255 bytes
	numSegments := len(payload) / 255
	lastSeg := len(payload) % 255
	if lastSeg > 0 || numSegments == 0 {
		numSegments++
	}
	if numSegments > 255 {
		numSegments = 255
		payload = payload[:255*255]
	}

	segTable := make([]byte, numSegments)
	remaining := len(payload)
	for i := 0; i < numSegments; i++ {
		if remaining >= 255 {
			segTable[i] = 255
			remaining -= 255
		} else {
			segTable[i] = byte(remaining)
			remaining = 0
		}
	}

	// Build page header (27 bytes + segment table)
	var page bytes.Buffer
	page.WriteString("OggS")                                              // capture pattern
	page.WriteByte(0)                                                     // stream structure version
	page.WriteByte(headerType)                                            // header type flags
	binary.Write(&page, binary.LittleEndian, r.granulePos)               // granule position
	binary.Write(&page, binary.LittleEndian, r.serialNo)                 // stream serial
	binary.Write(&page, binary.LittleEndian, r.pageSeqNo)                // page sequence number
	binary.Write(&page, binary.LittleEndian, uint32(0))                  // CRC placeholder (offset 22)
	page.WriteByte(byte(numSegments))                                     // number of page segments
	page.Write(segTable)
	page.Write(payload)

	// Calculate CRC over entire page
	pageBytes := page.Bytes()
	crc := oggCRC(pageBytes)
	binary.LittleEndian.PutUint32(pageBytes[22:26], crc)

	r.buf.Write(pageBytes)
	r.pageSeqNo++
}

// oggCRC computes the OGG CRC-32 checksum.
func oggCRC(data []byte) uint32 {
	// OGG uses a custom CRC-32 polynomial: 0x04C11DB7 (no reflect)
	var crc uint32
	for _, b := range data {
		crc ^= uint32(b) << 24
		for i := 0; i < 8; i++ {
			if crc&0x80000000 != 0 {
				crc = (crc << 1) ^ 0x04C11DB7
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// ---------------------------------------------------------------------------
// FLAC streaming
// ---------------------------------------------------------------------------

// generateFLACChunk generates FLAC stream with metadata and audio frames.
func (r *InfiniteReader) generateFLACChunk() error {
	switch r.phase {
	case 0:
		// Write "fLaC" magic + STREAMINFO metadata block
		r.buf.WriteString("fLaC")

		// STREAMINFO metadata block header
		// bit 0: not last metadata block (0), bits 1-7: type 0 (STREAMINFO)
		r.buf.WriteByte(0x00)
		// Block size: 34 bytes for STREAMINFO
		r.buf.Write([]byte{0x00, 0x00, 0x22})

		// STREAMINFO block (34 bytes)
		var info bytes.Buffer
		binary.Write(&info, binary.BigEndian, uint16(4096)) // min block size
		binary.Write(&info, binary.BigEndian, uint16(4096)) // max block size
		// min/max frame size (3 bytes each, 0 = unknown)
		info.Write([]byte{0x00, 0x00, 0x00}) // min frame size
		info.Write([]byte{0x00, 0x00, 0x00}) // max frame size
		// Sample rate (20 bits) + channels-1 (3 bits) + bits per sample-1 (5 bits) + total samples (36 bits)
		// 44100 Hz, 2 channels, 16 bits per sample, 0 total samples (streaming)
		// 44100 = 0xAC44
		// Packed: SSSSSSSS SSSSSSSS SSSSCCCC BBBBBTTT TTTTTTTT TTTTTTTT TTTTTTTT TTTTTTTT
		sampleRate := uint32(44100)
		channels := uint8(2)
		bps := uint8(16)
		b0 := byte(sampleRate >> 12)
		b1 := byte((sampleRate >> 4) & 0xFF)
		b2 := byte(((sampleRate & 0x0F) << 4) | (uint32(channels-1) << 1) | (uint32(bps-1) >> 4))
		b3 := byte(((bps - 1) & 0x0F) << 4) // total samples high bits = 0
		info.Write([]byte{b0, b1, b2, b3})
		info.Write([]byte{0x00, 0x00, 0x00, 0x00}) // total samples low 32 bits
		// MD5 signature (16 bytes, all zeros for streaming)
		info.Write(make([]byte, 16))

		r.buf.Write(info.Bytes())
		r.phase = 1

	case 1:
		// VORBIS_COMMENT metadata block (last metadata block)
		var comment bytes.Buffer
		vendor := "Glitch/1.0"
		binary.Write(&comment, binary.LittleEndian, uint32(len(vendor)))
		comment.WriteString(vendor)
		binary.Write(&comment, binary.LittleEndian, uint32(1))
		userComment := "TITLE=Infinite Glitch Stream"
		binary.Write(&comment, binary.LittleEndian, uint32(len(userComment)))
		comment.WriteString(userComment)

		commentData := comment.Bytes()
		// Last metadata block flag (0x80) | type 4 (VORBIS_COMMENT)
		r.buf.WriteByte(0x84)
		// Block length (3 bytes big-endian)
		r.buf.WriteByte(byte(len(commentData) >> 16))
		r.buf.WriteByte(byte(len(commentData) >> 8))
		r.buf.WriteByte(byte(len(commentData)))
		r.buf.Write(commentData)
		r.phase = 2

	default:
		// Generate audio frame data
		// FLAC frame header
		var frame bytes.Buffer

		// Sync code: 0xFFF8 (14 bits sync + 1 bit reserved + 1 bit blocking strategy=fixed)
		frame.Write([]byte{0xFF, 0xF8})

		// Block size (4 bits) + sample rate (4 bits)
		// Block size: 1100 = 4096 samples from header
		// Sample rate: 1001 = 44100 Hz from header
		frame.WriteByte(0xC9)

		// Channel assignment (4 bits) + sample size (3 bits) + reserved (1 bit)
		// Channels: 0001 = 2 channels (left/right)
		// Sample size: 100 = 16 bits per sample from header
		frame.WriteByte(0x18)

		// Frame number (UTF-8 coded, variable length) - use seqNum
		frame.Write(encodeUTF8Frame(uint64(r.seqNum)))

		// CRC-8 of frame header
		headerBytes := frame.Bytes()
		frame.WriteByte(flacCRC8(headerBytes))

		// Subframe data: simplified constant/verbatim data
		// Generate 4096 samples worth of audio-like data
		blockSize := 4096
		for ch := 0; ch < 2; ch++ {
			// Subframe header: 0 (padding) + type (1=verbatim for simplicity) + wasted bits flag
			frame.WriteByte(0x02) // verbatim subframe type

			for s := 0; s < blockSize; s++ {
				t := float64(r.sampleIndex+s) / 44100.0
				val := math.Sin(2*math.Pi*r.freq*t) * 16000
				sample := int16(val)
				binary.Write(&frame, binary.BigEndian, sample)
			}
		}
		r.sampleIndex += blockSize

		// Frame footer: CRC-16
		frameBytes := frame.Bytes()
		crc16 := flacCRC16(frameBytes)
		binary.Write(&frame, binary.BigEndian, crc16)

		r.buf.Write(frame.Bytes())
		r.seqNum++
	}

	return nil
}

// encodeUTF8Frame encodes a frame number in FLAC's UTF-8-like coding.
func encodeUTF8Frame(n uint64) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	} else if n < 0x800 {
		return []byte{
			byte(0xC0 | (n >> 6)),
			byte(0x80 | (n & 0x3F)),
		}
	} else if n < 0x10000 {
		return []byte{
			byte(0xE0 | (n >> 12)),
			byte(0x80 | ((n >> 6) & 0x3F)),
			byte(0x80 | (n & 0x3F)),
		}
	} else if n < 0x200000 {
		return []byte{
			byte(0xF0 | (n >> 18)),
			byte(0x80 | ((n >> 12) & 0x3F)),
			byte(0x80 | ((n >> 6) & 0x3F)),
			byte(0x80 | (n & 0x3F)),
		}
	}
	// For very large frame numbers, use 5 bytes
	return []byte{
		byte(0xF8 | (n >> 24)),
		byte(0x80 | ((n >> 18) & 0x3F)),
		byte(0x80 | ((n >> 12) & 0x3F)),
		byte(0x80 | ((n >> 6) & 0x3F)),
		byte(0x80 | (n & 0x3F)),
	}
}

// flacCRC8 computes FLAC CRC-8 (polynomial 0x07).
func flacCRC8(data []byte) byte {
	var crc byte
	for _, b := range data {
		crc ^= b
		for i := 0; i < 8; i++ {
			if crc&0x80 != 0 {
				crc = (crc << 1) ^ 0x07
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// flacCRC16 computes FLAC CRC-16 (polynomial 0x8005).
func flacCRC16(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x8005
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// ---------------------------------------------------------------------------
// MP4 streaming (fragmented MP4 / fMP4)
// ---------------------------------------------------------------------------

// generateMP4Chunk generates fragmented MP4 with ftyp/moov on phase 0,
// then moof+mdat pairs for streaming.
func (r *InfiniteReader) generateMP4Chunk() error {
	switch r.phase {
	case 0:
		// ftyp box
		r.writeMP4Box("ftyp", func(buf *bytes.Buffer) {
			buf.WriteString("isom")                     // major brand
			binary.Write(buf, binary.BigEndian, uint32(0x200)) // minor version
			buf.WriteString("isomiso2mp41")              // compatible brands
		})

		// moov box (minimal movie header for fMP4)
		r.writeMP4Box("moov", func(buf *bytes.Buffer) {
			// mvhd box
			r.writeMP4SubBox(buf, "mvhd", func(inner *bytes.Buffer) {
				inner.Write([]byte{0x00, 0x00, 0x00, 0x00}) // version + flags
				binary.Write(inner, binary.BigEndian, uint32(0)) // creation time
				binary.Write(inner, binary.BigEndian, uint32(0)) // modification time
				binary.Write(inner, binary.BigEndian, uint32(1000)) // timescale
				binary.Write(inner, binary.BigEndian, uint32(0))   // duration (unknown for streaming)
				binary.Write(inner, binary.BigEndian, uint32(0x00010000)) // rate (1.0)
				binary.Write(inner, binary.BigEndian, uint16(0x0100))    // volume (1.0)
				inner.Write(make([]byte, 10))  // reserved
				// Unity matrix (9 uint32)
				for _, v := range []uint32{0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000} {
					binary.Write(inner, binary.BigEndian, v)
				}
				inner.Write(make([]byte, 24)) // pre-defined
				binary.Write(inner, binary.BigEndian, uint32(2)) // next track ID
			})

			// trak box with minimal track
			r.writeMP4SubBox(buf, "trak", func(trak *bytes.Buffer) {
				// tkhd
				r.writeMP4SubBox(trak, "tkhd", func(tkhd *bytes.Buffer) {
					tkhd.Write([]byte{0x00, 0x00, 0x00, 0x03}) // version=0, flags=enabled+in_movie
					binary.Write(tkhd, binary.BigEndian, uint32(0)) // creation
					binary.Write(tkhd, binary.BigEndian, uint32(0)) // modification
					binary.Write(tkhd, binary.BigEndian, uint32(1)) // track ID
					binary.Write(tkhd, binary.BigEndian, uint32(0)) // reserved
					binary.Write(tkhd, binary.BigEndian, uint32(0)) // duration
					tkhd.Write(make([]byte, 8))  // reserved
					binary.Write(tkhd, binary.BigEndian, uint16(0))     // layer
					binary.Write(tkhd, binary.BigEndian, uint16(0))     // alternate group
					binary.Write(tkhd, binary.BigEndian, uint16(0))     // volume
					binary.Write(tkhd, binary.BigEndian, uint16(0))     // reserved
					for _, v := range []uint32{0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000} {
						binary.Write(tkhd, binary.BigEndian, v)
					}
					binary.Write(tkhd, binary.BigEndian, uint32(r.width)<<16)  // width
					binary.Write(tkhd, binary.BigEndian, uint32(r.height)<<16) // height
				})

				// mdia box
				r.writeMP4SubBox(trak, "mdia", func(mdia *bytes.Buffer) {
					// mdhd
					r.writeMP4SubBox(mdia, "mdhd", func(mdhd *bytes.Buffer) {
						mdhd.Write([]byte{0x00, 0x00, 0x00, 0x00})
						binary.Write(mdhd, binary.BigEndian, uint32(0))
						binary.Write(mdhd, binary.BigEndian, uint32(0))
						binary.Write(mdhd, binary.BigEndian, uint32(90000)) // timescale
						binary.Write(mdhd, binary.BigEndian, uint32(0))     // duration
						binary.Write(mdhd, binary.BigEndian, uint16(0x55C4)) // language: und
						binary.Write(mdhd, binary.BigEndian, uint16(0))
					})
					// hdlr
					r.writeMP4SubBox(mdia, "hdlr", func(hdlr *bytes.Buffer) {
						hdlr.Write([]byte{0x00, 0x00, 0x00, 0x00})
						binary.Write(hdlr, binary.BigEndian, uint32(0))
						hdlr.WriteString("vide") // handler type
						hdlr.Write(make([]byte, 12))
						hdlr.WriteString("Glitch Video\x00")
					})
					// minf (minimal)
					r.writeMP4SubBox(mdia, "minf", func(minf *bytes.Buffer) {
						// vmhd
						r.writeMP4SubBox(minf, "vmhd", func(vmhd *bytes.Buffer) {
							vmhd.Write([]byte{0x00, 0x00, 0x00, 0x01})
							vmhd.Write(make([]byte, 8))
						})
						// dinf + dref
						r.writeMP4SubBox(minf, "dinf", func(dinf *bytes.Buffer) {
							r.writeMP4SubBox(dinf, "dref", func(dref *bytes.Buffer) {
								dref.Write([]byte{0x00, 0x00, 0x00, 0x00})
								binary.Write(dref, binary.BigEndian, uint32(1))
								r.writeMP4SubBox(dref, "url ", func(url *bytes.Buffer) {
									url.Write([]byte{0x00, 0x00, 0x00, 0x01}) // self-contained
								})
							})
						})
						// stbl with empty tables (required for fMP4)
						r.writeMP4SubBox(minf, "stbl", func(stbl *bytes.Buffer) {
							r.writeMP4SubBox(stbl, "stsd", func(stsd *bytes.Buffer) {
								stsd.Write([]byte{0x00, 0x00, 0x00, 0x00})
								binary.Write(stsd, binary.BigEndian, uint32(0))
							})
							for _, boxType := range []string{"stts", "stsc", "stsz", "stco"} {
								r.writeMP4SubBox(stbl, boxType, func(inner *bytes.Buffer) {
									inner.Write([]byte{0x00, 0x00, 0x00, 0x00})
									binary.Write(inner, binary.BigEndian, uint32(0))
								})
							}
						})
					})
				})
			})

			// mvex box (movie extends for fragmented mp4)
			r.writeMP4SubBox(buf, "mvex", func(mvex *bytes.Buffer) {
				r.writeMP4SubBox(mvex, "trex", func(trex *bytes.Buffer) {
					trex.Write([]byte{0x00, 0x00, 0x00, 0x00})
					binary.Write(trex, binary.BigEndian, uint32(1)) // track ID
					binary.Write(trex, binary.BigEndian, uint32(1)) // default sample description index
					binary.Write(trex, binary.BigEndian, uint32(0)) // default sample duration
					binary.Write(trex, binary.BigEndian, uint32(0)) // default sample size
					binary.Write(trex, binary.BigEndian, uint32(0)) // default sample flags
				})
			})
		})

		r.phase = 1

	default:
		// Generate moof + mdat pairs (fragmented streaming)
		fragDuration := uint32(3000) // ~33ms at 90000 timescale
		frameSize := 1024 + r.rng.Intn(3072) // 1KB-4KB per frame

		// moof box
		r.writeMP4Box("moof", func(buf *bytes.Buffer) {
			// mfhd
			r.writeMP4SubBox(buf, "mfhd", func(mfhd *bytes.Buffer) {
				mfhd.Write([]byte{0x00, 0x00, 0x00, 0x00})
				binary.Write(mfhd, binary.BigEndian, uint32(r.seqNum+1)) // sequence number (1-based)
			})
			// traf
			r.writeMP4SubBox(buf, "traf", func(traf *bytes.Buffer) {
				// tfhd
				r.writeMP4SubBox(traf, "tfhd", func(tfhd *bytes.Buffer) {
					tfhd.Write([]byte{0x00, 0x02, 0x00, 0x20}) // default-base-is-moof + default-sample-duration-present
					binary.Write(tfhd, binary.BigEndian, uint32(1))            // track ID
					binary.Write(tfhd, binary.BigEndian, fragDuration)         // default sample duration
				})
				// tfdt (track fragment decode time)
				r.writeMP4SubBox(traf, "tfdt", func(tfdt *bytes.Buffer) {
					tfdt.Write([]byte{0x01, 0x00, 0x00, 0x00}) // version 1
					binary.Write(tfdt, binary.BigEndian, r.timecodeMs)
				})
				// trun
				r.writeMP4SubBox(traf, "trun", func(trun *bytes.Buffer) {
					trun.Write([]byte{0x00, 0x00, 0x02, 0x01}) // data-offset + sample-size present
					binary.Write(trun, binary.BigEndian, uint32(1)) // sample count
					binary.Write(trun, binary.BigEndian, uint32(0)) // data offset (placeholder)
					binary.Write(trun, binary.BigEndian, uint32(frameSize))
				})
			})
		})

		// mdat box with frame data
		r.writeMP4Box("mdat", func(buf *bytes.Buffer) {
			frame := make([]byte, frameSize)
			for i := range frame {
				frame[i] = byte(r.rng.Intn(256))
			}
			buf.Write(frame)
		})

		r.timecodeMs += uint64(fragDuration)
		r.seqNum++
	}

	return nil
}

// writeMP4Box writes a top-level MP4 box to r.buf.
func (r *InfiniteReader) writeMP4Box(boxType string, fill func(*bytes.Buffer)) {
	var content bytes.Buffer
	fill(&content)
	binary.Write(&r.buf, binary.BigEndian, uint32(content.Len()+8))
	r.buf.WriteString(boxType)
	r.buf.Write(content.Bytes())
}

// writeMP4SubBox writes a nested MP4 box into a buffer.
func (r *InfiniteReader) writeMP4SubBox(parent *bytes.Buffer, boxType string, fill func(*bytes.Buffer)) {
	var content bytes.Buffer
	fill(&content)
	binary.Write(parent, binary.BigEndian, uint32(content.Len()+8))
	parent.WriteString(boxType)
	parent.Write(content.Bytes())
}

// ---------------------------------------------------------------------------
// WebM streaming (EBML/Matroska)
// ---------------------------------------------------------------------------

// generateWebMChunk generates WebM with EBML header and segment/clusters.
func (r *InfiniteReader) generateWebMChunk() error {
	switch r.phase {
	case 0:
		// EBML header element
		r.writeEBMLElement(0x1A45DFA3, func(buf *bytes.Buffer) {
			r.writeEBMLUint(buf, 0x4286, 1)          // EBMLVersion: 1
			r.writeEBMLUint(buf, 0x42F7, 1)          // EBMLReadVersion: 1
			r.writeEBMLUint(buf, 0x42F2, 4)          // EBMLMaxIDLength: 4
			r.writeEBMLUint(buf, 0x42F3, 8)          // EBMLMaxSizeLength: 8
			r.writeEBMLString(buf, 0x4282, "webm")   // DocType
			r.writeEBMLUint(buf, 0x4287, 4)          // DocTypeVersion: 4
			r.writeEBMLUint(buf, 0x4285, 2)          // DocTypeReadVersion: 2
		})
		r.phase = 1

	case 1:
		// Segment header (unknown size for streaming)
		r.writeEBMLID(0x18538067) // Segment
		// Unknown size: all 1s in 8 bytes (0x01FFFFFFFFFFFFFF)
		r.buf.Write([]byte{0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

		// Info element
		r.writeEBMLElement(0x1549A966, func(buf *bytes.Buffer) {
			r.writeEBMLUint(buf, 0x2AD7B1, 1000000) // TimecodeScale: 1ms
			r.writeEBMLString(buf, 0x4D80, "Glitch Infinite Stream") // MuxingApp
			r.writeEBMLString(buf, 0x5741, "Glitch/1.0")             // WritingApp
		})

		// Tracks element
		r.writeEBMLElement(0x1654AE6B, func(buf *bytes.Buffer) {
			// TrackEntry for video
			r.writeEBMLSubElement(buf, 0xAE, func(track *bytes.Buffer) {
				r.writeEBMLUint(track, 0xD7, 1)   // TrackNumber: 1
				r.writeEBMLUint(track, 0x73C5, 1)  // TrackUID: 1
				r.writeEBMLUint(track, 0x83, 1)    // TrackType: video
				r.writeEBMLString(track, 0x86, "V_VP8") // CodecID
				// Video settings
				r.writeEBMLSubElement(track, 0xE0, func(video *bytes.Buffer) {
					r.writeEBMLUint(video, 0xB0, uint64(r.width))  // PixelWidth
					r.writeEBMLUint(video, 0xBA, uint64(r.height)) // PixelHeight
				})
			})
		})

		r.phase = 2

	default:
		// Generate Cluster elements with SimpleBlock data
		r.writeEBMLElement(0x1F43B675, func(cluster *bytes.Buffer) {
			// Timecode element
			r.writeEBMLUint(cluster, 0xE7, r.timecodeMs)

			// Generate 1-5 SimpleBlocks per cluster
			numBlocks := 1 + r.rng.Intn(5)
			for b := 0; b < numBlocks; b++ {
				// SimpleBlock data
				blockSize := 128 + r.rng.Intn(896) // 128..1024 bytes
				blockData := make([]byte, 4+blockSize) // header + data
				// Track number (1 byte EBML coded = 0x81 for track 1)
				blockData[0] = 0x81
				// Timecode relative to cluster (int16, big-endian)
				tc := uint16(b * 33) // ~30fps
				blockData[1] = byte(tc >> 8)
				blockData[2] = byte(tc)
				// Flags: keyframe for first block
				if b == 0 {
					blockData[3] = 0x80 // keyframe
				}
				for i := 4; i < len(blockData); i++ {
					blockData[i] = byte(r.rng.Intn(256))
				}

				r.writeEBMLBinary(cluster, 0xA3, blockData) // SimpleBlock
			}
		})

		r.timecodeMs += 33 * uint64(1+r.rng.Intn(5)) // advance timecode
		r.seqNum++
	}

	return nil
}

// writeEBMLElement writes a top-level EBML element to r.buf.
func (r *InfiniteReader) writeEBMLElement(id uint32, fill func(*bytes.Buffer)) {
	var content bytes.Buffer
	fill(&content)
	r.writeEBMLID(id)
	r.writeEBMLSize(uint64(content.Len()))
	r.buf.Write(content.Bytes())
}

// writeEBMLSubElement writes a nested EBML element to a parent buffer.
func (r *InfiniteReader) writeEBMLSubElement(parent *bytes.Buffer, id uint32, fill func(*bytes.Buffer)) {
	var content bytes.Buffer
	fill(&content)
	writeEBMLIDTo(parent, id)
	writeEBMLSizeTo(parent, uint64(content.Len()))
	parent.Write(content.Bytes())
}

// writeEBMLID writes an EBML element ID to r.buf.
func (r *InfiniteReader) writeEBMLID(id uint32) {
	writeEBMLIDTo(&r.buf, id)
}

// writeEBMLIDTo writes an EBML element ID to a buffer.
func writeEBMLIDTo(buf *bytes.Buffer, id uint32) {
	if id <= 0xFF {
		buf.WriteByte(byte(id))
	} else if id <= 0xFFFF {
		buf.WriteByte(byte(id >> 8))
		buf.WriteByte(byte(id))
	} else if id <= 0xFFFFFF {
		buf.WriteByte(byte(id >> 16))
		buf.WriteByte(byte(id >> 8))
		buf.WriteByte(byte(id))
	} else {
		buf.WriteByte(byte(id >> 24))
		buf.WriteByte(byte(id >> 16))
		buf.WriteByte(byte(id >> 8))
		buf.WriteByte(byte(id))
	}
}

// writeEBMLSize writes an EBML VINT size to r.buf.
func (r *InfiniteReader) writeEBMLSize(size uint64) {
	writeEBMLSizeTo(&r.buf, size)
}

// writeEBMLSizeTo writes an EBML VINT size to a buffer.
func writeEBMLSizeTo(buf *bytes.Buffer, size uint64) {
	if size < 0x7F {
		buf.WriteByte(byte(size) | 0x80)
	} else if size < 0x3FFF {
		buf.WriteByte(byte(size>>8) | 0x40)
		buf.WriteByte(byte(size))
	} else if size < 0x1FFFFF {
		buf.WriteByte(byte(size>>16) | 0x20)
		buf.WriteByte(byte(size >> 8))
		buf.WriteByte(byte(size))
	} else if size < 0x0FFFFFFF {
		buf.WriteByte(byte(size>>24) | 0x10)
		buf.WriteByte(byte(size >> 16))
		buf.WriteByte(byte(size >> 8))
		buf.WriteByte(byte(size))
	} else {
		// 8-byte size
		buf.WriteByte(byte(size>>48) | 0x01)
		buf.WriteByte(byte(size >> 40))
		buf.WriteByte(byte(size >> 32))
		buf.WriteByte(byte(size >> 24))
		buf.WriteByte(byte(size >> 16))
		buf.WriteByte(byte(size >> 8))
		buf.WriteByte(byte(size))
	}
}

// writeEBMLUint writes an EBML unsigned integer element to a buffer.
func (r *InfiniteReader) writeEBMLUint(buf *bytes.Buffer, id uint32, val uint64) {
	writeEBMLIDTo(buf, id)
	if val <= 0xFF {
		writeEBMLSizeTo(buf, 1)
		buf.WriteByte(byte(val))
	} else if val <= 0xFFFF {
		writeEBMLSizeTo(buf, 2)
		buf.WriteByte(byte(val >> 8))
		buf.WriteByte(byte(val))
	} else if val <= 0xFFFFFF {
		writeEBMLSizeTo(buf, 3)
		buf.WriteByte(byte(val >> 16))
		buf.WriteByte(byte(val >> 8))
		buf.WriteByte(byte(val))
	} else {
		writeEBMLSizeTo(buf, 4)
		binary.Write(buf, binary.BigEndian, uint32(val))
	}
}

// writeEBMLString writes an EBML UTF-8 string element to a buffer.
func (r *InfiniteReader) writeEBMLString(buf *bytes.Buffer, id uint32, val string) {
	writeEBMLIDTo(buf, id)
	writeEBMLSizeTo(buf, uint64(len(val)))
	buf.WriteString(val)
}

// writeEBMLBinary writes an EBML binary element to a buffer.
func (r *InfiniteReader) writeEBMLBinary(buf *bytes.Buffer, id uint32, data []byte) {
	writeEBMLIDTo(buf, id)
	writeEBMLSizeTo(buf, uint64(len(data)))
	buf.Write(data)
}

// ---------------------------------------------------------------------------
// AVI streaming
// ---------------------------------------------------------------------------

// generateAVIChunk generates RIFF/AVI with headers on phase 0,
// then movi chunk video frames.
func (r *InfiniteReader) generateAVIChunk() error {
	if !r.headerWritten {
		// RIFF AVI header
		r.buf.WriteString("RIFF")
		binary.Write(&r.buf, binary.LittleEndian, uint32(0xFFFFFFFF-8)) // max size
		r.buf.WriteString("AVI ")

		// hdrl LIST
		r.writeAVIList("hdrl", func(buf *bytes.Buffer) {
			// avih (main AVI header)
			buf.WriteString("avih")
			avihSize := uint32(56)
			binary.Write(buf, binary.LittleEndian, avihSize)
			binary.Write(buf, binary.LittleEndian, uint32(33333))         // microseconds per frame (~30fps)
			binary.Write(buf, binary.LittleEndian, uint32(1000000))       // max bytes per sec
			binary.Write(buf, binary.LittleEndian, uint32(0))             // padding granularity
			binary.Write(buf, binary.LittleEndian, uint32(0x00000110))    // flags: has index + must use index
			binary.Write(buf, binary.LittleEndian, uint32(0))             // total frames (unknown for streaming)
			binary.Write(buf, binary.LittleEndian, uint32(0))             // initial frames
			binary.Write(buf, binary.LittleEndian, uint32(1))             // streams
			binary.Write(buf, binary.LittleEndian, uint32(r.width*r.height*3)) // suggested buffer size
			binary.Write(buf, binary.LittleEndian, uint32(r.width))       // width
			binary.Write(buf, binary.LittleEndian, uint32(r.height))      // height
			buf.Write(make([]byte, 16))                                    // reserved

			// strl LIST (stream header list)
			r.writeAVISubList(buf, "strl", func(strl *bytes.Buffer) {
				// strh (stream header)
				strl.WriteString("strh")
				strhSize := uint32(56)
				binary.Write(strl, binary.LittleEndian, strhSize)
				strl.WriteString("vids")                                        // fccType
				strl.WriteString("DIB ")                                        // fccHandler (uncompressed)
				binary.Write(strl, binary.LittleEndian, uint32(0))              // flags
				binary.Write(strl, binary.LittleEndian, uint16(0))              // priority
				binary.Write(strl, binary.LittleEndian, uint16(0))              // language
				binary.Write(strl, binary.LittleEndian, uint32(0))              // initial frames
				binary.Write(strl, binary.LittleEndian, uint32(1))              // scale
				binary.Write(strl, binary.LittleEndian, uint32(30))             // rate (30fps)
				binary.Write(strl, binary.LittleEndian, uint32(0))              // start
				binary.Write(strl, binary.LittleEndian, uint32(0))              // length
				binary.Write(strl, binary.LittleEndian, uint32(r.width*r.height*3)) // suggested buf size
				binary.Write(strl, binary.LittleEndian, uint32(0))              // quality
				binary.Write(strl, binary.LittleEndian, uint32(0))              // sample size
				binary.Write(strl, binary.LittleEndian, uint16(0))              // left
				binary.Write(strl, binary.LittleEndian, uint16(0))              // top
				binary.Write(strl, binary.LittleEndian, uint16(r.width))        // right
				binary.Write(strl, binary.LittleEndian, uint16(r.height))       // bottom

				// strf (stream format - BITMAPINFOHEADER)
				strl.WriteString("strf")
				strfSize := uint32(40) // BITMAPINFOHEADER
				binary.Write(strl, binary.LittleEndian, strfSize)
				binary.Write(strl, binary.LittleEndian, uint32(40))             // biSize
				binary.Write(strl, binary.LittleEndian, int32(r.width))         // biWidth
				binary.Write(strl, binary.LittleEndian, int32(r.height))        // biHeight
				binary.Write(strl, binary.LittleEndian, uint16(1))              // biPlanes
				binary.Write(strl, binary.LittleEndian, uint16(24))             // biBitCount (24-bit RGB)
				binary.Write(strl, binary.LittleEndian, uint32(0))              // biCompression (BI_RGB)
				binary.Write(strl, binary.LittleEndian, uint32(r.width*r.height*3)) // biSizeImage
				binary.Write(strl, binary.LittleEndian, int32(0))               // biXPelsPerMeter
				binary.Write(strl, binary.LittleEndian, int32(0))               // biYPelsPerMeter
				binary.Write(strl, binary.LittleEndian, uint32(0))              // biClrUsed
				binary.Write(strl, binary.LittleEndian, uint32(0))              // biClrImportant
			})
		})

		// movi LIST header (open-ended for streaming)
		r.buf.WriteString("LIST")
		binary.Write(&r.buf, binary.LittleEndian, uint32(0xFFFFFFFF-8))
		r.buf.WriteString("movi")

		r.headerWritten = true
	}

	// Generate video frame chunks ('00dc' = stream 0, uncompressed video)
	// Use a small BMP-like block for each frame (8x8 pixels)
	fw, fh := 8, 8
	frameDataSize := fw * fh * 3 // 24-bit RGB
	frameData := make([]byte, frameDataSize)

	// Fill with pattern based on frame count
	baseR := byte(r.rng.Intn(256))
	baseG := byte(r.rng.Intn(256))
	baseB := byte(r.rng.Intn(256))
	for i := 0; i < frameDataSize; i += 3 {
		frameData[i] = byte(int(baseB) + r.rng.Intn(20) - 10) // BGR order for BMP
		frameData[i+1] = byte(int(baseG) + r.rng.Intn(20) - 10)
		frameData[i+2] = byte(int(baseR) + r.rng.Intn(20) - 10)
	}

	r.buf.WriteString("00dc")
	binary.Write(&r.buf, binary.LittleEndian, uint32(frameDataSize))
	r.buf.Write(frameData)
	// Pad to 2-byte boundary if needed
	if frameDataSize%2 != 0 {
		r.buf.WriteByte(0x00)
	}

	r.frameCount++
	return nil
}

// writeAVIList writes a LIST chunk to r.buf.
func (r *InfiniteReader) writeAVIList(listType string, fill func(*bytes.Buffer)) {
	var content bytes.Buffer
	content.WriteString(listType)
	fill(&content)
	r.buf.WriteString("LIST")
	binary.Write(&r.buf, binary.LittleEndian, uint32(content.Len()))
	r.buf.Write(content.Bytes())
}

// writeAVISubList writes a nested LIST chunk to a parent buffer.
func (r *InfiniteReader) writeAVISubList(parent *bytes.Buffer, listType string, fill func(*bytes.Buffer)) {
	var content bytes.Buffer
	content.WriteString(listType)
	fill(&content)
	parent.WriteString("LIST")
	binary.Write(parent, binary.LittleEndian, uint32(content.Len()))
	parent.Write(content.Bytes())
}

// ---------------------------------------------------------------------------
// MPEG-TS streaming
// ---------------------------------------------------------------------------

// generateTSChunk generates MPEG Transport Stream packets.
// Phase 0: PAT and PMT packets. Subsequent: PES video packets in 188-byte TS packets.
func (r *InfiniteReader) generateTSChunk() error {
	if !r.headerWritten {
		// PAT packet (PID 0)
		r.writeTSPacket(0x0000, true, r.buildPAT())
		// PMT packet (PID 0x1000)
		r.writeTSPacket(0x1000, true, r.buildPMT())
		r.headerWritten = true
	}

	// Generate 5-20 TS packets with PES video data per call
	numPackets := 5 + r.rng.Intn(16)

	for p := 0; p < numPackets; p++ {
		// Video PES data on PID 0x0100
		pesPayload := make([]byte, 184) // max TS payload
		isStart := (p == 0)

		if isStart {
			// PES header for first packet of access unit
			pes := r.buildPESHeader()
			copy(pesPayload, pes)
			// Fill remaining with frame data
			for i := len(pes); i < len(pesPayload); i++ {
				pesPayload[i] = byte(r.rng.Intn(256))
			}
		} else {
			// Continuation data
			for i := range pesPayload {
				pesPayload[i] = byte(r.rng.Intn(256))
			}
		}

		r.writeTSPacket(0x0100, isStart, pesPayload)
	}

	r.seqNum++
	return nil
}

// writeTSPacket writes a 188-byte MPEG-TS packet to the buffer.
func (r *InfiniteReader) writeTSPacket(pid uint16, payloadStart bool, payload []byte) {
	var pkt [188]byte

	// Sync byte
	pkt[0] = 0x47

	// Transport error indicator (0), payload unit start indicator, transport priority (0)
	pkt[1] = byte(pid >> 8) & 0x1F // PID high 5 bits
	if payloadStart {
		pkt[1] |= 0x40 // payload unit start indicator
	}
	pkt[2] = byte(pid) // PID low 8 bits

	// Scrambling (00), adaptation field control (01 = payload only), continuity counter
	pkt[3] = 0x10 | (r.contCounter & 0x0F)
	r.contCounter++

	// Copy payload (up to 184 bytes)
	payloadLen := 184
	if len(payload) < payloadLen {
		payloadLen = len(payload)
	}
	copy(pkt[4:], payload[:payloadLen])

	// Pad with 0xFF if payload is short
	for i := 4 + payloadLen; i < 188; i++ {
		pkt[i] = 0xFF
	}

	r.buf.Write(pkt[:])
}

// buildPAT builds a Program Association Table section.
func (r *InfiniteReader) buildPAT() []byte {
	var pat bytes.Buffer
	pat.WriteByte(0x00) // pointer field
	pat.WriteByte(0x00) // table ID (PAT)
	// Section syntax indicator (1) + '0' + reserved (11) + section length
	sectionLen := uint16(13) // basic PAT
	pat.WriteByte(byte(0xB0 | (sectionLen >> 8)))
	pat.WriteByte(byte(sectionLen))
	binary.Write(&pat, binary.BigEndian, uint16(0x0001)) // transport stream ID
	pat.WriteByte(0xC1)                                   // version=0, current/next=1
	pat.WriteByte(0x00)                                   // section number
	pat.WriteByte(0x00)                                   // last section number
	// Program 1 -> PMT PID 0x1000
	binary.Write(&pat, binary.BigEndian, uint16(0x0001)) // program number
	binary.Write(&pat, binary.BigEndian, uint16(0xE000|0x1000)) // reserved bits + PMT PID
	// CRC32
	patBytes := pat.Bytes()
	crc := mpegCRC32(patBytes[1:]) // skip pointer field
	binary.Write(&pat, binary.BigEndian, crc)
	return pat.Bytes()
}

// buildPMT builds a Program Map Table section.
func (r *InfiniteReader) buildPMT() []byte {
	var pmt bytes.Buffer
	pmt.WriteByte(0x00) // pointer field
	pmt.WriteByte(0x02) // table ID (PMT)
	sectionLen := uint16(18)
	pmt.WriteByte(byte(0xB0 | (sectionLen >> 8)))
	pmt.WriteByte(byte(sectionLen))
	binary.Write(&pmt, binary.BigEndian, uint16(0x0001)) // program number
	pmt.WriteByte(0xC1)                                   // version=0, current/next=1
	pmt.WriteByte(0x00)                                   // section number
	pmt.WriteByte(0x00)                                   // last section number
	binary.Write(&pmt, binary.BigEndian, uint16(0xE000|0x0100)) // PCR PID
	binary.Write(&pmt, binary.BigEndian, uint16(0xF000))        // program info length = 0
	// Stream: H.264 video on PID 0x0100
	pmt.WriteByte(0x1B) // stream type: H.264
	binary.Write(&pmt, binary.BigEndian, uint16(0xE000|0x0100)) // elementary PID
	binary.Write(&pmt, binary.BigEndian, uint16(0xF000))        // ES info length = 0
	// CRC32
	pmtBytes := pmt.Bytes()
	crc := mpegCRC32(pmtBytes[1:])
	binary.Write(&pmt, binary.BigEndian, crc)
	return pmt.Bytes()
}

// buildPESHeader builds a Packetized Elementary Stream header.
func (r *InfiniteReader) buildPESHeader() []byte {
	var pes bytes.Buffer
	// Start code prefix
	pes.Write([]byte{0x00, 0x00, 0x01})
	pes.WriteByte(0xE0) // stream ID: video stream 0
	// PES packet length (0 = unbounded for video)
	binary.Write(&pes, binary.BigEndian, uint16(0))
	// Optional PES header
	pes.WriteByte(0x80) // marker bits, scrambling=0, priority=0, alignment=0, copyright=0, original=0
	pes.WriteByte(0x80) // PTS flag
	pes.WriteByte(0x05) // PES header data length

	// PTS (5 bytes)
	pts := uint64(r.seqNum) * 3600 // ~40ms intervals at 90kHz
	pes.WriteByte(byte(0x21 | ((pts >> 29) & 0x0E)))
	binary.Write(&pes, binary.BigEndian, uint16(((pts>>14)&0xFFFE)|1))
	binary.Write(&pes, binary.BigEndian, uint16(((pts<<1)&0xFFFE)|1))

	return pes.Bytes()
}

// mpegCRC32 is defined in generator.go

// ---------------------------------------------------------------------------
// HLS streaming (m3u8 playlist)
// ---------------------------------------------------------------------------

// generateHLSChunk generates an evolving m3u8 playlist.
func (r *InfiniteReader) generateHLSChunk() error {
	// Each call generates a complete playlist that's progressively longer
	r.segmentNum++

	targetDuration := 6
	// Live-style sliding window: show last 5 segments
	windowSize := 5
	startSeq := r.segmentNum
	if startSeq > windowSize {
		startSeq = r.segmentNum - windowSize + 1
	}

	r.buf.WriteString("#EXTM3U\n")
	r.buf.WriteString(fmt.Sprintf("#EXT-X-VERSION:3\n"))
	r.buf.WriteString(fmt.Sprintf("#EXT-X-TARGETDURATION:%d\n", targetDuration))
	r.buf.WriteString(fmt.Sprintf("#EXT-X-MEDIA-SEQUENCE:%d\n", startSeq))

	for seq := startSeq; seq <= r.segmentNum; seq++ {
		// Vary segment duration slightly
		dur := float64(targetDuration) - 0.5 + float64(r.rng.Intn(100))/100.0
		r.buf.WriteString(fmt.Sprintf("#EXTINF:%.3f,\n", dur))
		r.buf.WriteString(fmt.Sprintf("segment_%06d.ts\n", seq))
	}

	// After many segments, allow "ending" the stream
	if r.segmentNum > 100000 {
		r.buf.WriteString("#EXT-X-ENDLIST\n")
		return io.EOF
	}

	return nil
}

// ---------------------------------------------------------------------------
// DASH streaming (MPD manifest)
// ---------------------------------------------------------------------------

// generateDASHChunk generates an evolving DASH MPD manifest.
func (r *InfiniteReader) generateDASHChunk() error {
	r.segmentNum++

	duration := r.segmentNum * 4 // 4 seconds per segment
	hours := duration / 3600
	minutes := (duration % 3600) / 60
	seconds := duration % 60

	r.buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	r.buf.WriteString(fmt.Sprintf(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="dynamic" `+
		`minimumUpdatePeriod="PT4S" availabilityStartTime="2024-01-01T00:00:00Z" `+
		`mediaPresentationDuration="PT%dH%dM%dS" minBufferTime="PT2S">`+"\n",
		hours, minutes, seconds))

	r.buf.WriteString(`  <Period id="1">` + "\n")
	r.buf.WriteString(fmt.Sprintf(`    <AdaptationSet mimeType="video/mp4" contentType="video" `+
		`width="%d" height="%d" frameRate="30">`+"\n", r.width, r.height))
	r.buf.WriteString(`      <Representation id="1" bandwidth="1000000" codecs="avc1.64001e">` + "\n")
	r.buf.WriteString(`        <SegmentTemplate media="segment_$Number$.m4s" initialization="init.mp4" ` +
		fmt.Sprintf(`startNumber="1" timescale="1000" duration="4000"/>`+"\n"))

	// Add SegmentTimeline entries for recent segments
	r.buf.WriteString(`        <SegmentTimeline>` + "\n")
	startSeg := r.segmentNum
	if startSeg > 10 {
		startSeg = r.segmentNum - 9
	}
	for seg := startSeg; seg <= r.segmentNum; seg++ {
		r.buf.WriteString(fmt.Sprintf(`          <S t="%d" d="4000"/>`, (seg-1)*4000) + "\n")
	}
	r.buf.WriteString(`        </SegmentTimeline>` + "\n")

	r.buf.WriteString(`      </Representation>` + "\n")
	r.buf.WriteString(`    </AdaptationSet>` + "\n")
	r.buf.WriteString(`  </Period>` + "\n")
	r.buf.WriteString(`</MPD>` + "\n")

	if r.segmentNum > 100000 {
		return io.EOF
	}

	return nil
}

// ---------------------------------------------------------------------------
// SVG streaming
// ---------------------------------------------------------------------------

// generateSVGChunk generates an SVG that accumulates elements over time.
func (r *InfiniteReader) generateSVGChunk() error {
	if r.svgClosed {
		return io.EOF
	}

	if !r.headerWritten {
		// SVG opening tags with viewBox and style
		r.buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
		r.buf.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" `+
			`viewBox="0 0 %d %d" width="%d" height="%d">`+"\n",
			r.width, r.height, r.width, r.height))
		r.buf.WriteString(`<style>` + "\n")
		r.buf.WriteString(`  .glitch-text { font-family: monospace; font-size: 12px; }` + "\n")
		r.buf.WriteString(`  .glitch-shape { stroke-width: 2; }` + "\n")
		r.buf.WriteString(`</style>` + "\n")
		r.buf.WriteString(fmt.Sprintf(`<rect width="%d" height="%d" fill="#%02x%02x%02x"/>`,
			r.width, r.height, r.rng.Intn(64), r.rng.Intn(64), r.rng.Intn(64)) + "\n")
		r.headerWritten = true
	}

	// Generate 3-10 SVG elements per call
	numElements := 3 + r.rng.Intn(8)
	for i := 0; i < numElements; i++ {
		elemType := r.rng.Intn(7)
		fill := fmt.Sprintf("#%02x%02x%02x", r.rng.Intn(256), r.rng.Intn(256), r.rng.Intn(256))
		stroke := fmt.Sprintf("#%02x%02x%02x", r.rng.Intn(256), r.rng.Intn(256), r.rng.Intn(256))
		opacity := 0.2 + float64(r.rng.Intn(80))/100.0

		switch elemType {
		case 0: // rectangle
			x := r.rng.Intn(r.width)
			y := r.rng.Intn(r.height)
			w := 10 + r.rng.Intn(100)
			h := 10 + r.rng.Intn(100)
			r.buf.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="%d" height="%d" `+
				`fill="%s" stroke="%s" opacity="%.2f" class="glitch-shape"/>`,
				x, y, w, h, fill, stroke, opacity) + "\n")

		case 1: // circle
			cx := r.rng.Intn(r.width)
			cy := r.rng.Intn(r.height)
			radius := 5 + r.rng.Intn(80)
			r.buf.WriteString(fmt.Sprintf(`<circle cx="%d" cy="%d" r="%d" `+
				`fill="%s" stroke="%s" opacity="%.2f" class="glitch-shape"/>`,
				cx, cy, radius, fill, stroke, opacity) + "\n")

		case 2: // ellipse
			cx := r.rng.Intn(r.width)
			cy := r.rng.Intn(r.height)
			rx := 10 + r.rng.Intn(60)
			ry := 10 + r.rng.Intn(60)
			r.buf.WriteString(fmt.Sprintf(`<ellipse cx="%d" cy="%d" rx="%d" ry="%d" `+
				`fill="%s" stroke="%s" opacity="%.2f"/>`,
				cx, cy, rx, ry, fill, stroke, opacity) + "\n")

		case 3: // line
			x1 := r.rng.Intn(r.width)
			y1 := r.rng.Intn(r.height)
			x2 := r.rng.Intn(r.width)
			y2 := r.rng.Intn(r.height)
			r.buf.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" `+
				`stroke="%s" stroke-width="%d" opacity="%.2f"/>`,
				x1, y1, x2, y2, stroke, 1+r.rng.Intn(5), opacity) + "\n")

		case 4: // path (random cubic bezier)
			sx := r.rng.Intn(r.width)
			sy := r.rng.Intn(r.height)
			c1x := r.rng.Intn(r.width)
			c1y := r.rng.Intn(r.height)
			c2x := r.rng.Intn(r.width)
			c2y := r.rng.Intn(r.height)
			ex := r.rng.Intn(r.width)
			ey := r.rng.Intn(r.height)
			r.buf.WriteString(fmt.Sprintf(`<path d="M%d,%d C%d,%d %d,%d %d,%d" `+
				`fill="none" stroke="%s" stroke-width="%d" opacity="%.2f"/>`,
				sx, sy, c1x, c1y, c2x, c2y, ex, ey, stroke, 1+r.rng.Intn(4), opacity) + "\n")

		case 5: // text
			x := r.rng.Intn(r.width)
			y := r.rng.Intn(r.height)
			texts := []string{"GLITCH", "CHAOS", "STREAM", "INFINITE", "ERROR", "VOID", "NULL", "0xFF"}
			text := texts[r.rng.Intn(len(texts))]
			fontSize := 10 + r.rng.Intn(30)
			r.buf.WriteString(fmt.Sprintf(`<text x="%d" y="%d" fill="%s" font-size="%d" `+
				`opacity="%.2f" class="glitch-text">%s</text>`,
				x, y, fill, fontSize, opacity, text) + "\n")

		case 6: // polygon
			numPoints := 3 + r.rng.Intn(5)
			points := ""
			for p := 0; p < numPoints; p++ {
				if p > 0 {
					points += " "
				}
				points += fmt.Sprintf("%d,%d", r.rng.Intn(r.width), r.rng.Intn(r.height))
			}
			r.buf.WriteString(fmt.Sprintf(`<polygon points="%s" `+
				`fill="%s" stroke="%s" opacity="%.2f" class="glitch-shape"/>`,
				points, fill, stroke, opacity) + "\n")
		}
	}

	r.seqNum++

	// Close SVG after many elements
	if r.seqNum > 10000 {
		r.buf.WriteString("</svg>\n")
		r.svgClosed = true
		return io.EOF
	}

	return nil
}

// ---------------------------------------------------------------------------
// BMP streaming (with magic bytes, then random data)
// ---------------------------------------------------------------------------

// generateBMPChunk generates BMP-formatted data with proper headers on phase 0,
// then continued pixel data rows.
func (r *InfiniteReader) generateBMPChunk() error {
	if !r.headerWritten {
		// BMP file header (14 bytes) + DIB header (40 bytes BITMAPINFOHEADER)
		rowSize := ((r.width*24 + 31) / 32) * 4 // rows padded to 4-byte boundary
		imageSize := rowSize * r.height

		// File header
		r.buf.WriteByte('B')
		r.buf.WriteByte('M')
		binary.Write(&r.buf, binary.LittleEndian, uint32(54+imageSize)) // file size
		binary.Write(&r.buf, binary.LittleEndian, uint16(0))            // reserved
		binary.Write(&r.buf, binary.LittleEndian, uint16(0))            // reserved
		binary.Write(&r.buf, binary.LittleEndian, uint32(54))           // pixel data offset

		// DIB header (BITMAPINFOHEADER)
		binary.Write(&r.buf, binary.LittleEndian, uint32(40))                // header size
		binary.Write(&r.buf, binary.LittleEndian, int32(r.width))            // width
		binary.Write(&r.buf, binary.LittleEndian, int32(r.height))           // height (positive = bottom-up)
		binary.Write(&r.buf, binary.LittleEndian, uint16(1))                 // planes
		binary.Write(&r.buf, binary.LittleEndian, uint16(24))                // bits per pixel
		binary.Write(&r.buf, binary.LittleEndian, uint32(0))                 // compression (BI_RGB)
		binary.Write(&r.buf, binary.LittleEndian, uint32(imageSize))         // image size
		binary.Write(&r.buf, binary.LittleEndian, int32(2835))               // X pixels per meter
		binary.Write(&r.buf, binary.LittleEndian, int32(2835))               // Y pixels per meter
		binary.Write(&r.buf, binary.LittleEndian, uint32(0))                 // colors in table
		binary.Write(&r.buf, binary.LittleEndian, uint32(0))                 // important colors

		r.headerWritten = true
	}

	// Generate pixel rows (16 rows per call)
	rowSize := ((r.width*24 + 31) / 32) * 4
	numRows := 16
	baseR := byte(r.rng.Intn(256))
	baseG := byte(r.rng.Intn(256))
	baseB := byte(r.rng.Intn(256))

	for row := 0; row < numRows; row++ {
		rowBuf := make([]byte, rowSize)
		for x := 0; x < r.width; x++ {
			off := x * 3
			rowBuf[off] = byte(int(baseB) + r.rng.Intn(30) - 15)   // BGR order
			rowBuf[off+1] = byte(int(baseG) + r.rng.Intn(30) - 15)
			rowBuf[off+2] = byte(int(baseR) + r.rng.Intn(30) - 15)
		}
		r.buf.Write(rowBuf)
	}

	r.seqNum++
	return nil
}

// ---------------------------------------------------------------------------
// WebP streaming (with RIFF/WebP magic, then random VP8 data)
// ---------------------------------------------------------------------------

// generateWebPChunk generates WebP-formatted data with proper headers on phase 0,
// then generates VP8 frame data chunks.
func (r *InfiniteReader) generateWebPChunk() error {
	if !r.headerWritten {
		// RIFF header
		r.buf.WriteString("RIFF")
		binary.Write(&r.buf, binary.LittleEndian, uint32(0xFFFFFFFF-8)) // max size for streaming
		r.buf.WriteString("WEBP")

		// VP8 chunk header
		r.buf.WriteString("VP8 ")
		// VP8 frame size placeholder (we'll write it as large)
		binary.Write(&r.buf, binary.LittleEndian, uint32(0xFFFFFF))

		// VP8 bitstream frame header (uncompressed data chunk)
		// Frame tag (3 bytes): keyframe, version, show_frame, first_part_size
		// Keyframe tag: bit 0 = 0 (keyframe)
		frameTag := uint32(0) | (0 << 1) | (1 << 4) | (100 << 5)
		r.buf.WriteByte(byte(frameTag))
		r.buf.WriteByte(byte(frameTag >> 8))
		r.buf.WriteByte(byte(frameTag >> 16))

		// Start code for keyframe
		r.buf.Write([]byte{0x9D, 0x01, 0x2A})

		// Width and height (16 bits each, little-endian)
		binary.Write(&r.buf, binary.LittleEndian, uint16(r.width))
		binary.Write(&r.buf, binary.LittleEndian, uint16(r.height))

		r.headerWritten = true
	}

	// Generate VP8-like frame data chunks
	chunkSize := 1024 + r.rng.Intn(3072) // 1-4 KB
	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = byte(r.rng.Intn(256))
	}
	r.buf.Write(chunk)

	r.seqNum++
	return nil
}

// ---------------------------------------------------------------------------
// ICO streaming (with ICO magic bytes, then BMP image data)
// ---------------------------------------------------------------------------

// generateICOChunk generates ICO-formatted data with proper headers on phase 0,
// then continued pixel data.
func (r *InfiniteReader) generateICOChunk() error {
	if !r.headerWritten {
		// ICO header (6 bytes)
		binary.Write(&r.buf, binary.LittleEndian, uint16(0))     // reserved
		binary.Write(&r.buf, binary.LittleEndian, uint16(1))     // type: ICO
		binary.Write(&r.buf, binary.LittleEndian, uint16(1))     // 1 image

		// ICO directory entry (16 bytes)
		iconW := 32  // standard icon size
		iconH := 32
		r.buf.WriteByte(byte(iconW)) // width (0 = 256)
		r.buf.WriteByte(byte(iconH)) // height (0 = 256)
		r.buf.WriteByte(0)           // color count (0 = no palette)
		r.buf.WriteByte(0)           // reserved
		binary.Write(&r.buf, binary.LittleEndian, uint16(1))  // color planes
		binary.Write(&r.buf, binary.LittleEndian, uint16(32)) // bits per pixel
		// Size of BMP data: BITMAPINFOHEADER(40) + pixels(32*32*4) + AND mask(32*32/8)
		bmpDataSize := uint32(40 + iconW*iconH*4 + iconW*iconH/8)
		binary.Write(&r.buf, binary.LittleEndian, bmpDataSize)
		binary.Write(&r.buf, binary.LittleEndian, uint32(22)) // offset to BMP data

		// BMP BITMAPINFOHEADER (ICO uses double height)
		binary.Write(&r.buf, binary.LittleEndian, uint32(40))
		binary.Write(&r.buf, binary.LittleEndian, int32(iconW))
		binary.Write(&r.buf, binary.LittleEndian, int32(iconH*2)) // double height for ICO
		binary.Write(&r.buf, binary.LittleEndian, uint16(1))      // planes
		binary.Write(&r.buf, binary.LittleEndian, uint16(32))     // bits per pixel
		binary.Write(&r.buf, binary.LittleEndian, uint32(0))      // compression
		binary.Write(&r.buf, binary.LittleEndian, uint32(0))      // image size
		binary.Write(&r.buf, binary.LittleEndian, int32(0))
		binary.Write(&r.buf, binary.LittleEndian, int32(0))
		binary.Write(&r.buf, binary.LittleEndian, uint32(0))
		binary.Write(&r.buf, binary.LittleEndian, uint32(0))

		// Pixel data (BGRA, bottom-up)
		for y := 0; y < iconH; y++ {
			for x := 0; x < iconW; x++ {
				r.buf.WriteByte(byte(r.rng.Intn(256))) // B
				r.buf.WriteByte(byte(r.rng.Intn(256))) // G
				r.buf.WriteByte(byte(r.rng.Intn(256))) // R
				r.buf.WriteByte(255)                    // A
			}
		}

		// AND mask (all zeros = fully opaque)
		maskSize := iconW * iconH / 8
		r.buf.Write(make([]byte, maskSize))

		r.headerWritten = true
	}

	// After the initial icon, generate more random icon-like data
	chunkSize := 1024 + r.rng.Intn(3072)
	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = byte(r.rng.Intn(256))
	}
	r.buf.Write(chunk)

	r.seqNum++
	return nil
}

// ---------------------------------------------------------------------------
// TIFF streaming (with TIFF magic bytes, then IFD and pixel data)
// ---------------------------------------------------------------------------

// generateTIFFChunk generates TIFF-formatted data with proper headers on phase 0,
// then continued strip data.
func (r *InfiniteReader) generateTIFFChunk() error {
	if !r.headerWritten {
		// TIFF header (8 bytes)
		// Little-endian byte order
		r.buf.Write([]byte{'I', 'I'}) // little-endian
		binary.Write(&r.buf, binary.LittleEndian, uint16(42)) // magic number
		binary.Write(&r.buf, binary.LittleEndian, uint32(8))  // offset to first IFD

		// IFD (Image File Directory)
		numEntries := uint16(11)
		binary.Write(&r.buf, binary.LittleEndian, numEntries)

		// IFD entries (12 bytes each): tag, type, count, value/offset
		w := uint32(r.width)
		h := uint32(r.height)
		stripRows := uint32(16)
		strips := (h + stripRows - 1) / stripRows

		r.writeTIFFEntry(256, 3, 1, w)                  // ImageWidth
		r.writeTIFFEntry(257, 3, 1, h)                  // ImageLength
		r.writeTIFFEntry(258, 3, 1, 8)                  // BitsPerSample (8 for each channel)
		r.writeTIFFEntry(259, 3, 1, 1)                  // Compression (1=none)
		r.writeTIFFEntry(262, 3, 1, 2)                  // PhotometricInterpretation (2=RGB)
		r.writeTIFFEntry(273, 4, strips, 0xFFFFFFFF)    // StripOffsets (placeholder)
		r.writeTIFFEntry(277, 3, 1, 3)                  // SamplesPerPixel
		r.writeTIFFEntry(278, 3, 1, stripRows)          // RowsPerStrip
		r.writeTIFFEntry(279, 4, strips, w*stripRows*3) // StripByteCounts
		r.writeTIFFEntry(282, 5, 1, 0)                  // XResolution (placeholder)
		r.writeTIFFEntry(283, 5, 1, 0)                  // YResolution (placeholder)

		// Next IFD offset (0 = no more IFDs)
		binary.Write(&r.buf, binary.LittleEndian, uint32(0))

		r.headerWritten = true
	}

	// Generate strip data (16 rows per strip)
	stripRows := 16
	stripSize := r.width * stripRows * 3 // RGB
	strip := make([]byte, stripSize)

	baseR := byte(r.rng.Intn(256))
	baseG := byte(r.rng.Intn(256))
	baseB := byte(r.rng.Intn(256))
	for i := 0; i < stripSize; i += 3 {
		strip[i] = byte(int(baseR) + r.rng.Intn(30) - 15)
		strip[i+1] = byte(int(baseG) + r.rng.Intn(30) - 15)
		strip[i+2] = byte(int(baseB) + r.rng.Intn(30) - 15)
	}
	r.buf.Write(strip)

	r.seqNum++
	return nil
}

// writeTIFFEntry writes a 12-byte TIFF IFD entry.
func (r *InfiniteReader) writeTIFFEntry(tag, dataType uint16, count, value uint32) {
	binary.Write(&r.buf, binary.LittleEndian, tag)
	binary.Write(&r.buf, binary.LittleEndian, dataType)
	binary.Write(&r.buf, binary.LittleEndian, count)
	binary.Write(&r.buf, binary.LittleEndian, value)
}

// ---------------------------------------------------------------------------
// Random chunk fallback
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// clampU8 clamps an int to the 0-255 range and returns it as uint8.
func clampU8(v int) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}

// Ensure packages are used.
var _ = crc32.NewIEEE
var _ = jpeg.Encode
var _ = fmt.Sprintf
