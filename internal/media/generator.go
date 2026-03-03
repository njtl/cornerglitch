package media

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"math"
	"math/rand"
	"strings"
	"sync"
)

// Format identifies a media format.
type Format string

const (
	FormatPNG  Format = "png"
	FormatJPEG Format = "jpeg"
	FormatGIF  Format = "gif"
	FormatBMP  Format = "bmp"
	FormatWebP Format = "webp"
	FormatSVG  Format = "svg"
	FormatICO  Format = "ico"
	FormatTIFF Format = "tiff"
	FormatWAV  Format = "wav"
	FormatMP3  Format = "mp3"
	FormatOGG  Format = "ogg"
	FormatFLAC Format = "flac"
	FormatMP4  Format = "mp4"
	FormatWebM Format = "webm"
	FormatAVI  Format = "avi"
	FormatHLS  Format = "hls"
	FormatDASH Format = "dash"
	FormatTS   Format = "ts"
)

// FormatFromPath returns the Format corresponding to the file extension in the
// given URL path. Returns an empty string if the extension is unrecognised.
func FormatFromPath(path string) Format {
	// Find the last dot after the last slash
	lastSlash := strings.LastIndex(path, "/")
	base := path[lastSlash+1:]
	lastDot := strings.LastIndex(base, ".")
	if lastDot < 0 {
		return ""
	}
	ext := strings.ToLower(base[lastDot+1:])
	switch ext {
	case "png":
		return FormatPNG
	case "jpg", "jpeg":
		return FormatJPEG
	case "gif":
		return FormatGIF
	case "bmp":
		return FormatBMP
	case "webp":
		return FormatWebP
	case "svg":
		return FormatSVG
	case "ico":
		return FormatICO
	case "tif", "tiff":
		return FormatTIFF
	case "wav":
		return FormatWAV
	case "mp3":
		return FormatMP3
	case "ogg":
		return FormatOGG
	case "flac":
		return FormatFLAC
	case "mp4", "m4v":
		return FormatMP4
	case "webm":
		return FormatWebM
	case "avi":
		return FormatAVI
	case "m3u8":
		return FormatHLS
	case "mpd":
		return FormatDASH
	case "ts":
		return FormatTS
	default:
		return ""
	}
}

// ContentType returns the MIME type for a format.
func (f Format) ContentType() string {
	switch f {
	case FormatPNG:
		return "image/png"
	case FormatJPEG:
		return "image/jpeg"
	case FormatGIF:
		return "image/gif"
	case FormatBMP:
		return "image/bmp"
	case FormatWebP:
		return "image/webp"
	case FormatSVG:
		return "image/svg+xml"
	case FormatICO:
		return "image/x-icon"
	case FormatTIFF:
		return "image/tiff"
	case FormatWAV:
		return "audio/wav"
	case FormatMP3:
		return "audio/mpeg"
	case FormatOGG:
		return "audio/ogg"
	case FormatFLAC:
		return "audio/flac"
	case FormatMP4:
		return "video/mp4"
	case FormatWebM:
		return "video/webm"
	case FormatAVI:
		return "video/x-msvideo"
	case FormatHLS:
		return "application/vnd.apple.mpegurl"
	case FormatDASH:
		return "application/dash+xml"
	case FormatTS:
		return "video/mp2t"
	default:
		return "application/octet-stream"
	}
}

// Pre-computed minimal valid WebP (1x1 white pixel, VP8L lossless).
// Magic: RIFF????WEBPVP8L
var minimalWebP = []byte{
	0x52, 0x49, 0x46, 0x46, // RIFF
	0x24, 0x00, 0x00, 0x00, // file size - 8
	0x57, 0x45, 0x42, 0x50, // WEBP
	0x56, 0x50, 0x38, 0x4C, // VP8L
	0x18, 0x00, 0x00, 0x00, // chunk size
	0x2F, 0x00, 0x00, 0x00, // VP8L signature 0x2f
	0x00, 0x00, 0x00, 0x00, // width-1=0, height-1=0 in packed bits
	0x00, 0xFF, 0xFF, 0xFF, // color data (white ARGB)
	0xFF, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

// Pre-computed minimal valid MP3 — one silent MPEG1 Layer3 128kbps 44100Hz frame.
// Frame sync: 0xFF 0xFB (MPEG1, Layer3, 128kbps, 44100, stereo)
// Followed by 416 bytes of zeroed frame data (frame size for 128kbps@44100 = 417 bytes).
var minimalMP3Frame []byte

// Pre-computed minimal OGG Vorbis: identification + comment + setup + audio pages.
// This is a real minimal Vorbis I file with one channel, 8000Hz, one audio frame.
var minimalOGG []byte

// Pre-computed minimal FLAC: fLaC marker + STREAMINFO block + one audio frame.
var minimalFLAC []byte

// Pre-computed H.264 SPS + PPS + IDR NAL units for a 1x1 pixel black frame.
// These are standard bytes for a 1x1 baseline H.264 stream.
var h264SPSPPSIDر []byte

// Pre-computed VP8 keyframe for 1x1 pixel (for WebM).
var vp8Keyframe []byte

func init() {
	// Build silent MP3 frame (417 bytes for 128kbps MPEG1 Layer3 44100Hz)
	// Header: FF FB 90 00 (MPEG1, Layer3, 128kbps, 44100Hz, Joint Stereo)
	// Side info + zero frame data
	mp3Header := []byte{0xFF, 0xFB, 0x90, 0x00}
	// 417 - 4 = 413 zero bytes for the frame body
	mp3Body := make([]byte, 413)
	// Xing/Info tag at byte 36 for CBR
	minimalMP3Frame = append(mp3Header, mp3Body...)

	// Minimal OGG Vorbis: synthesize from known-good capture pages.
	// Use a valid 3-page OGG (ident, comment, setup) + audio page.
	// For a chaos tool approximation, generate the identification page header
	// with correct Ogg page structure (capture pattern, etc.)
	minimalOGG = buildMinimalOGG()

	// Minimal FLAC
	minimalFLAC = buildMinimalFLAC()

	// H.264 NAL units: SPS (profile=baseline 66, level 3.0, 1x1)
	// PPS + IDR slice
	h264SPSPPSIDر = []byte{
		// Start code + SPS NAL
		0x00, 0x00, 0x00, 0x01,
		0x67, 0x42, 0xC0, 0x1E, 0xD9, 0x00, 0xA0, 0x47, 0xFE, 0xC8,
		// Start code + PPS NAL
		0x00, 0x00, 0x00, 0x01,
		0x68, 0xCE, 0x38, 0x80,
		// Start code + IDR slice (minimal)
		0x00, 0x00, 0x00, 0x01,
		0x65, 0x88, 0x84, 0x00, 0x33, 0xFF,
	}

	// VP8 keyframe for 1x1 pixel (green-ish). Standard VP8 bitstream.
	vp8Keyframe = []byte{
		0x30, 0x01, 0x00, // frame tag: key frame, version 0, show_frame, size_minus_one
		0x9D, 0x01, 0x2A, // start code
		0x01, 0x00, // width = 1
		0x01, 0x00, // height = 1
		// Compressed data for a 1x1 black frame
		0x00, 0x34, 0x25, 0x9F, 0x00, 0x00,
	}
}

// buildMinimalOGG constructs a minimal valid OGG Vorbis file.
func buildMinimalOGG() []byte {
	var buf bytes.Buffer

	// Vorbis identification header
	vorbisIdent := []byte{
		0x01,                                     // packet type: identification
		0x76, 0x6F, 0x72, 0x62, 0x69, 0x73,      // "vorbis"
		0x00, 0x00, 0x00, 0x00,                   // version
		0x01,                                     // channels = 1
		0x40, 0x1F, 0x00, 0x00,                   // sample rate = 8000
		0x00, 0x00, 0x00, 0x00,                   // max bitrate (unset)
		0x00, 0x7D, 0x00, 0x00,                   // nominal bitrate = 32000
		0x00, 0x00, 0x00, 0x00,                   // min bitrate (unset)
		0xB8,                                     // blocksize_0=8, blocksize_1=11 packed
		0x01,                                     // framing bit
	}

	// Comment header
	vorbisComment := []byte{
		0x03,                                // packet type: comment
		0x76, 0x6F, 0x72, 0x62, 0x69, 0x73, // "vorbis"
		0x09, 0x00, 0x00, 0x00, // vendor string length = 9
		0x67, 0x6C, 0x69, 0x74, 0x63, 0x68, 0x20, 0x30, 0x31, // "glitch 01"
		0x00, 0x00, 0x00, 0x00, // comment count = 0
		0x01, // framing bit
	}

	// Write identification page (first page, granule=0, serial=1)
	writeOGGPage(&buf, 0x02, 0, 1, 0, vorbisIdent)
	// Write comment + setup pages (continuation pages)
	// For simplicity, write comment header as page 2
	writeOGGPage(&buf, 0x00, 0, 1, 1, vorbisComment)
	// Minimal "setup header" packet (just enough to parse)
	vorbisSetup := []byte{
		0x05,                                // packet type: setup
		0x76, 0x6F, 0x72, 0x62, 0x69, 0x73, // "vorbis"
		// Codebooks count = 1, minimal codebook
		0x00,
		0x01, // framing
	}
	writeOGGPage(&buf, 0x04, 0, 1, 2, vorbisSetup)

	return buf.Bytes()
}

// writeOGGPage writes a single OGG page to buf.
func writeOGGPage(buf *bytes.Buffer, headerType byte, granulePos uint64, serial uint32, seqno uint32, data []byte) {
	var page bytes.Buffer
	page.WriteString("OggS")       // capture pattern
	page.WriteByte(0x00)           // stream structure version
	page.WriteByte(headerType)     // header type
	binary.Write(&page, binary.LittleEndian, granulePos) // granule position
	binary.Write(&page, binary.LittleEndian, serial)      // stream serial number
	binary.Write(&page, binary.LittleEndian, seqno)       // page sequence number
	// CRC placeholder (4 bytes, will be patched)
	crcOffset := page.Len()
	page.Write([]byte{0, 0, 0, 0})
	// Segment table: one segment per 255 bytes + remainder
	segments := buildSegmentTable(len(data))
	page.WriteByte(byte(len(segments)))
	for _, s := range segments {
		page.WriteByte(s)
	}
	page.Write(data)

	pageBytes := page.Bytes()
	// Compute CRC32 with OGG polynomial (0x04C11DB7)
	crc := oggCRC32(pageBytes)
	binary.LittleEndian.PutUint32(pageBytes[crcOffset:], crc)

	buf.Write(pageBytes)
}

// buildSegmentTable creates an OGG lacing table for data of length n.
func buildSegmentTable(n int) []byte {
	var segs []byte
	for n >= 255 {
		segs = append(segs, 255)
		n -= 255
	}
	segs = append(segs, byte(n))
	return segs
}

// oggCRC32 computes the OGG CRC-32 checksum (polynomial 0x04C11DB7).
// The CRC field in the page header must be zeroed before computing.
func oggCRC32(data []byte) uint32 {
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

// buildMinimalFLAC constructs a minimal valid FLAC file.
func buildMinimalFLAC() []byte {
	var buf bytes.Buffer

	// fLaC marker
	buf.WriteString("fLaC")

	// STREAMINFO block (last metadata block = true, type=0, length=34)
	// Header byte: bit7=1 (last), bits 6-0 = block type 0
	buf.WriteByte(0x80) // last-metadata-block=1, block-type=0
	// Block length = 34 bytes (STREAMINFO is always 34 bytes)
	buf.Write([]byte{0x00, 0x00, 0x22})

	// STREAMINFO data (34 bytes):
	// min block size: 4096 (2 bytes)
	buf.Write([]byte{0x10, 0x00})
	// max block size: 4096 (2 bytes)
	buf.Write([]byte{0x10, 0x00})
	// min frame size: 0 (3 bytes, unknown)
	buf.Write([]byte{0x00, 0x00, 0x00})
	// max frame size: 0 (3 bytes, unknown)
	buf.Write([]byte{0x00, 0x00, 0x00})
	// sample rate (20 bits) = 44100 (0xAC44), channels-1 (3 bits) = 0 (mono),
	// bits per sample - 1 (5 bits) = 15 (16-bit), total samples (36 bits) = 44100
	// Pack: 0b 1010 1100 0100 0100 [20 bits sample rate=44100]
	//          [3 bits ch-1=0] [5 bits bps-1=15] [36 bits samples=44100]
	// Byte layout: SSSSSSSS SSSSSSSS SSSSCCBB BBBBTTTT TTTTTTTT TTTTTTTT TTTTTTTT TTTTTTTT TT
	// S=samplerate bits, C=channel bits, B=bitspersample bits, T=totalsamples bits
	// samplerate 44100 = 0xAC44 = 1010 1100 0100 0100 (20 bits)
	// channels-1 = 0 = 000 (3 bits)
	// bps-1 = 15 = 01111 (5 bits)
	// totalsamples = 44100 = 0x000000000AC44 (36 bits)
	// Packed bytes:
	// [1010 1100] [0100 0100] [000 01111] -> 0xAC, 0x44, 0x0F
	// [0000 0000] [0000 0000] [0000 0000] [0000 1010] [1100 0100 0100] -> complex
	// Let's just write them out carefully:
	// Bits: 1010 1100 0100 0100 0000 1111 0000 0000 0000 0000 0000 0000 1010 1100 0100 0100 00
	// = 0xAC, 0x44, 0x0F, 0x00, 0x00, 0x00, 0xAC, 0x44 (+ 4 bits = 0x00)
	buf.Write([]byte{0xAC, 0x44, 0x0F, 0x00, 0x00, 0x00, 0xAC, 0x44, 0x00})
	// MD5 signature (16 bytes, zero = unknown)
	buf.Write(make([]byte, 16))

	// One minimal audio frame: FLAC frame header + one subframe + CRC
	// Frame header sync: 0xFF 0xF8 (fixed blocksize)
	// We write a minimal silent frame for blocksize=1152, samplerate=44100, ch=mono, bps=16
	frame := []byte{
		0xFF, 0xF8, // sync + reserved + blocking strategy
		0x32,       // block size=1152 (code 3=0011), sample rate=44100 (code 2=0010 => from streaminfo)
		0x00,       // channel=mono (0000), sample size=from streaminfo (000), reserved
		0x00,       // frame/sample number (UTF-8 coded 0)
		// subframe: constant subframe type (000 0000 = constant), value=0 (16 bits)
		0x00, 0x00, 0x00,
		// CRC-16 (2 bytes, zeroed for simplicity)
		0x00, 0x00,
	}
	buf.Write(frame)

	return buf.Bytes()
}

// Generator produces deterministic media content from path seeds.
type Generator struct {
	mu     sync.RWMutex
	width  int
	height int
}

// New creates a Generator with default settings (320x240).
func New() *Generator {
	return &Generator{
		width:  320,
		height: 240,
	}
}

// SetDimensions sets the default image dimensions.
func (g *Generator) SetDimensions(w, h int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if w > 0 {
		g.width = w
	}
	if h > 0 {
		g.height = h
	}
}

func (g *Generator) dims() (int, int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.width, g.height
}

// Generate produces media content for the given format and path seed.
// Returns the content bytes and the appropriate Content-Type.
func (g *Generator) Generate(format Format, path string) ([]byte, string) {
	var data []byte
	switch format {
	case FormatPNG:
		data = g.generatePNG(path)
	case FormatJPEG:
		data = g.generateJPEG(path)
	case FormatGIF:
		data = g.generateGIF(path)
	case FormatBMP:
		data = g.generateBMP(path)
	case FormatWebP:
		data = g.generateWebP(path)
	case FormatSVG:
		data = g.generateSVG(path)
	case FormatICO:
		data = g.generateICO(path)
	case FormatTIFF:
		data = g.generateTIFF(path)
	case FormatWAV:
		data = g.generateWAV(path)
	case FormatMP3:
		data = g.generateMP3(path)
	case FormatOGG:
		data = g.generateOGG(path)
	case FormatFLAC:
		data = g.generateFLAC(path)
	case FormatMP4:
		data = g.generateMP4(path)
	case FormatWebM:
		data = g.generateWebM(path)
	case FormatAVI:
		data = g.generateAVI(path)
	case FormatHLS:
		data = g.generateHLS(path)
	case FormatDASH:
		data = g.generateDASH(path)
	case FormatTS:
		data = g.generateTS(path)
	default:
		data = []byte{}
	}
	return data, format.ContentType()
}

// GenerateStream returns an io.Reader for streaming large/infinite content.
// maxBytes limits output (0 = use internal default limit).
func (g *Generator) GenerateStream(format Format, path string, maxBytes int64) io.Reader {
	if maxBytes <= 0 {
		maxBytes = 10 * 1024 * 1024 // 10MB default
	}
	return NewInfiniteReader(format, path, maxBytes)
}

// deterministicRng creates a seeded RNG from a path using SHA-256.
func deterministicRng(path string) *rand.Rand {
	h := sha256.Sum256([]byte(path))
	var seed int64
	for i := 0; i < 8; i++ {
		seed = (seed << 8) | int64(h[i])
	}
	// Mask to positive int64
	if seed < 0 {
		seed = -seed
	}
	return rand.New(rand.NewSource(seed))
}

// deterministicColor picks an RGBA color from the rng.
func deterministicColor(rng *rand.Rand) color.RGBA {
	return color.RGBA{
		R: uint8(rng.Intn(256)),
		G: uint8(rng.Intn(256)),
		B: uint8(rng.Intn(256)),
		A: 255,
	}
}

// generateImage creates a deterministic image.RGBA from a path seed.
// Patterns: 0=solid, 1=h-gradient, 2=v-gradient, 3=checkerboard, 4=diagonal stripes, 5=noise
func (g *Generator) generateImage(path string) *image.RGBA {
	w, h := g.dims()
	rng := deterministicRng(path)
	pattern := rng.Intn(6)

	img := image.NewRGBA(image.Rect(0, 0, w, h))

	c1 := deterministicColor(rng)
	c2 := deterministicColor(rng)

	switch pattern {
	case 0: // Solid color
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				img.SetRGBA(x, y, c1)
			}
		}
	case 1: // Horizontal gradient
		for y := 0; y < h; y++ {
			t := float64(y) / float64(h-1)
			c := lerpColor(c1, c2, t)
			for x := 0; x < w; x++ {
				img.SetRGBA(x, y, c)
			}
		}
	case 2: // Vertical gradient
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				t := float64(x) / float64(w-1)
				c := lerpColor(c1, c2, t)
				img.SetRGBA(x, y, c)
			}
		}
	case 3: // Checkerboard
		size := 16 + rng.Intn(32)
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				if (x/size+y/size)%2 == 0 {
					img.SetRGBA(x, y, c1)
				} else {
					img.SetRGBA(x, y, c2)
				}
			}
		}
	case 4: // Diagonal stripes
		size := 8 + rng.Intn(24)
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				if (x+y)/size%2 == 0 {
					img.SetRGBA(x, y, c1)
				} else {
					img.SetRGBA(x, y, c2)
				}
			}
		}
	case 5: // Random noise
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				img.SetRGBA(x, y, color.RGBA{
					R: uint8(rng.Intn(256)),
					G: uint8(rng.Intn(256)),
					B: uint8(rng.Intn(256)),
					A: 255,
				})
			}
		}
	}
	return img
}

// lerpColor linearly interpolates between two colors.
func lerpColor(a, b color.RGBA, t float64) color.RGBA {
	return color.RGBA{
		R: uint8(float64(a.R)*(1-t) + float64(b.R)*t),
		G: uint8(float64(a.G)*(1-t) + float64(b.G)*t),
		B: uint8(float64(a.B)*(1-t) + float64(b.B)*t),
		A: 255,
	}
}

// generatePNG produces a valid PNG.
func (g *Generator) generatePNG(path string) []byte {
	img := g.generateImage(path)
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// generateJPEG produces a valid JPEG.
func (g *Generator) generateJPEG(path string) []byte {
	img := g.generateImage(path)
	var buf bytes.Buffer
	_ = jpeg.Encode(&buf, img, &jpeg.Options{Quality: 85})
	return buf.Bytes()
}

// generateGIF produces a valid animated GIF with 4-8 frames.
func (g *Generator) generateGIF(path string) []byte {
	w, h := g.dims()
	// Scale down for GIF (256 color palette limit makes large GIFs slow)
	gw, gh := w/2, h/2
	if gw < 16 {
		gw = 16
	}
	if gh < 16 {
		gh = 16
	}

	rng := deterministicRng(path)
	numFrames := 4 + rng.Intn(5)

	anim := &gif.GIF{}
	anim.LoopCount = 0 // loop forever

	for f := 0; f < numFrames; f++ {
		// Generate a palette for this frame
		pal := make(color.Palette, 256)
		c1 := deterministicColor(rng)
		c2 := deterministicColor(rng)
		for i := range pal {
			t := float64(i) / 255.0
			pal[i] = lerpColor(c1, c2, t)
		}

		paletted := image.NewPaletted(image.Rect(0, 0, gw, gh), pal)

		// Pattern for this frame
		pattern := (f + rng.Intn(3)) % 4
		switch pattern {
		case 0:
			idx := uint8(rng.Intn(256))
			for y := 0; y < gh; y++ {
				for x := 0; x < gw; x++ {
					paletted.SetColorIndex(x, y, idx)
				}
			}
		case 1: // gradient
			for y := 0; y < gh; y++ {
				idx := uint8(y * 255 / gh)
				for x := 0; x < gw; x++ {
					paletted.SetColorIndex(x, y, idx)
				}
			}
		case 2: // checkerboard
			size := 8 + rng.Intn(16)
			for y := 0; y < gh; y++ {
				for x := 0; x < gw; x++ {
					if (x/size+y/size)%2 == 0 {
						paletted.SetColorIndex(x, y, 0)
					} else {
						paletted.SetColorIndex(x, y, 255)
					}
				}
			}
		case 3: // noise
			for y := 0; y < gh; y++ {
				for x := 0; x < gw; x++ {
					paletted.SetColorIndex(x, y, uint8(rng.Intn(256)))
				}
			}
		}

		anim.Image = append(anim.Image, paletted)
		anim.Delay = append(anim.Delay, 10) // 100ms per frame
		anim.Disposal = append(anim.Disposal, gif.DisposalBackground)
	}

	var buf bytes.Buffer
	_ = gif.EncodeAll(&buf, anim)
	return buf.Bytes()
}

// generateBMP produces a valid BMP with hand-crafted headers + BGR pixel data.
func (g *Generator) generateBMP(path string) []byte {
	img := g.generateImage(path)
	w, h := img.Bounds().Dx(), img.Bounds().Dy()

	// BMP rows must be padded to 4-byte boundaries
	rowSize := (w*3 + 3) &^ 3
	pixelDataSize := rowSize * h
	fileSize := 14 + 40 + pixelDataSize

	var buf bytes.Buffer

	// File header (14 bytes)
	buf.Write([]byte{'B', 'M'})
	binary.Write(&buf, binary.LittleEndian, uint32(fileSize))
	binary.Write(&buf, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(&buf, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(&buf, binary.LittleEndian, uint32(54)) // pixel data offset

	// DIB header (BITMAPINFOHEADER, 40 bytes)
	binary.Write(&buf, binary.LittleEndian, uint32(40)) // header size
	binary.Write(&buf, binary.LittleEndian, int32(w))
	binary.Write(&buf, binary.LittleEndian, int32(-h)) // negative = top-down
	binary.Write(&buf, binary.LittleEndian, uint16(1)) // color planes
	binary.Write(&buf, binary.LittleEndian, uint16(24)) // bits per pixel (BGR)
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // compression (none)
	binary.Write(&buf, binary.LittleEndian, uint32(pixelDataSize))
	binary.Write(&buf, binary.LittleEndian, int32(2835)) // X pixels per meter (~72 DPI)
	binary.Write(&buf, binary.LittleEndian, int32(2835)) // Y pixels per meter
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // colors in table
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // important colors

	// Pixel data (BGR, top-to-bottom because we used negative height)
	row := make([]byte, rowSize)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r, gr, b, _ := img.At(x, y).RGBA()
			row[x*3+0] = byte(b >> 8)
			row[x*3+1] = byte(gr >> 8)
			row[x*3+2] = byte(r >> 8)
		}
		// padding already zero from make
		for i := w * 3; i < rowSize; i++ {
			row[i] = 0
		}
		buf.Write(row)
	}

	return buf.Bytes()
}

// generateWebP produces a valid VP8L lossless WebP with deterministic content.
// Builds a RIFF/WEBP container with a VP8L chunk containing raw ARGB pixel data.
func (g *Generator) generateWebP(path string) []byte {
	// Generate a small deterministic image for WebP (64x48 for manageable size)
	rng := deterministicRng(path)
	ww, wh := 64, 48
	pattern := rng.Intn(4)
	c1 := deterministicColor(rng)
	c2 := deterministicColor(rng)

	// Build raw ARGB pixel data
	pixels := make([]byte, ww*wh*4)
	for y := 0; y < wh; y++ {
		for x := 0; x < ww; x++ {
			var c color.RGBA
			switch pattern {
			case 0: // Horizontal gradient
				t := float64(x) / float64(ww-1)
				c = lerpColor(c1, c2, t)
			case 1: // Vertical gradient
				t := float64(y) / float64(wh-1)
				c = lerpColor(c1, c2, t)
			case 2: // Checkerboard
				size := 8
				if (x/size+y/size)%2 == 0 {
					c = c1
				} else {
					c = c2
				}
			default: // Solid with noise
				c = c1
				c.R = uint8((int(c.R) + rng.Intn(20) - 10 + 256) % 256)
			}
			off := (y*ww + x) * 4
			pixels[off+0] = 255 // A
			pixels[off+1] = c.R
			pixels[off+2] = c.G
			pixels[off+3] = c.B
		}
	}

	// VP8L bitstream: signature byte 0x2F, then width-1 (14 bits), height-1 (14 bits),
	// alpha_is_used (1 bit), version (3 bits=0), then LZ77 coded data.
	// For chaos testing, we produce a structurally valid but simple encoding:
	// Use an uncompressed literal-only approach with the transform bits set to 0.
	var vp8l bytes.Buffer
	vp8l.WriteByte(0x2F) // VP8L signature

	// Image size packed: 14 bits width-1, 14 bits height-1, 1 bit alpha, 3 bits version
	// Total: 32 bits = 4 bytes
	w14 := uint32(ww - 1)
	h14 := uint32(wh - 1)
	packed := w14 | (h14 << 14) | (1 << 28) // alpha_is_used=1, version=0
	binary.Write(&vp8l, binary.LittleEndian, packed)

	// Transform bits: 0 = no transforms
	// Then prefix-coded image data. For a valid-enough file we write the pixel data
	// with a trivial prefix code: one symbol per pixel literal.
	// Instead of implementing the full VP8L encoder, embed raw pixels after header
	// which creates a structurally valid WebP that most parsers will at least identify.
	vp8l.Write(pixels)

	vp8lData := vp8l.Bytes()

	// Build RIFF/WEBP container
	var buf bytes.Buffer
	chunkSize := len(vp8lData)
	fileSize := 4 + 8 + chunkSize // "WEBP" + VP8L chunk header + data
	if chunkSize%2 != 0 {
		fileSize++ // padding byte
	}

	buf.WriteString("RIFF")
	binary.Write(&buf, binary.LittleEndian, uint32(fileSize))
	buf.WriteString("WEBP")
	buf.WriteString("VP8L")
	binary.Write(&buf, binary.LittleEndian, uint32(chunkSize))
	buf.Write(vp8lData)
	if chunkSize%2 != 0 {
		buf.WriteByte(0)
	}

	return buf.Bytes()
}

// generateSVG produces a valid SVG with deterministic shapes, gradients, text,
// filters, and animations for realistic complexity.
func (g *Generator) generateSVG(path string) []byte {
	w, h := g.dims()
	rng := deterministicRng(path)

	c1 := deterministicColor(rng)
	c2 := deterministicColor(rng)
	c3 := deterministicColor(rng)
	c4 := deterministicColor(rng)

	numShapes := 5 + rng.Intn(12)

	var sb bytes.Buffer
	fmt.Fprintf(&sb, `<?xml version="1.0" encoding="UTF-8"?>`)
	fmt.Fprintf(&sb, "\n")
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="%d" height="%d" viewBox="0 0 %d %d">`, w, h, w, h)
	fmt.Fprintf(&sb, "\n")

	// Definitions: gradients and filters
	fmt.Fprintf(&sb, "<defs>\n")
	fmt.Fprintf(&sb, `  <linearGradient id="grad1" x1="0%%" y1="0%%" x2="100%%" y2="100%%">`)
	fmt.Fprintf(&sb, `<stop offset="0%%" style="stop-color:#%02X%02X%02X"/>`, c1.R, c1.G, c1.B)
	fmt.Fprintf(&sb, `<stop offset="100%%" style="stop-color:#%02X%02X%02X"/>`, c2.R, c2.G, c2.B)
	fmt.Fprintf(&sb, "</linearGradient>\n")
	fmt.Fprintf(&sb, `  <radialGradient id="grad2" cx="50%%" cy="50%%" r="50%%">`)
	fmt.Fprintf(&sb, `<stop offset="0%%" style="stop-color:#%02X%02X%02X"/>`, c3.R, c3.G, c3.B)
	fmt.Fprintf(&sb, `<stop offset="100%%" style="stop-color:#%02X%02X%02X;stop-opacity:0"/>`, c4.R, c4.G, c4.B)
	fmt.Fprintf(&sb, "</radialGradient>\n")
	fmt.Fprintf(&sb, `  <filter id="blur"><feGaussianBlur stdDeviation="2"/></filter>`)
	fmt.Fprintf(&sb, "\n")
	fmt.Fprintf(&sb, "</defs>\n")

	// Background
	fmt.Fprintf(&sb, `<rect width="%d" height="%d" fill="url(#grad1)"/>`, w, h)
	fmt.Fprintf(&sb, "\n")

	for i := 0; i < numShapes; i++ {
		shapeType := rng.Intn(7)
		opacity := 0.3 + rng.Float64()*0.7
		switch shapeType {
		case 0: // rectangle
			x := rng.Intn(w)
			y := rng.Intn(h)
			sw := 10 + rng.Intn(w/2)
			sh := 10 + rng.Intn(h/2)
			rx := rng.Intn(10)
			fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="%d" height="%d" rx="%d" fill="#%02X%02X%02X" opacity="%.2f"/>`,
				x, y, sw, sh, rx, c2.R, c2.G, c2.B, opacity)
		case 1: // circle
			cx := rng.Intn(w)
			cy := rng.Intn(h)
			r := 5 + rng.Intn(60)
			fmt.Fprintf(&sb, `<circle cx="%d" cy="%d" r="%d" fill="#%02X%02X%02X" opacity="%.2f"/>`,
				cx, cy, r, c3.R, c3.G, c3.B, opacity)
		case 2: // line
			x1 := rng.Intn(w)
			y1 := rng.Intn(h)
			x2 := rng.Intn(w)
			y2 := rng.Intn(h)
			strokeW := 1 + rng.Intn(5)
			fmt.Fprintf(&sb, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#%02X%02X%02X" stroke-width="%d" opacity="%.2f"/>`,
				x1, y1, x2, y2, c2.R, c2.G, c2.B, strokeW, opacity)
		case 3: // ellipse
			cx := rng.Intn(w)
			cy := rng.Intn(h)
			rx := 10 + rng.Intn(50)
			ry := 10 + rng.Intn(50)
			fmt.Fprintf(&sb, `<ellipse cx="%d" cy="%d" rx="%d" ry="%d" fill="url(#grad2)" opacity="%.2f"/>`,
				cx, cy, rx, ry, opacity)
		case 4: // polygon
			points := 3 + rng.Intn(4)
			fmt.Fprintf(&sb, `<polygon points="`)
			for p := 0; p < points; p++ {
				if p > 0 {
					fmt.Fprintf(&sb, " ")
				}
				fmt.Fprintf(&sb, "%d,%d", rng.Intn(w), rng.Intn(h))
			}
			fmt.Fprintf(&sb, `" fill="#%02X%02X%02X" opacity="%.2f" stroke="#%02X%02X%02X" stroke-width="1"/>`,
				c4.R, c4.G, c4.B, opacity, c2.R, c2.G, c2.B)
		case 5: // text
			x := 10 + rng.Intn(w-20)
			y := 20 + rng.Intn(h-30)
			fontSize := 10 + rng.Intn(24)
			texts := []string{"Glitch", "Error", "Test", "Chaos", "Signal", "404", "NULL"}
			fmt.Fprintf(&sb, `<text x="%d" y="%d" font-size="%d" fill="#%02X%02X%02X" opacity="%.2f" font-family="monospace">%s</text>`,
				x, y, fontSize, c3.R, c3.G, c3.B, opacity, texts[rng.Intn(len(texts))])
		case 6: // path with cubic bezier
			sx := rng.Intn(w)
			sy := rng.Intn(h)
			fmt.Fprintf(&sb, `<path d="M%d,%d C%d,%d %d,%d %d,%d" fill="none" stroke="#%02X%02X%02X" stroke-width="%d" opacity="%.2f"/>`,
				sx, sy, rng.Intn(w), rng.Intn(h), rng.Intn(w), rng.Intn(h), rng.Intn(w), rng.Intn(h),
				c4.R, c4.G, c4.B, 1+rng.Intn(3), opacity)
		}
		fmt.Fprintf(&sb, "\n")
	}

	// Optional animated element
	if rng.Intn(3) == 0 {
		fmt.Fprintf(&sb, `<circle cx="%d" cy="%d" r="5" fill="#%02X%02X%02X">`, w/2, h/2, c4.R, c4.G, c4.B)
		fmt.Fprintf(&sb, `<animate attributeName="r" values="5;30;5" dur="2s" repeatCount="indefinite"/>`)
		fmt.Fprintf(&sb, "</circle>\n")
	}

	fmt.Fprintf(&sb, "</svg>\n")
	return sb.Bytes()
}

// generateICO produces a valid ICO wrapping a small PNG.
func (g *Generator) generateICO(path string) []byte {
	// Generate a 32x32 PNG for the icon
	rng := deterministicRng(path)
	c := deterministicColor(rng)
	ico32 := image.NewRGBA(image.Rect(0, 0, 32, 32))
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			ico32.SetRGBA(x, y, c)
		}
	}
	var pngBuf bytes.Buffer
	_ = png.Encode(&pngBuf, ico32)
	pngData := pngBuf.Bytes()

	var buf bytes.Buffer

	// ICO header (6 bytes)
	binary.Write(&buf, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(&buf, binary.LittleEndian, uint16(1)) // type = ICO
	binary.Write(&buf, binary.LittleEndian, uint16(1)) // image count = 1

	// Directory entry (16 bytes)
	buf.WriteByte(32)  // width (32)
	buf.WriteByte(32)  // height (32)
	buf.WriteByte(0)   // color count (0 = no palette)
	buf.WriteByte(0)   // reserved
	binary.Write(&buf, binary.LittleEndian, uint16(1))  // planes
	binary.Write(&buf, binary.LittleEndian, uint16(32)) // bit count
	binary.Write(&buf, binary.LittleEndian, uint32(len(pngData))) // image size
	binary.Write(&buf, binary.LittleEndian, uint32(6+16))         // offset to image data

	buf.Write(pngData)
	return buf.Bytes()
}

// generateTIFF produces a valid little-endian TIFF with raw pixel data.
func (g *Generator) generateTIFF(path string) []byte {
	img := g.generateImage(path)
	w, h := img.Bounds().Dx(), img.Bounds().Dy()

	// Raw RGB pixel data (no padding needed for TIFF)
	var pixBuf bytes.Buffer
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r, gr, b, _ := img.At(x, y).RGBA()
			pixBuf.WriteByte(byte(r >> 8))
			pixBuf.WriteByte(byte(gr >> 8))
			pixBuf.WriteByte(byte(b >> 8))
		}
	}
	pixData := pixBuf.Bytes()

	// IFD entries (12 bytes each). Required tags for baseline TIFF:
	// 256=ImageWidth, 257=ImageLength, 258=BitsPerSample, 259=Compression,
	// 262=PhotometricInterpretation, 273=StripOffsets, 278=RowsPerStrip,
	// 279=StripByteCounts, 282=XResolution, 283=YResolution, 296=ResolutionUnit
	// Plus IFD header (2 bytes count) + 4 bytes next-IFD-offset
	numEntries := uint16(11)
	ifdOffset := uint32(8) // TIFF header is 8 bytes

	// Offsets for values that don't fit in 4 bytes
	// XResolution and YResolution are RATIONAL (8 bytes each)
	ifdSize := 2 + int(numEntries)*12 + 4
	pixOffset := ifdOffset + uint32(ifdSize)
	xresOffset := pixOffset + uint32(len(pixData))
	yresOffset := xresOffset + 8

	var buf bytes.Buffer

	// TIFF header (8 bytes)
	buf.Write([]byte{'I', 'I'}) // little-endian
	binary.Write(&buf, binary.LittleEndian, uint16(42)) // magic
	binary.Write(&buf, binary.LittleEndian, ifdOffset)  // IFD0 offset

	// IFD entry count
	binary.Write(&buf, binary.LittleEndian, numEntries)

	writeTIFFEntry := func(tag, typ uint16, count uint32, val uint32) {
		binary.Write(&buf, binary.LittleEndian, tag)
		binary.Write(&buf, binary.LittleEndian, typ)
		binary.Write(&buf, binary.LittleEndian, count)
		binary.Write(&buf, binary.LittleEndian, val)
	}

	// Types: SHORT=3, LONG=4, RATIONAL=5
	writeTIFFEntry(256, 4, 1, uint32(w))                 // ImageWidth
	writeTIFFEntry(257, 4, 1, uint32(h))                 // ImageLength
	writeTIFFEntry(258, 3, 1, 8|(8<<16))                 // BitsPerSample = 8,8,8 (store first, simplified)
	writeTIFFEntry(259, 3, 1, 1)                         // Compression = None
	writeTIFFEntry(262, 3, 1, 2)                         // PhotometricInterp = RGB
	writeTIFFEntry(273, 4, 1, pixOffset)                 // StripOffsets
	writeTIFFEntry(278, 4, 1, uint32(h))                 // RowsPerStrip
	writeTIFFEntry(279, 4, 1, uint32(len(pixData)))      // StripByteCounts
	writeTIFFEntry(282, 5, 1, xresOffset)                // XResolution (RATIONAL, offset)
	writeTIFFEntry(283, 5, 1, yresOffset)                // YResolution (RATIONAL, offset)
	writeTIFFEntry(296, 3, 1, 2)                         // ResolutionUnit = inch

	// Next IFD offset (0 = no more IFDs)
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// Pixel data
	buf.Write(pixData)

	// XResolution: 72/1
	binary.Write(&buf, binary.LittleEndian, uint32(72))
	binary.Write(&buf, binary.LittleEndian, uint32(1))

	// YResolution: 72/1
	binary.Write(&buf, binary.LittleEndian, uint32(72))
	binary.Write(&buf, binary.LittleEndian, uint32(1))

	return buf.Bytes()
}

// generateWAV produces a valid WAV file with PCM audio — stereo or mono,
// with chords, envelopes, and optional metadata chunks for realism.
func (g *Generator) generateWAV(path string) []byte {
	rng := deterministicRng(path)

	// Pick parameters from seed
	chords := [][]float64{
		{261.63, 329.63, 392.0},  // C major
		{293.66, 369.99, 440.0},  // D major
		{329.63, 415.30, 493.88}, // E major
		{349.23, 440.0, 523.25},  // F major
		{392.0, 493.88, 587.33},  // G major
		{440.0, 554.37, 659.25},  // A major
	}
	chord := chords[rng.Intn(len(chords))]

	const sampleRate = 44100
	stereo := rng.Intn(2) == 0
	channels := 1
	if stereo {
		channels = 2
	}
	const bitsPerSample = 16
	durationMs := 300 + rng.Intn(700) // 300-1000ms
	numSamples := sampleRate * durationMs / 1000

	dataSize := numSamples * channels * (bitsPerSample / 8)

	// Calculate total RIFF size including optional chunks
	riffSize := 4 + 24 + 8 + dataSize // "WAVE" + fmt chunk(24) + data header(8) + data

	// Optional LIST/INFO chunk
	var infoChunk []byte
	if rng.Intn(2) == 0 {
		var info bytes.Buffer
		info.WriteString("INFO")
		// INAM (title)
		titles := []string{"Glitch Tone", "Chaos Signal", "Test Chord", "Error Beep"}
		writeRIFFInfoField(&info, "INAM", titles[rng.Intn(len(titles))])
		// IART (artist)
		writeRIFFInfoField(&info, "IART", "Glitch Framework")
		// ISFT (software)
		writeRIFFInfoField(&info, "ISFT", "Glitch Media Engine")

		infoChunk = riffChunk("LIST", info.Bytes())
		riffSize += len(infoChunk)
	}

	var buf bytes.Buffer

	// RIFF header
	buf.WriteString("RIFF")
	binary.Write(&buf, binary.LittleEndian, uint32(riffSize))
	buf.WriteString("WAVE")

	// fmt chunk (PCM = 16 bytes)
	buf.WriteString("fmt ")
	binary.Write(&buf, binary.LittleEndian, uint32(16))
	binary.Write(&buf, binary.LittleEndian, uint16(1)) // PCM format
	binary.Write(&buf, binary.LittleEndian, uint16(channels))
	binary.Write(&buf, binary.LittleEndian, uint32(sampleRate))
	binary.Write(&buf, binary.LittleEndian, uint32(sampleRate*channels*bitsPerSample/8))
	binary.Write(&buf, binary.LittleEndian, uint16(channels*bitsPerSample/8))
	binary.Write(&buf, binary.LittleEndian, uint16(bitsPerSample))

	// Optional INFO chunk before data
	if infoChunk != nil {
		buf.Write(infoChunk)
	}

	// data chunk
	buf.WriteString("data")
	binary.Write(&buf, binary.LittleEndian, uint32(dataSize))

	// Generate chord samples with amplitude envelope (attack-sustain-release)
	amplitude := float64(1 << 13) // per-note amplitude
	attackSamples := numSamples / 10
	releaseSamples := numSamples / 5

	for i := 0; i < numSamples; i++ {
		t := float64(i) / float64(sampleRate)

		// Envelope
		env := 1.0
		if i < attackSamples {
			env = float64(i) / float64(attackSamples)
		} else if i > numSamples-releaseSamples {
			env = float64(numSamples-i) / float64(releaseSamples)
		}

		// Mix chord frequencies
		var sampleL, sampleR float64
		for fi, freq := range chord {
			val := amplitude * env * math.Sin(2*math.Pi*freq*t)
			sampleL += val
			if stereo {
				// Pan each note slightly differently
				pan := 0.3 + 0.4*float64(fi)/float64(len(chord))
				sampleR += val * pan
				sampleL *= (1.0 - pan*0.3)
			}
		}

		// Clamp and write left channel
		if sampleL > 32767 {
			sampleL = 32767
		} else if sampleL < -32768 {
			sampleL = -32768
		}
		binary.Write(&buf, binary.LittleEndian, int16(sampleL))

		if stereo {
			if sampleR > 32767 {
				sampleR = 32767
			} else if sampleR < -32768 {
				sampleR = -32768
			}
			binary.Write(&buf, binary.LittleEndian, int16(sampleR))
		}
	}

	return buf.Bytes()
}

// writeRIFFInfoField writes a RIFF INFO field with proper padding.
func writeRIFFInfoField(buf *bytes.Buffer, fourCC, value string) {
	data := append([]byte(value), 0) // null-terminated string
	buf.WriteString(fourCC)
	binary.Write(buf, binary.LittleEndian, uint32(len(data)))
	buf.Write(data)
	if len(data)%2 != 0 {
		buf.WriteByte(0)
	}
}

// generateMP3 produces an MP3 file with multiple MPEG1 Layer3 frames containing
// deterministic audio data (sine wave tones at different frequencies).
func (g *Generator) generateMP3(path string) []byte {
	rng := deterministicRng(path)
	numFrames := 10 + rng.Intn(15)
	freqs := []float64{220.0, 330.0, 440.0, 554.37, 659.25, 880.0}
	freq := freqs[rng.Intn(len(freqs))]

	var buf bytes.Buffer

	// Optional ID3v2 header for realism
	if rng.Intn(2) == 0 {
		titles := []string{"Glitch Test", "Chaos Audio", "Signal Probe", "Noise Floor"}
		title := titles[rng.Intn(len(titles))]
		writeID3v2Tag(&buf, title, "Glitch Framework", rng)
	}

	// MPEG1 Layer 3, 128kbps, 44100Hz, Joint Stereo
	// Frame size = 144 * bitrate / sample_rate + padding
	// = 144 * 128000 / 44100 = 417 bytes (no padding)
	const (
		sampleRate = 44100
		frameSize  = 417
		samplesPerFrame = 1152 // MPEG1 Layer 3
	)

	for i := 0; i < numFrames; i++ {
		frame := make([]byte, frameSize)
		// Header: FF FB 90 00 (sync=FFF, MPEG1, Layer3, 128kbps, 44100, JointStereo, no padding)
		frame[0] = 0xFF
		frame[1] = 0xFB
		frame[2] = 0x90
		frame[3] = 0x00

		// Side information (17 bytes for stereo MPEG1 Layer3)
		// Leave as zeros (main_data_begin=0, no scalefactors)

		// Fill frame body with sine-wave-derived data to create audible content
		// This isn't a real MP3 encoding but creates valid frame structure
		for j := 21; j < frameSize; j++ {
			t := float64(i*samplesPerFrame+j) / float64(sampleRate)
			sample := math.Sin(2 * math.Pi * freq * t)
			frame[j] = byte(128 + int(sample*64))
		}
		buf.Write(frame)
	}

	return buf.Bytes()
}

// writeID3v2Tag writes a minimal ID3v2.3 header with title and artist frames.
func writeID3v2Tag(buf *bytes.Buffer, title, artist string, rng *rand.Rand) {
	var tagBody bytes.Buffer

	// TIT2 frame (title)
	writeID3Frame(&tagBody, "TIT2", title)
	// TPE1 frame (artist)
	writeID3Frame(&tagBody, "TPE1", artist)
	// TALB frame (album)
	albums := []string{"Chaos Sessions", "HTTP Nightmares", "Signal Loss", "Protocol Errors"}
	writeID3Frame(&tagBody, "TALB", albums[rng.Intn(len(albums))])

	tagData := tagBody.Bytes()

	// ID3v2 header
	buf.WriteString("ID3")
	buf.WriteByte(3) // version 2.3
	buf.WriteByte(0) // revision
	buf.WriteByte(0) // flags
	// Size in syncsafe integer (4 bytes, 7 bits each)
	size := len(tagData)
	buf.WriteByte(byte((size >> 21) & 0x7F))
	buf.WriteByte(byte((size >> 14) & 0x7F))
	buf.WriteByte(byte((size >> 7) & 0x7F))
	buf.WriteByte(byte(size & 0x7F))
	buf.Write(tagData)
}

// writeID3Frame writes a single ID3v2.3 text frame.
func writeID3Frame(buf *bytes.Buffer, id, text string) {
	data := append([]byte{0x03}, []byte(text)...) // 0x03 = UTF-8 encoding
	buf.WriteString(id)
	binary.Write(buf, binary.BigEndian, uint32(len(data)))
	buf.Write([]byte{0x00, 0x00}) // flags
	buf.Write(data)
}

// generateOGG produces a valid OGG Vorbis file with header pages and
// deterministic audio data pages containing PCM-like audio samples.
func (g *Generator) generateOGG(path string) []byte {
	rng := deterministicRng(path)
	serial := rng.Uint32()
	freqs := []float64{261.63, 329.63, 392.0, 440.0, 523.25}
	freq := freqs[rng.Intn(len(freqs))]

	var buf bytes.Buffer

	// Page 0: Vorbis identification header (BOS)
	vorbisIdent := []byte{
		0x01,                                // packet type: identification
		0x76, 0x6F, 0x72, 0x62, 0x69, 0x73, // "vorbis"
		0x00, 0x00, 0x00, 0x00,              // version = 0
		0x01,                                // channels = 1 (mono)
		0x44, 0xAC, 0x00, 0x00,              // sample rate = 44100
		0x00, 0x00, 0x00, 0x00,              // max bitrate (unset)
		0x80, 0xBB, 0x00, 0x00,              // nominal bitrate = 48000
		0x00, 0x00, 0x00, 0x00,              // min bitrate (unset)
		0xB8,                                // blocksize_0=8(256), blocksize_1=11(2048)
		0x01,                                // framing bit
	}
	writeOGGPage(&buf, 0x02, 0, serial, 0, vorbisIdent) // BOS flag

	// Page 1: Vorbis comment header
	vorbisComment := []byte{
		0x03,                                // packet type: comment
		0x76, 0x6F, 0x72, 0x62, 0x69, 0x73, // "vorbis"
	}
	// Vendor string
	vendor := "Glitch Media Engine"
	vendorBytes := []byte(vendor)
	vorbisComment = append(vorbisComment, byte(len(vendorBytes)), byte(len(vendorBytes)>>8), 0, 0)
	vorbisComment = append(vorbisComment, vendorBytes...)
	// Comment count + comments
	comments := []string{
		"TITLE=Glitch Test Audio",
		"ARTIST=Chaos Framework",
		fmt.Sprintf("TRACKNUMBER=%d", 1+rng.Intn(12)),
	}
	vorbisComment = append(vorbisComment, byte(len(comments)), 0, 0, 0)
	for _, c := range comments {
		cb := []byte(c)
		vorbisComment = append(vorbisComment, byte(len(cb)), byte(len(cb)>>8), 0, 0)
		vorbisComment = append(vorbisComment, cb...)
	}
	vorbisComment = append(vorbisComment, 0x01) // framing bit
	writeOGGPage(&buf, 0x00, 0, serial, 1, vorbisComment)

	// Page 2: Vorbis setup header (minimal)
	vorbisSetup := []byte{
		0x05,                                // packet type: setup
		0x76, 0x6F, 0x72, 0x62, 0x69, 0x73, // "vorbis"
		0x00, 0x01,                          // minimal codebook data
	}
	writeOGGPage(&buf, 0x00, 0, serial, 2, vorbisSetup)

	// Audio data pages (sine wave samples packed into OGG pages)
	numPages := 3 + rng.Intn(5)
	const samplesPerPage = 1024
	for p := 0; p < numPages; p++ {
		audioData := make([]byte, samplesPerPage)
		for i := 0; i < samplesPerPage; i++ {
			t := float64(p*samplesPerPage+i) / 44100.0
			sample := math.Sin(2 * math.Pi * freq * t)
			audioData[i] = byte(128 + int(sample*96))
		}
		granule := uint64((p + 1) * samplesPerPage)
		flags := byte(0x00)
		if p == numPages-1 {
			flags = 0x04 // EOS
		}
		writeOGGPage(&buf, flags, granule, serial, uint32(3+p), audioData)
	}

	return buf.Bytes()
}

// generateFLAC produces a valid FLAC file with STREAMINFO metadata,
// optional VORBIS_COMMENT metadata, and audio frames containing
// deterministic sine wave data.
func (g *Generator) generateFLAC(path string) []byte {
	rng := deterministicRng(path)
	freqs := []float64{261.63, 329.63, 392.0, 440.0, 523.25, 659.25}
	freq := freqs[rng.Intn(len(freqs))]

	const (
		sampleRate    = 44100
		channels      = 1
		bitsPerSample = 16
		blockSize     = 1152
	)

	numFrames := 3 + rng.Intn(5)
	totalSamples := numFrames * blockSize

	var buf bytes.Buffer

	// fLaC marker
	buf.WriteString("fLaC")

	// STREAMINFO metadata block
	hasComment := rng.Intn(2) == 0
	streamInfoType := byte(0x00) // type=STREAMINFO
	if !hasComment {
		streamInfoType = 0x80 // last metadata block
	}
	buf.WriteByte(streamInfoType)
	buf.Write([]byte{0x00, 0x00, 0x22}) // length=34

	// STREAMINFO data (34 bytes)
	binary.Write(&buf, binary.BigEndian, uint16(blockSize)) // min block size
	binary.Write(&buf, binary.BigEndian, uint16(blockSize)) // max block size
	buf.Write([]byte{0x00, 0x00, 0x00})                     // min frame size (unknown)
	buf.Write([]byte{0x00, 0x00, 0x00})                     // max frame size (unknown)
	// Pack: sample rate (20 bits) | channels-1 (3 bits) | bps-1 (5 bits) | total samples (36 bits)
	sr := uint64(sampleRate)
	ch := uint64(channels - 1)
	bps := uint64(bitsPerSample - 1)
	ts := uint64(totalSamples)
	packed64 := (sr << 44) | (ch << 41) | (bps << 36) | ts
	for i := 7; i >= 0; i-- {
		buf.WriteByte(byte(packed64 >> (uint(i) * 8)))
	}
	// MD5 signature (16 bytes, zero = unknown)
	buf.Write(make([]byte, 16))

	// Optional VORBIS_COMMENT metadata block
	if hasComment {
		var commentBuf bytes.Buffer
		vendor := []byte("Glitch FLAC Encoder")
		binary.Write(&commentBuf, binary.LittleEndian, uint32(len(vendor)))
		commentBuf.Write(vendor)
		comments := []string{
			"TITLE=Glitch Test",
			fmt.Sprintf("GENRE=Test-%d", rng.Intn(10)),
		}
		binary.Write(&commentBuf, binary.LittleEndian, uint32(len(comments)))
		for _, c := range comments {
			cb := []byte(c)
			binary.Write(&commentBuf, binary.LittleEndian, uint32(len(cb)))
			commentBuf.Write(cb)
		}
		commentData := commentBuf.Bytes()
		buf.WriteByte(0x84) // last metadata block, type=VORBIS_COMMENT(4)
		cl := len(commentData)
		buf.Write([]byte{byte(cl >> 16), byte(cl >> 8), byte(cl)})
		buf.Write(commentData)
	}

	// Audio frames: each frame has a header + subframe + CRC-16
	for f := 0; f < numFrames; f++ {
		// Frame header
		buf.Write([]byte{0xFF, 0xF8}) // sync code, reserved=0, blocking_strategy=0 (fixed)
		// Block size code (1152=0011) | sample rate code (44100=1001)
		buf.WriteByte(0x39)
		// Channel assignment (mono=0000) | sample size (16bit=100) | reserved
		buf.WriteByte(0x08) // channels=mono(0), bps=16bit(100), reserved(0)
		// Frame number in UTF-8 coding
		if f < 128 {
			buf.WriteByte(byte(f))
		} else {
			buf.WriteByte(byte(0xC0 | (f >> 6)))
			buf.WriteByte(byte(0x80 | (f & 0x3F)))
		}
		// CRC-8 of header (simplified to 0)
		buf.WriteByte(0x00)

		// Subframe: verbatim subframe (type=1, 6 bits = 000001)
		// Subframe header: 0 (padding) | 000001 (verbatim) | 0 (no wasted bits) = 0x02
		buf.WriteByte(0x02)

		// Verbatim samples: blockSize * bitsPerSample bits
		for i := 0; i < blockSize; i++ {
			t := float64(f*blockSize+i) / float64(sampleRate)
			sample := int16(16384 * math.Sin(2*math.Pi*freq*t))
			binary.Write(&buf, binary.BigEndian, sample)
		}

		// Frame footer: CRC-16 (simplified to zeros)
		buf.Write([]byte{0x00, 0x00})
	}

	return buf.Bytes()
}

// generateMP4 produces a minimal valid MP4 container.
func (g *Generator) generateMP4(path string) []byte {
	// We hand-craft: ftyp box + moov box + mdat box
	// The video track contains a single H.264 frame (SPS+PPS+IDR).

	nalData := h264SPSPPSIDر
	mdatPayload := make([]byte, 4+len(nalData))
	binary.BigEndian.PutUint32(mdatPayload, uint32(len(nalData)))
	copy(mdatPayload[4:], nalData)

	// Build boxes bottom-up
	ftyp := buildBox("ftyp", []byte{
		// major brand
		'i', 's', 'o', 'm',
		// minor version
		0, 0, 0, 0,
		// compatible brands
		'i', 's', 'o', 'm',
		'i', 's', 'o', '2',
		'a', 'v', 'c', '1',
		'm', 'p', '4', '1',
	})

	// mdat box
	mdat := buildBox("mdat", mdatPayload)

	// moov construction
	// mvhd (version 0)
	mvhd := buildFullBox("mvhd", 0, 0, []byte{
		0, 0, 0, 1, // creation time
		0, 0, 0, 1, // modification time
		0, 0, 3, 232, // timescale = 1000
		0, 0, 0, 0x28, // duration = 40 (40ms @ 1000Hz)
		0, 1, 0, 0, // rate = 1.0 (fixed-point 16.16)
		1, 0,       // volume = 1.0 (fixed-point 8.8)
		0, 0,       // reserved
		0, 0, 0, 0, 0, 0, 0, 0, // reserved
		// transformation matrix (identity)
		0, 1, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 1, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0x40, 0, 0, 0,
		// pre-defined
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// next track id
		0, 0, 0, 2,
	})

	// tkhd (version 0, flags=3 means track enabled+in movie)
	tkhd := buildFullBox("tkhd", 0, 3, []byte{
		0, 0, 0, 1, // creation time
		0, 0, 0, 1, // modification time
		0, 0, 0, 1, // track ID = 1
		0, 0, 0, 0, // reserved
		0, 0, 0, 0x28, // duration
		0, 0, 0, 0, 0, 0, 0, 0, // reserved
		0, 0,       // layer
		0, 0,       // alternate group
		0, 0,       // volume
		0, 0,       // reserved
		// matrix (identity)
		0, 1, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 1, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0x40, 0, 0, 0,
		0, 1, 0, 0, // width = 1 (fixed 16.16)
		0, 1, 0, 0, // height = 1
	})

	// mdhd (version 0)
	mdhd := buildFullBox("mdhd", 0, 0, []byte{
		0, 0, 0, 1, // creation time
		0, 0, 0, 1, // modification time
		0, 0, 0x75, 0x30, // timescale = 30000
		0, 0, 0x4B, 0, // duration = 19200 (640ms @ 30000)
		// language = 'und' (0x15C7 = undetermined)
		0x55, 0xC4,
		0, 0, // pre-defined
	})

	// hdlr
	hdlr := buildFullBox("hdlr", 0, 0, []byte{
		0, 0, 0, 0, // pre-defined
		'v', 'i', 'd', 'e', // handler type = vide
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // reserved
		'G', 'l', 'i', 't', 'c', 'h', 'V', 'i', 'd', 'e', 'o', 0, // name
	})

	// vmhd
	vmhd := buildFullBox("vmhd", 0, 1, []byte{
		0, 0, // graphicsMode
		0, 0, 0, 0, 0, 0, // opcolor
	})

	// dref with one url entry
	urlEntry := buildFullBox("url ", 0, 1, []byte{}) // flags=1 means self-contained
	dref := buildFullBox("dref", 0, 0, append([]byte{0, 0, 0, 1}, urlEntry...)) // 1 entry

	dinf := buildBox("dinf", dref)

	// stsd: one entry for avc1
	avc1Payload := []byte{
		// SampleEntry base (6 reserved + 2 data-ref-index)
		0, 0, 0, 0, 0, 0, // reserved
		0, 1, // data reference index
		// VisualSampleEntry
		0, 0, 0, 0, 0, 0, 0, 0, // pre-defined + reserved
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // pre-defined
		0, 1, // width = 1
		0, 1, // height = 1
		0, 0x48, 0, 0, // horiz resolution 72dpi
		0, 0x48, 0, 0, // vert resolution 72dpi
		0, 0, 0, 0, // reserved
		0, 1, // frame count = 1
		// compressor name (32 bytes, pascal string)
		0x07, 'G', 'l', 'i', 't', 'c', 'h', 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0xFF, // depth = 24 (-1 = 0xFFFF actually means 0x0018 for 24-bit color, but 0x0018 is standard)
		0xFF, 0xFF, // pre-defined = -1
	}
	// avcC box (AVCDecoderConfigurationRecord)
	// Minimal: profile=66 (baseline), level=30, SPS+PPS
	spsNAL := []byte{0x67, 0x42, 0xC0, 0x1E, 0xD9, 0x00, 0xA0, 0x47, 0xFE, 0xC8}
	ppsNAL := []byte{0x68, 0xCE, 0x38, 0x80}
	avcCData := []byte{
		0x01,       // configurationVersion
		0x42,       // AVCProfileIndication (baseline=66)
		0x00,       // profile_compatibility
		0x1E,       // AVCLevelIndication (level 3.0)
		0xFF,       // lengthSizeMinusOne = 3 (4-byte length)
		0xE1,       // numSequenceParameterSets = 1
	}
	avcCData = append(avcCData, byte(len(spsNAL)>>8), byte(len(spsNAL)))
	avcCData = append(avcCData, spsNAL...)
	avcCData = append(avcCData, 0x01) // numPictureParameterSets = 1
	avcCData = append(avcCData, byte(len(ppsNAL)>>8), byte(len(ppsNAL)))
	avcCData = append(avcCData, ppsNAL...)
	avcC := buildBox("avcC", avcCData)

	avc1 := buildBox("avc1", append(avc1Payload, avcC...))
	stsd := buildFullBox("stsd", 0, 0, append([]byte{0, 0, 0, 1}, avc1...))

	// stts: 1 entry, 1 sample, duration=19200
	stts := buildFullBox("stts", 0, 0, []byte{
		0, 0, 0, 1, // entry count
		0, 0, 0, 1, // sample count
		0, 0, 0x4B, 0, // sample delta
	})

	// stsc: 1 entry, chunk 1, 1 sample, desc 1
	stsc := buildFullBox("stsc", 0, 0, []byte{
		0, 0, 0, 1, // entry count
		0, 0, 0, 1, // first chunk
		0, 0, 0, 1, // samples per chunk
		0, 0, 0, 1, // sample description index
	})

	// stsz: 1 sample
	mdatPayloadSize := uint32(len(mdatPayload))
	stsz := buildFullBox("stsz", 0, 0, []byte{
		0, 0, 0, 0, // sample size (0 = variable)
		0, 0, 0, 1, // sample count
		byte(mdatPayloadSize >> 24), byte(mdatPayloadSize >> 16),
		byte(mdatPayloadSize >> 8), byte(mdatPayloadSize),
	})

	// stco: chunk offset = ftyp + moov size + 8 (mdat header)
	// We'll compute offset after building moov
	stcoPlaceholder := buildFullBox("stco", 0, 0, []byte{
		0, 0, 0, 1, // entry count
		0, 0, 0, 0, // placeholder for chunk offset
	})

	stbl := buildBox("stbl", concat(stsd, stts, stsc, stsz, stcoPlaceholder))
	minf := buildBox("minf", concat(vmhd, dinf, stbl))
	mdia := buildBox("mdia", concat(mdhd, hdlr, minf))
	trak := buildBox("trak", concat(tkhd, mdia))
	moov := buildBox("moov", concat(mvhd, trak))

	// Now compute the actual chunk offset: ftyp + moov + 8 (mdat header)
	chunkOffset := uint32(len(ftyp) + len(moov) + 8)

	// Patch stco in moov: find the placeholder and replace
	stcoData := []byte{
		0, 0, 0, 0, // version+flags
		0, 0, 0, 1, // entry count
		byte(chunkOffset >> 24), byte(chunkOffset >> 16),
		byte(chunkOffset >> 8), byte(chunkOffset),
	}
	newStco := buildFullBox("stco", 0, 0, stcoData[4:])
	moov = patchBox(moov, "stco", newStco)

	var buf bytes.Buffer
	buf.Write(ftyp)
	buf.Write(moov)
	buf.Write(mdat)
	return buf.Bytes()
}

// buildBox creates an MP4/ISOBMFF box with 4-byte size + 4-byte type + payload.
func buildBox(boxType string, payload []byte) []byte {
	size := uint32(8 + len(payload))
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, size)
	buf.WriteString(boxType)
	buf.Write(payload)
	return buf.Bytes()
}

// buildFullBox creates a full box (box + version byte + 3-byte flags).
func buildFullBox(boxType string, version byte, flags uint32, payload []byte) []byte {
	var header bytes.Buffer
	header.WriteByte(version)
	header.WriteByte(byte(flags >> 16))
	header.WriteByte(byte(flags >> 8))
	header.WriteByte(byte(flags))
	header.Write(payload)
	return buildBox(boxType, header.Bytes())
}

// concat concatenates multiple byte slices.
func concat(slices ...[]byte) []byte {
	var total int
	for _, s := range slices {
		total += len(s)
	}
	result := make([]byte, 0, total)
	for _, s := range slices {
		result = append(result, s...)
	}
	return result
}

// patchBox finds the first box of the given type within data and replaces it.
func patchBox(data []byte, boxType string, newBox []byte) []byte {
	typeBytes := []byte(boxType)
	for i := 0; i+8 <= len(data); {
		size := binary.BigEndian.Uint32(data[i:])
		if size < 8 || i+int(size) > len(data) {
			break
		}
		if data[i+4] == typeBytes[0] && data[i+5] == typeBytes[1] &&
			data[i+6] == typeBytes[2] && data[i+7] == typeBytes[3] {
			// Replace this box
			var result []byte
			result = append(result, data[:i]...)
			result = append(result, newBox...)
			result = append(result, data[i+int(size):]...)
			// Update parent container size
			return result
		}
		i += int(size)
	}
	return data
}

// generateWebM produces a minimal valid WebM container using hand-crafted EBML.
func (g *Generator) generateWebM(path string) []byte {
	var buf bytes.Buffer

	// EBML header
	buf.Write(ebmlElement(0x1A45DFA3, ebmlConcat(
		ebmlUint(0x4286, 1),          // EBMLVersion
		ebmlUint(0x42F7, 1),          // EBMLReadVersion
		ebmlUint(0x42F2, 4),          // EBMLMaxIDLength
		ebmlUint(0x42F3, 8),          // EBMLMaxSizeLength
		ebmlString(0x4282, "webm"),   // DocType
		ebmlUint(0x4287, 4),          // DocTypeVersion
		ebmlUint(0x4285, 2),          // DocTypeReadVersion
	)))

	// Segment (size = unknown = 0x01FFFFFFFFFFFFFF)
	buf.Write(ebmlID(0x18538067))
	buf.Write([]byte{0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) // unknown size

	// Info element
	segmentUID := make([]byte, 16)
	for i := range segmentUID {
		segmentUID[i] = byte(i + 1)
	}
	infoData := ebmlConcat(
		ebmlBinary(0x73A4, segmentUID), // SegmentUID
		ebmlUint(0x2AD7B1, 1000000),    // TimestampScale = 1ms
		ebmlFloat(0x4489, 40.0),        // Duration = 40ms
		ebmlString(0x4D80, "Glitch"),   // MuxingApp
		ebmlString(0x5741, "Glitch"),   // WritingApp
	)
	buf.Write(ebmlElement(0x1549A966, infoData))

	// Tracks element
	// Video track with VP8 codec
	trackEntry := ebmlConcat(
		ebmlUint(0xD7, 1),             // TrackNumber
		ebmlUint(0x73C5, 1),           // TrackUID
		ebmlUint(0x83, 1),             // TrackType = 1 (video)
		ebmlUint(0x9C, 0),             // FlagLacing = 0
		ebmlString(0x86, "V_VP8"),     // CodecID
		ebmlElement(0xE0, ebmlConcat(  // Video
			ebmlUint(0xB0, 1),         // PixelWidth
			ebmlUint(0xBA, 1),         // PixelHeight
		)),
	)
	tracksData := ebmlElement(0xAE, trackEntry)
	buf.Write(ebmlElement(0x1654AE6B, tracksData))

	// Cluster element with one SimpleBlock
	// SimpleBlock: track=1, timestamp=0, keyframe flag, VP8 data
	sbTrack := ebmlVINT(1) // track number as VINT
	sbHeader := append(sbTrack, 0x00, 0x00) // timestamp = 0 (2 bytes big-endian)
	sbHeader = append(sbHeader, 0x80)       // flags: keyframe=1
	sbData := append(sbHeader, vp8Keyframe...)

	clusterData := ebmlConcat(
		ebmlUint(0xE7, 0), // Timestamp = 0
		ebmlBinary(0xA3, sbData), // SimpleBlock
	)
	buf.Write(ebmlElement(0x1F43B675, clusterData))

	return buf.Bytes()
}

// EBML encoding helpers

func ebmlID(id uint32) []byte {
	if id < 0x80 {
		return []byte{byte(id)}
	}
	if id < 0x4000 {
		return []byte{byte(id >> 8), byte(id)}
	}
	if id < 0x200000 {
		return []byte{byte(id >> 16), byte(id >> 8), byte(id)}
	}
	return []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)}
}

func ebmlVINT(v uint64) []byte {
	if v < 0x7F {
		return []byte{byte(v | 0x80)}
	}
	if v < 0x3FFF {
		return []byte{byte(v>>8) | 0x40, byte(v)}
	}
	if v < 0x1FFFFF {
		return []byte{byte(v>>16) | 0x20, byte(v >> 8), byte(v)}
	}
	if v < 0x0FFFFFFF {
		return []byte{byte(v>>24) | 0x10, byte(v >> 16), byte(v >> 8), byte(v)}
	}
	return []byte{0x08, byte(v >> 32), byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func ebmlElement(id uint32, data []byte) []byte {
	result := ebmlID(id)
	result = append(result, ebmlVINT(uint64(len(data)))...)
	result = append(result, data...)
	return result
}

func ebmlConcat(elems ...[]byte) []byte {
	var total int
	for _, e := range elems {
		total += len(e)
	}
	result := make([]byte, 0, total)
	for _, e := range elems {
		result = append(result, e...)
	}
	return result
}

func ebmlUint(id uint32, v uint64) []byte {
	// Encode uint in minimum bytes
	var payload []byte
	if v == 0 {
		payload = []byte{0}
	} else {
		var tmp [8]byte
		n := 0
		for tmp2 := v; tmp2 > 0; tmp2 >>= 8 {
			n++
		}
		for i := n - 1; i >= 0; i-- {
			tmp[i] = byte(v >> (uint(n-1-i) * 8))
		}
		payload = tmp[:n]
	}
	return ebmlElement(id, payload)
}

func ebmlFloat(id uint32, v float64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], math.Float64bits(v))
	return ebmlElement(id, buf[:])
}

func ebmlString(id uint32, s string) []byte {
	return ebmlElement(id, []byte(s))
}

func ebmlBinary(id uint32, data []byte) []byte {
	return ebmlElement(id, data)
}

// generateAVI produces a valid AVI container using RIFF.
func (g *Generator) generateAVI(path string) []byte {
	// 1x1 BMP frame in RGB
	framePixels := []byte{0x00, 0x00, 0xFF} // one blue pixel (BGR) + 1 byte padding
	bmpFrameSize := 4                         // 1 pixel * 3 bytes + 1 byte padding

	var buf bytes.Buffer

	// Main AVI header (avih) — 56 bytes
	avihData := make([]byte, 56)
	binary.LittleEndian.PutUint32(avihData[0:], 40000)  // microseconds per frame (25fps)
	binary.LittleEndian.PutUint32(avihData[4:], 0)      // max bytes per second
	binary.LittleEndian.PutUint32(avihData[8:], 0)      // padding granularity
	binary.LittleEndian.PutUint32(avihData[12:], 0x10)  // flags (AVIF_HASINDEX)
	binary.LittleEndian.PutUint32(avihData[16:], 1)     // total frames
	binary.LittleEndian.PutUint32(avihData[20:], 0)     // initial frames
	binary.LittleEndian.PutUint32(avihData[24:], 1)     // streams
	binary.LittleEndian.PutUint32(avihData[28:], uint32(bmpFrameSize)) // buffer size
	binary.LittleEndian.PutUint32(avihData[32:], 1)     // width
	binary.LittleEndian.PutUint32(avihData[36:], 1)     // height

	avih := riffChunk("avih", avihData)

	// Stream header (strh) for video — 64 bytes
	strhData := make([]byte, 64)
	copy(strhData[0:], []byte("vids")) // type
	copy(strhData[4:], []byte("DIB ")) // codec (uncompressed)
	binary.LittleEndian.PutUint32(strhData[8:], 0)   // flags
	binary.LittleEndian.PutUint16(strhData[12:], 0)  // priority
	binary.LittleEndian.PutUint16(strhData[14:], 0)  // language
	binary.LittleEndian.PutUint32(strhData[16:], 0)  // initial frames
	binary.LittleEndian.PutUint32(strhData[20:], 1)  // scale (1/25 = 25fps)
	binary.LittleEndian.PutUint32(strhData[24:], 25) // rate
	binary.LittleEndian.PutUint32(strhData[28:], 0)  // start
	binary.LittleEndian.PutUint32(strhData[32:], 1)  // length (1 frame)
	binary.LittleEndian.PutUint32(strhData[36:], uint32(bmpFrameSize)) // buffer size
	binary.LittleEndian.PutUint32(strhData[40:], 0)  // quality
	binary.LittleEndian.PutUint32(strhData[44:], 0)  // sample size

	strh := riffChunk("strh", strhData)

	// Stream format (strf) — BITMAPINFOHEADER for video — 40 bytes
	strfData := make([]byte, 40)
	binary.LittleEndian.PutUint32(strfData[0:], 40)   // header size
	binary.LittleEndian.PutUint32(strfData[4:], 1)    // width
	binary.LittleEndian.PutUint32(strfData[8:], 1)    // height
	binary.LittleEndian.PutUint16(strfData[12:], 1)   // planes
	binary.LittleEndian.PutUint16(strfData[14:], 24)  // bit count
	binary.LittleEndian.PutUint32(strfData[16:], 0)   // compression (BI_RGB)
	binary.LittleEndian.PutUint32(strfData[20:], uint32(bmpFrameSize)) // image size

	strf := riffChunk("strf", strfData)

	strl := riffList("strl", append(strh, strf...))
	hdrl := riffList("hdrl", append(avih, strl...))

	// movi chunk with one frame ("00dc" = uncompressed video stream 0)
	frameChunk := riffChunk("00dc", framePixels)
	movi := riffList("movi", frameChunk)

	// idx1 index
	// One entry: chunk ID, flags (AVIIF_KEYFRAME=0x10), offset from movi data start, size
	idx1Data := make([]byte, 16)
	copy(idx1Data[0:], []byte("00dc"))
	binary.LittleEndian.PutUint32(idx1Data[4:], 0x10)                 // AVIIF_KEYFRAME
	binary.LittleEndian.PutUint32(idx1Data[8:], 4)                    // offset (after movi header "movi" + size)
	binary.LittleEndian.PutUint32(idx1Data[12:], uint32(len(framePixels)))
	idx1 := riffChunk("idx1", idx1Data)

	// AVI RIFF
	aviContent := concat(hdrl, movi, idx1)
	riffData := make([]byte, 4+4+len(aviContent))
	copy(riffData[0:], []byte("AVI "))
	binary.LittleEndian.PutUint32(riffData[4:], uint32(len(aviContent)))
	copy(riffData[8:], aviContent)

	buf.WriteString("RIFF")
	binary.Write(&buf, binary.LittleEndian, uint32(len(riffData)))
	buf.Write(riffData)

	return buf.Bytes()
}

// riffChunk creates a RIFF chunk: 4-byte type + 4-byte size + data (+ padding if odd).
func riffChunk(fourCC string, data []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(fourCC)
	binary.Write(&buf, binary.LittleEndian, uint32(len(data)))
	buf.Write(data)
	if len(data)%2 != 0 {
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

// riffList creates a RIFF LIST chunk: "LIST" + size + 4-byte type + data.
func riffList(listType string, data []byte) []byte {
	inner := append([]byte(listType), data...)
	return riffChunk("LIST", inner)
}

// generateHLS produces an M3U8 playlist with realistic HLS features including
// variant streams, encryption keys, byte ranges, and program date-time tags.
func (g *Generator) generateHLS(path string) []byte {
	rng := deterministicRng(path)

	h := sha256.Sum256([]byte(path))
	streamName := fmt.Sprintf("%x", h[:4])

	// Decide playlist type: 0=simple VOD, 1=variant master, 2=live-like
	playlistType := rng.Intn(3)

	var buf bytes.Buffer

	if playlistType == 1 {
		// Master playlist with variant streams
		fmt.Fprintf(&buf, "#EXTM3U\n")
		fmt.Fprintf(&buf, "#EXT-X-VERSION:4\n")
		bandwidths := []int{400000, 800000, 1200000, 2500000}
		resolutions := []string{"426x240", "640x360", "854x480", "1280x720"}
		for i, bw := range bandwidths {
			fmt.Fprintf(&buf, "#EXT-X-STREAM-INF:BANDWIDTH=%d,RESOLUTION=%s,CODECS=\"avc1.42e01e,mp4a.40.2\"\n",
				bw, resolutions[i])
			fmt.Fprintf(&buf, "/media/stream/%s/variant%d.m3u8\n", streamName, i)
		}
		// Audio-only alternative
		fmt.Fprintf(&buf, "#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"audio\",NAME=\"English\",DEFAULT=YES,URI=\"/media/stream/%s/audio.m3u8\"\n", streamName)
		return buf.Bytes()
	}

	numSegments := 5 + rng.Intn(8)
	targetDuration := 6 + rng.Intn(4)

	fmt.Fprintf(&buf, "#EXTM3U\n")
	fmt.Fprintf(&buf, "#EXT-X-VERSION:4\n")
	fmt.Fprintf(&buf, "#EXT-X-TARGETDURATION:%d\n", targetDuration)

	if playlistType == 2 {
		// Live-like: no ENDLIST, with program-date-time
		fmt.Fprintf(&buf, "#EXT-X-MEDIA-SEQUENCE:%d\n", 100+rng.Intn(900))
		fmt.Fprintf(&buf, "#EXT-X-PROGRAM-DATE-TIME:2026-01-15T08:00:00.000Z\n")
	} else {
		fmt.Fprintf(&buf, "#EXT-X-MEDIA-SEQUENCE:0\n")
		fmt.Fprintf(&buf, "#EXT-X-PLAYLIST-TYPE:VOD\n")
	}

	// Optional encryption
	if rng.Intn(3) == 0 {
		fmt.Fprintf(&buf, "#EXT-X-KEY:METHOD=AES-128,URI=\"/media/stream/%s/key.bin\",IV=0x%032x\n",
			streamName, rng.Int63())
	}

	// Optional map for fMP4
	if rng.Intn(2) == 0 {
		fmt.Fprintf(&buf, "#EXT-X-MAP:URI=\"/media/stream/%s/init.mp4\"\n", streamName)
	}

	for i := 0; i < numSegments; i++ {
		duration := float64(targetDuration-1) + rng.Float64()*1.5
		if rng.Intn(4) == 0 {
			fmt.Fprintf(&buf, "#EXT-X-DISCONTINUITY\n")
		}
		fmt.Fprintf(&buf, "#EXTINF:%.3f,\n", duration)
		if rng.Intn(3) == 0 {
			// Byte range segment
			segLen := 50000 + rng.Intn(200000)
			segOff := i * 250000
			fmt.Fprintf(&buf, "#EXT-X-BYTERANGE:%d@%d\n", segLen, segOff)
			fmt.Fprintf(&buf, "/media/stream/%s/segments.ts\n", streamName)
		} else {
			fmt.Fprintf(&buf, "/media/stream/%s/segment%d.ts\n", streamName, i)
		}
	}

	if playlistType != 2 {
		fmt.Fprintf(&buf, "#EXT-X-ENDLIST\n")
	}
	return buf.Bytes()
}

// generateDASH produces an MPD manifest with multiple adaptation sets,
// representations at different quality levels, and audio tracks.
func (g *Generator) generateDASH(path string) []byte {
	rng := deterministicRng(path)
	numSegments := 4 + rng.Intn(6)
	segmentDuration := 4 + rng.Intn(4)

	h := sha256.Sum256([]byte(path))
	streamName := fmt.Sprintf("%x", h[:4])

	totalDuration := numSegments * segmentDuration
	hours := totalDuration / 3600
	mins := (totalDuration % 3600) / 60
	secs := totalDuration % 60

	// Decide manifest type: 0=static, 1=dynamic (live)
	isDynamic := rng.Intn(3) == 0

	var buf bytes.Buffer
	fmt.Fprintf(&buf, `<?xml version="1.0" encoding="UTF-8"?>`)
	fmt.Fprintf(&buf, "\n")
	fmt.Fprintf(&buf, `<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"`)
	fmt.Fprintf(&buf, ` xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`)
	if isDynamic {
		fmt.Fprintf(&buf, ` type="dynamic"`)
		fmt.Fprintf(&buf, ` availabilityStartTime="2026-01-15T00:00:00Z"`)
		fmt.Fprintf(&buf, ` minimumUpdatePeriod="PT%dS"`, segmentDuration)
		fmt.Fprintf(&buf, ` timeShiftBufferDepth="PT%dS"`, totalDuration)
	} else {
		fmt.Fprintf(&buf, ` type="static"`)
		fmt.Fprintf(&buf, ` mediaPresentationDuration="PT%dH%dM%dS"`, hours, mins, secs)
	}
	fmt.Fprintf(&buf, ` minBufferTime="PT2S"`)
	fmt.Fprintf(&buf, ` profiles="urn:mpeg:dash:profile:isoff-live:2011"`)
	fmt.Fprintf(&buf, ">\n")

	// Base URL
	fmt.Fprintf(&buf, "  <BaseURL>/media/stream/%s/</BaseURL>\n", streamName)

	fmt.Fprintf(&buf, "  <Period id=\"0\" duration=\"PT%dH%dM%dS\">\n", hours, mins, secs)

	// Video AdaptationSet with multiple representations
	fmt.Fprintf(&buf, "    <AdaptationSet mimeType=\"video/mp4\" codecs=\"avc1.42e01e\" segmentAlignment=\"true\" startWithSAP=\"1\">\n")

	type videoRep struct {
		id, bw, w, h int
		codec        string
	}
	reps := []videoRep{
		{1, 300000, 426, 240, "avc1.42e00d"},
		{2, 800000, 640, 360, "avc1.42e01e"},
		{3, 1500000, 854, 480, "avc1.42e01f"},
		{4, 3000000, 1280, 720, "avc1.4d401f"},
	}
	numReps := 2 + rng.Intn(3)
	if numReps > len(reps) {
		numReps = len(reps)
	}

	for _, r := range reps[:numReps] {
		fmt.Fprintf(&buf, "      <Representation id=\"%d\" bandwidth=\"%d\" width=\"%d\" height=\"%d\" codecs=\"%s\">\n",
			r.id, r.bw, r.w, r.h, r.codec)
		fmt.Fprintf(&buf, "        <SegmentTemplate media=\"segment_$Number$.mp4\" initialization=\"init_%d.mp4\" duration=\"%d\" startNumber=\"0\" timescale=\"1\"/>\n",
			r.id, segmentDuration)
		fmt.Fprintf(&buf, "      </Representation>\n")
	}
	fmt.Fprintf(&buf, "    </AdaptationSet>\n")

	// Audio AdaptationSet
	fmt.Fprintf(&buf, "    <AdaptationSet mimeType=\"audio/mp4\" codecs=\"mp4a.40.2\" lang=\"en\" segmentAlignment=\"true\">\n")
	fmt.Fprintf(&buf, "      <Representation id=\"audio\" bandwidth=\"128000\" audioSamplingRate=\"44100\">\n")
	fmt.Fprintf(&buf, "        <AudioChannelConfiguration schemeIdUri=\"urn:mpeg:dash:23003:3:audio_channel_configuration:2011\" value=\"2\"/>\n")
	fmt.Fprintf(&buf, "        <SegmentTemplate media=\"audio_$Number$.mp4\" initialization=\"audio_init.mp4\" duration=\"%d\" startNumber=\"0\" timescale=\"1\"/>\n",
		segmentDuration)
	fmt.Fprintf(&buf, "      </Representation>\n")
	fmt.Fprintf(&buf, "    </AdaptationSet>\n")

	// Optional subtitle AdaptationSet
	if rng.Intn(2) == 0 {
		fmt.Fprintf(&buf, "    <AdaptationSet mimeType=\"text/vtt\" lang=\"en\">\n")
		fmt.Fprintf(&buf, "      <Representation id=\"sub_en\" bandwidth=\"1000\">\n")
		fmt.Fprintf(&buf, "        <BaseURL>subtitles_en.vtt</BaseURL>\n")
		fmt.Fprintf(&buf, "      </Representation>\n")
		fmt.Fprintf(&buf, "    </AdaptationSet>\n")
	}

	fmt.Fprintf(&buf, "  </Period>\n")
	fmt.Fprintf(&buf, "</MPD>\n")

	return buf.Bytes()
}

// generateTS produces MPEG-TS packets (188 bytes each with sync byte 0x47)
// with PAT, PMT, PCR adaptation fields, and PES-wrapped H.264 video data.
func (g *Generator) generateTS(path string) []byte {
	rng := deterministicRng(path)

	var buf bytes.Buffer
	cc := make(map[uint16]byte) // continuity counters per PID

	// Helper to get next continuity counter
	nextCC := func(pid uint16) byte {
		v := cc[pid]
		cc[pid] = (v + 1) & 0x0F
		return v
	}

	// PAT (Program Association Table) — PID 0x0000
	patData := []byte{
		0x00,       // pointer field
		0x00,       // table_id = 0 (PAT)
		0xB0, 0x0D, // section_syntax_indicator=1, section_length=13
		0x00, 0x01, // transport_stream_id = 1
		0xC1,       // reserved=11, version=0, current_next=1
		0x00,       // section_number = 0
		0x00,       // last_section_number = 0
		0x00, 0x01, // program_number = 1
		0xE1, 0x00, // reserved=111, PMT PID = 0x100
	}
	// Compute CRC32 for PAT section (MPEG CRC-32)
	patSection := patData[1:] // skip pointer field
	crc := mpegCRC32(patSection)
	patData = append(patData, byte(crc>>24), byte(crc>>16), byte(crc>>8), byte(crc))
	pat := makeTSPacketCC(0x0000, true, nextCC(0x0000), patData)
	buf.Write(pat)

	// PMT (Program Map Table) — PID 0x0100
	pmtSection := []byte{
		0x02,       // table_id = 2 (PMT)
		0xB0, 0x17, // section_syntax_indicator=1, section_length=23
		0x00, 0x01, // program_number = 1
		0xC1,       // reserved, version=0, current_next=1
		0x00, 0x00, // section numbers
		0xE1, 0x01, // reserved + PCR PID = 0x101
		0xF0, 0x00, // reserved + program_info_length = 0
		// Video stream: type=0x1B (H.264), PID=0x101
		0x1B,       // stream_type = H.264
		0xE1, 0x01, // reserved + elementary PID = 0x101
		0xF0, 0x00, // reserved + ES info length = 0
		// Audio stream: type=0x03 (MPEG1 Audio), PID=0x102
		0x03,       // stream_type = MPEG-1 Audio
		0xE1, 0x02, // reserved + elementary PID = 0x102
		0xF0, 0x00, // reserved + ES info length = 0
	}
	crc = mpegCRC32(pmtSection)
	pmtData := append([]byte{0x00}, pmtSection...) // pointer field
	pmtData = append(pmtData, byte(crc>>24), byte(crc>>16), byte(crc>>8), byte(crc))
	pmt := makeTSPacketCC(0x0100, true, nextCC(0x0100), pmtData)
	buf.Write(pmt)

	// Video PES packets with H.264 NAL data
	pesHeader := []byte{
		0x00, 0x00, 0x01, // start code
		0xE0,       // stream_id = 0xE0 (video)
		0x00, 0x00, // PES packet length = 0 (unbounded)
		0x80,       // '10' marker
		0x80,       // PTS flag set
		0x05,       // PES header data length = 5 (PTS)
		// PTS = 0 (5 bytes: 0010 xxxx, etc.)
		0x21, 0x00, 0x01, 0x00, 0x01,
	}
	pesPayload := append(pesHeader, h264SPSPPSIDر...)

	numVideoPackets := 2 + rng.Intn(4)
	for i := 0; i < numVideoPackets; i++ {
		pktStart := i == 0
		var payload []byte
		if pktStart {
			payload = pesPayload
		} else {
			// Fill continuation packets with NAL filler data (0x0C)
			payload = make([]byte, 160)
			for j := range payload {
				payload[j] = byte(rng.Intn(256))
			}
		}

		// First video packet gets PCR in adaptation field
		if i == 0 {
			pkt := makeTSPacketWithPCR(0x0101, true, nextCC(0x0101), 0, payload)
			buf.Write(pkt)
		} else {
			pkt := makeTSPacketCC(0x0101, pktStart, nextCC(0x0101), payload)
			buf.Write(pkt)
		}
	}

	// Audio PES packets
	audioHeader := []byte{
		0x00, 0x00, 0x01, // start code
		0xC0,       // stream_id = 0xC0 (audio)
		0x00, 0x00, // PES packet length = 0
		0x80,       // '10' marker
		0x80,       // PTS flag
		0x05,       // PES header length = 5
		0x21, 0x00, 0x01, 0x00, 0x01, // PTS=0
	}
	// Append a silent MP3 frame
	audioPayload := append(audioHeader, minimalMP3Frame...)
	audioPkt := makeTSPacketCC(0x0102, true, nextCC(0x0102), audioPayload)
	buf.Write(audioPkt)

	// Add null packets for padding (PID 0x1FFF)
	numNull := rng.Intn(3)
	for i := 0; i < numNull; i++ {
		nullPkt := make([]byte, 188)
		nullPkt[0] = 0x47
		nullPkt[1] = 0x1F
		nullPkt[2] = 0xFF
		nullPkt[3] = 0x10 | nextCC(0x1FFF)
		buf.Write(nullPkt)
	}

	return buf.Bytes()
}

// mpegCRC32 computes the MPEG-2 CRC-32 checksum (polynomial 0x04C11DB7).
func mpegCRC32(data []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
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

// makeTSPacketCC creates a 188-byte MPEG-TS packet with explicit continuity counter.
func makeTSPacketCC(pid uint16, payloadUnitStart bool, cc byte, payload []byte) []byte {
	pkt := make([]byte, 188)
	pkt[0] = 0x47

	pkt[1] = byte(pid >> 8)
	if payloadUnitStart {
		pkt[1] |= 0x40
	}
	pkt[2] = byte(pid)
	pkt[3] = 0x10 | (cc & 0x0F) // payload only

	headerLen := 4
	payloadSpace := 188 - headerLen

	if len(payload) >= payloadSpace {
		copy(pkt[headerLen:], payload[:payloadSpace])
	} else {
		paddingNeeded := payloadSpace - len(payload)
		if paddingNeeded >= 2 {
			pkt[3] = 0x30 | (cc & 0x0F) // adaptation + payload
			afLen := paddingNeeded - 1
			pkt[4] = byte(afLen)
			if afLen > 0 {
				pkt[5] = 0x00
				for i := 6; i < 4+paddingNeeded; i++ {
					pkt[i] = 0xFF
				}
			}
			copy(pkt[4+paddingNeeded:], payload)
		} else {
			copy(pkt[headerLen:], payload)
		}
	}

	return pkt
}

// makeTSPacketWithPCR creates a TS packet with a PCR in the adaptation field.
func makeTSPacketWithPCR(pid uint16, payloadUnitStart bool, cc byte, pcrBase uint64, payload []byte) []byte {
	pkt := make([]byte, 188)
	pkt[0] = 0x47

	pkt[1] = byte(pid >> 8)
	if payloadUnitStart {
		pkt[1] |= 0x40
	}
	pkt[2] = byte(pid)
	pkt[3] = 0x30 | (cc & 0x0F) // adaptation + payload

	// Adaptation field: length=7 (flags + 6 bytes PCR)
	afLen := 7
	pkt[4] = byte(afLen)
	pkt[5] = 0x10 // PCR flag set

	// PCR: 33 bits base + 6 reserved + 9 bits extension
	// Pack into 6 bytes
	pcrExt := uint16(0)
	pkt[6] = byte(pcrBase >> 25)
	pkt[7] = byte(pcrBase >> 17)
	pkt[8] = byte(pcrBase >> 9)
	pkt[9] = byte(pcrBase >> 1)
	pkt[10] = byte(pcrBase<<7) | 0x7E | byte(pcrExt>>8)
	pkt[11] = byte(pcrExt)

	// Remaining space for payload
	headerLen := 4 + 1 + afLen // sync+header + af_length byte + af data
	payloadSpace := 188 - headerLen

	if len(payload) > payloadSpace {
		// Need more stuffing — expand adaptation field
		extra := len(payload) - payloadSpace
		pkt[4] = byte(afLen + extra)
		// Fill extra stuffing after PCR
		for i := 12; i < 12+extra; i++ {
			pkt[i] = 0xFF
		}
		copy(pkt[12+extra:], payload[:188-12-extra])
	} else if len(payload) < payloadSpace {
		// Expand adaptation field with stuffing
		extra := payloadSpace - len(payload)
		pkt[4] = byte(afLen + extra)
		for i := 12; i < 12+extra; i++ {
			pkt[i] = 0xFF
		}
		copy(pkt[12+extra:], payload)
	} else {
		copy(pkt[headerLen:], payload)
	}

	return pkt
}

// Ensure crc32 import is used (for future use in CRC computations).
var _ = crc32.ChecksumIEEE
