package mediachaos

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
)

// corruptBytes applies random bit-flips at the given intensity.
// intensity is in [0.0, 1.0] — higher values flip more bits.
func corruptBytes(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) == 0 {
		return data
	}
	out := make([]byte, len(data))
	copy(out, data)
	// Number of bytes to corrupt is proportional to intensity * length, minimum 1.
	numCorrupt := int(float64(len(out))*intensity) + 1
	if numCorrupt > len(out) {
		numCorrupt = len(out)
	}
	for i := 0; i < numCorrupt; i++ {
		pos := rng.Intn(len(out))
		// Flip a random bit in the byte at pos.
		out[pos] ^= 1 << uint(rng.Intn(8))
	}
	return out
}

// corruptGeneric applies format-agnostic corruption (bit flips, truncation, garbage insertion).
func corruptGeneric(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) == 0 {
		return data
	}
	variant := rng.Intn(3)
	switch variant {
	case 0:
		// Truncate at a random point. High intensity truncates earlier.
		maxKeep := int(float64(len(data)) * (1.0 - intensity*0.8))
		if maxKeep < 1 {
			maxKeep = 1
		}
		cutAt := rng.Intn(maxKeep) + 1
		if cutAt > len(data) {
			cutAt = len(data)
		}
		return data[:cutAt]

	case 1:
		// Flip random bits — number of flips proportional to intensity * length.
		return corruptBytes(data, intensity, rng)

	default:
		// Insert random garbage bytes at a random position.
		out := make([]byte, len(data))
		copy(out, data)
		numInserts := int(float64(len(out))*intensity*0.1) + 1
		for i := 0; i < numInserts; i++ {
			pos := rng.Intn(len(out))
			garbage := make([]byte, rng.Intn(8)+1)
			rng.Read(garbage)
			result := make([]byte, 0, len(out)+len(garbage))
			result = append(result, out[:pos]...)
			result = append(result, garbage...)
			result = append(result, out[pos:]...)
			out = result
		}
		return out
	}
}

// =============================================================================
// PNG corruption
// =============================================================================

// corruptPNG applies PNG-specific corruption.
//
// PNG structure: 8-byte magic, then IHDR chunk (len+type+data+CRC),
// then one or more IDAT chunks, then IEND chunk.
// Offsets:
//
//	magic:        [0:8]
//	IHDR chunk:   [8:], length=13 — total 25 bytes (4+4+13+4)
//	  IHDR type:  [12:16]
//	  width:      [16:20]
//	  height:     [20:24]
//	  bit depth:  [24]
//	  color type: [25]
//	  CRC:        [29:33]
//	IDAT/IEND follow after IHDR
func corruptPNG(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) < 16 {
		return corruptGeneric(data, intensity, rng)
	}
	out := make([]byte, len(data))
	copy(out, data)

	level := intensityLevel(intensity) // 0=low, 1=medium, 2=high

	switch level {
	case 0:
		// Low: flip bits only in IDAT payload (visual glitch, usually still parseable).
		// Also corrupt filter bytes and inject invalid filter methods.
		offset := 8
		idatCorrupted := false
		for offset+8 <= len(out) {
			chunkLen := int(be32(out[offset:]))
			chunkType := string(out[offset+4 : offset+8])
			dataStart := offset + 8
			dataEnd := dataStart + chunkLen
			if dataEnd > len(out) {
				break
			}
			if chunkType == "IDAT" && chunkLen > 0 {
				numFlips := int(float64(chunkLen)*intensity*0.1) + 1
				for i := 0; i < numFlips; i++ {
					pos := dataStart + rng.Intn(chunkLen)
					out[pos] ^= 1 << uint(rng.Intn(8))
				}
				// Also inject invalid filter bytes within the compressed stream.
				// Filter bytes in the decompressed stream are 0-4; we corrupt
				// within the compressed data, which may produce invalid filter values.
				if chunkLen > 4 {
					// Corrupt a byte near the start (likely within zlib header or first filter)
					pos := dataStart + rng.Intn(min(chunkLen, 16))
					out[pos] = byte(rng.Intn(256))
				}
				idatCorrupted = true
				break // corrupt first IDAT only
			}
			offset = dataEnd + 4 // skip CRC
		}
		if !idatCorrupted {
			return corruptGeneric(out, intensity, rng)
		}

	case 1:
		// Medium: corrupt CRC values and inject invalid ancillary chunks.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt CRC values in one or more chunks.
			offset := 8
			corrupted := 0
			maxCorrupt := int(intensity*5) + 1
			for offset+8 <= len(out) && corrupted < maxCorrupt {
				chunkLen := int(be32(out[offset:]))
				crcStart := offset + 8 + chunkLen
				if crcStart+4 > len(out) {
					break
				}
				rng.Read(out[crcStart : crcStart+4])
				corrupted++
				offset = crcStart + 4
			}
		case 1:
			// PLTE chunk with wrong number of entries for indexed color type.
			// Inject a malformed PLTE after IHDR.
			if len(out) >= 33 {
				// Create a PLTE chunk with a non-multiple-of-3 length (invalid).
				plteData := make([]byte, 7) // 7 is not divisible by 3
				rng.Read(plteData)
				chunk := makePNGChunk("PLTE", plteData)
				// Insert after IHDR (offset 33).
				result := make([]byte, 0, len(out)+len(chunk))
				result = append(result, out[:33]...)
				result = append(result, chunk...)
				result = append(result, out[33:]...)
				out = result
			}
		case 2:
			// Ancillary chunk before IHDR (invalid ordering).
			if len(out) >= 8 {
				// Inject a tEXt chunk before IHDR.
				textData := []byte("Comment\x00corrupted by glitch")
				chunk := makePNGChunk("tEXt", textData)
				result := make([]byte, 0, len(out)+len(chunk))
				result = append(result, out[:8]...) // PNG magic
				result = append(result, chunk...)    // tEXt before IHDR
				result = append(result, out[8:]...)  // IHDR and rest
				out = result
			}
		}

	default:
		// High: corrupt IHDR dimensions and color params, remove IEND, truncate IDAT.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt width and height in IHDR (offsets 16-23 from file start).
			if len(out) >= 26 {
				putBe32(out[16:], uint32(rng.Intn(65536)+1))
				putBe32(out[20:], uint32(rng.Intn(65536)+1))
				// Invalid IHDR: bit depth 3 with color type 2 (not in valid set).
				out[24] = 3 // bit depth 3 (invalid for color type 2)
				out[25] = 2 // color type 2 (RGB)
			}
			// Truncate the file to remove or cut IEND and part of IDAT.
			cutFraction := 0.5 + intensity*0.4
			cutAt := int(float64(len(out)) * (1.0 - cutFraction*0.3))
			if cutAt < 33 {
				cutAt = 33
			}
			if cutAt < len(out) {
				out = out[:cutAt]
			}
		case 1:
			// Invalid IHDR: width=0 (forbidden by spec).
			if len(out) >= 24 {
				putBe32(out[16:], 0) // width = 0
			}
		case 2:
			// Corrupt width/height and truncate aggressively.
			if len(out) >= 24 {
				putBe32(out[16:], uint32(rng.Intn(65536)+1))
				putBe32(out[20:], uint32(rng.Intn(65536)+1))
			}
			cutAt := int(float64(len(out)) * 0.4)
			if cutAt < 33 {
				cutAt = 33
			}
			if cutAt < len(out) {
				out = out[:cutAt]
			}
		}
	}
	return out
}

// makePNGChunk creates a raw PNG chunk (len + type + data + CRC).
// The CRC is intentionally wrong (zeroed) to produce parse errors.
func makePNGChunk(chunkType string, data []byte) []byte {
	chunk := make([]byte, 4+4+len(data)+4)
	putBe32(chunk[0:], uint32(len(data)))
	copy(chunk[4:8], chunkType)
	copy(chunk[8:], data)
	// Leave CRC as zeros (intentionally wrong).
	return chunk
}

// =============================================================================
// JPEG corruption
// =============================================================================

// corruptJPEG applies JPEG-specific corruption.
//
// JPEG structure: SOI (FF D8), then segments (FF xx len data), SOS scan data, EOI (FF D9).
// SOF0 (FF C0) segment contains: len(2)+precision(1)+height(2)+width(2)+components(1)+...
func corruptJPEG(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) < 4 {
		return corruptGeneric(data, intensity, rng)
	}
	out := make([]byte, len(data))
	copy(out, data)

	level := intensityLevel(intensity)

	switch level {
	case 0:
		// Low: flip bits in scan data (after SOS marker FF DA).
		sosOffset := findJPEGMarker(out, 0xDA)
		if sosOffset < 0 || sosOffset+2 >= len(out) {
			return corruptGeneric(out, intensity, rng)
		}
		sosHdrLen := int(be16(out[sosOffset+2:]))
		scanStart := sosOffset + 2 + sosHdrLen
		if scanStart >= len(out) {
			return corruptGeneric(out, intensity, rng)
		}
		scanLen := len(out) - scanStart
		numFlips := int(float64(scanLen)*intensity*0.05) + 1
		for i := 0; i < numFlips; i++ {
			pos := scanStart + rng.Intn(scanLen)
			out[pos] ^= 1 << uint(rng.Intn(8))
		}

	case 1:
		// Medium: corrupt quantization tables, restart markers, or DHT.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt quantization table values (DQT marker FF DB).
			dqtOffset := findJPEGMarker(out, 0xDB)
			if dqtOffset < 0 || dqtOffset+4 >= len(out) {
				return corruptGeneric(out, intensity, rng)
			}
			dqtLen := int(be16(out[dqtOffset+2:]))
			tableStart := dqtOffset + 4
			tableEnd := dqtOffset + 2 + dqtLen
			if tableEnd > len(out) {
				tableEnd = len(out)
			}
			numCorrupt := int(float64(tableEnd-tableStart)*intensity*0.3) + 1
			for i := 0; i < numCorrupt; i++ {
				if tableEnd <= tableStart {
					break
				}
				pos := tableStart + rng.Intn(tableEnd-tableStart)
				out[pos] = byte(rng.Intn(256))
			}
		case 1:
			// Invalid restart markers: inject RST7 followed by RST3 at wrong positions.
			sosOffset := findJPEGMarker(out, 0xDA)
			if sosOffset >= 0 && sosOffset+20 < len(out) {
				sosHdrLen := int(be16(out[sosOffset+2:]))
				scanStart := sosOffset + 2 + sosHdrLen
				if scanStart+10 < len(out) {
					scanLen := len(out) - scanStart
					// Inject invalid restart markers at random positions in scan data.
					for i := 0; i < 3; i++ {
						pos := scanStart + rng.Intn(scanLen-1)
						out[pos] = 0xFF
						if pos+1 < len(out) {
							// RST markers are 0xD0-0xD7; inject them out of sequence.
							rstMarkers := []byte{0xD7, 0xD3, 0xD5, 0xD1}
							out[pos+1] = rstMarkers[rng.Intn(len(rstMarkers))]
						}
					}
				}
			}
		case 2:
			// DHT with invalid code lengths (sum > 256).
			dhtOffset := findJPEGMarker(out, 0xC4)
			if dhtOffset >= 0 && dhtOffset+20 < len(out) {
				// DHT table: after marker(2)+length(2)+table_class_id(1), 16 bytes of code counts.
				countsStart := dhtOffset + 5
				if countsStart+16 <= len(out) {
					// Set all 16 count bytes to 255 (sum = 4080, way over 256).
					for i := 0; i < 16; i++ {
						out[countsStart+i] = byte(rng.Intn(200) + 50)
					}
				}
			}
		}

	default:
		// High: corrupt SOF0 dimensions; inject multiple SOF markers; remove EOI.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt SOF0 dimensions.
			sof0Offset := findJPEGMarker(out, 0xC0)
			if sof0Offset >= 0 && sof0Offset+9 < len(out) {
				putBe16(out[sof0Offset+5:], uint16(rng.Intn(65536)+1))
				putBe16(out[sof0Offset+7:], uint16(rng.Intn(65536)+1))
			}
			// Remove EOI.
			if len(out) >= 2 && out[len(out)-2] == 0xFF && out[len(out)-1] == 0xD9 {
				out = out[:len(out)-2]
			}
			cutAt := int(float64(len(out)) * 0.7)
			if cutAt < 4 {
				cutAt = 4
			}
			if cutAt < len(out) {
				out = out[:cutAt]
			}
		case 1:
			// Multiple SOF markers (SOF0 and SOF2 both present — ambiguous).
			sof0Offset := findJPEGMarker(out, 0xC0)
			if sof0Offset >= 0 && sof0Offset+2 < len(out) {
				sofLen := int(be16(out[sof0Offset+2:]))
				sofEnd := sof0Offset + 2 + sofLen
				if sofEnd < len(out) {
					// Inject a duplicate SOF2 (progressive) marker after SOF0.
					sofData := make([]byte, sofLen+2)
					copy(sofData, out[sof0Offset:sof0Offset+2+sofLen])
					sofData[1] = 0xC2 // Change to SOF2
					result := make([]byte, 0, len(out)+len(sofData))
					result = append(result, out[:sofEnd]...)
					result = append(result, sofData...)
					result = append(result, out[sofEnd:]...)
					out = result
				}
			}
		case 2:
			// APP markers with absurd lengths.
			// Find APP0 (FF E0) and set its length to a huge value.
			app0Offset := findJPEGMarker(out, 0xE0)
			if app0Offset >= 0 && app0Offset+4 < len(out) {
				putBe16(out[app0Offset+2:], 0xFFFE) // 65534 bytes length
			}
			// Truncate aggressively.
			cutAt := int(float64(len(out)) * 0.5)
			if cutAt < 4 {
				cutAt = 4
			}
			if cutAt < len(out) {
				out = out[:cutAt]
			}
		}
	}
	return out
}

// =============================================================================
// GIF corruption
// =============================================================================

// corruptGIF applies GIF-specific corruption.
//
// GIF structure: Header (6: "GIF89a"), Logical Screen Descriptor (7),
// optional Global Color Table (3 * 2^(n+1) bytes), then blocks.
// LSD offsets from start: width [6:8], height [8:10], packed [10], bg [11], aspect [12].
// Global color table starts at offset 13 if bit 7 of packed byte is set.
func corruptGIF(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) < 13 {
		return corruptGeneric(data, intensity, rng)
	}
	out := make([]byte, len(data))
	copy(out, data)

	level := intensityLevel(intensity)

	switch level {
	case 0:
		// Low: corrupt palette entries in Global Color Table (wrong colors).
		if out[10]&0x80 == 0 {
			return corruptGeneric(out, intensity, rng)
		}
		ctSize := 3 * (1 << ((int(out[10]&0x07) + 1)))
		ctStart := 13
		ctEnd := ctStart + ctSize
		if ctEnd > len(out) {
			ctEnd = len(out)
		}
		numCorrupt := int(float64(ctSize)*intensity*0.3) + 1
		for i := 0; i < numCorrupt; i++ {
			if ctEnd <= ctStart {
				break
			}
			pos := ctStart + rng.Intn(ctEnd-ctStart)
			out[pos] = byte(rng.Intn(256))
		}

	case 1:
		// Medium: corrupt LZW data or inject invalid LZW minimum code sizes.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt LZW data within Image Descriptor sub-blocks.
			imgOffset := -1
			for i := 13; i < len(out)-1; i++ {
				if out[i] == 0x2C {
					imgOffset = i
					break
				}
			}
			if imgOffset < 0 || imgOffset+11 >= len(out) {
				return corruptGeneric(out, intensity, rng)
			}
			subStart := imgOffset + 10 + 1 // +1 for LZW minimum code size
			if subStart < len(out) {
				blockLen := int(out[subStart])
				if blockLen > 0 && subStart+1+blockLen <= len(out) {
					numFlips := int(float64(blockLen)*intensity*0.4) + 1
					for i := 0; i < numFlips; i++ {
						pos := subStart + 1 + rng.Intn(blockLen)
						out[pos] ^= 1 << uint(rng.Intn(8))
					}
				}
			}
		case 1:
			// Invalid LZW minimum code size (0 or 13).
			imgOffset := -1
			for i := 13; i < len(out)-1; i++ {
				if out[i] == 0x2C {
					imgOffset = i
					break
				}
			}
			if imgOffset >= 0 && imgOffset+11 < len(out) {
				lzwMinPos := imgOffset + 10
				if rng.Intn(2) == 0 {
					out[lzwMinPos] = 0 // LZW min code size 0 (invalid)
				} else {
					out[lzwMinPos] = 13 // LZW min code size 13 (invalid, max is 12)
				}
			}
		case 2:
			// Sub-block with size 0 not at terminator position.
			imgOffset := -1
			for i := 13; i < len(out)-1; i++ {
				if out[i] == 0x2C {
					imgOffset = i
					break
				}
			}
			if imgOffset >= 0 && imgOffset+14 < len(out) {
				subStart := imgOffset + 11
				// Inject a zero-length sub-block in the middle of data.
				if subStart+2 < len(out) {
					result := make([]byte, 0, len(out)+1)
					result = append(result, out[:subStart+1]...)
					result = append(result, 0x00) // zero-length sub-block (premature terminator)
					result = append(result, out[subStart+1:]...)
					out = result
				}
			}
		}

	default:
		// High: corrupt screen descriptor dimensions; invalid disposal; remove trailer.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt screen descriptor and remove trailer.
			putLe16(out[6:], uint16(rng.Intn(65536)+1))
			putLe16(out[8:], uint16(rng.Intn(65536)+1))
			if len(out) > 0 && out[len(out)-1] == 0x3B {
				out = out[:len(out)-1]
			}
			cutAt := int(float64(len(out)) * 0.6)
			if cutAt < 13 {
				cutAt = 13
			}
			if cutAt < len(out) {
				out = out[:cutAt]
			}
		case 1:
			// Frame outside logical screen bounds: set image descriptor with huge offsets.
			imgOffset := -1
			for i := 13; i < len(out)-1; i++ {
				if out[i] == 0x2C {
					imgOffset = i
					break
				}
			}
			if imgOffset >= 0 && imgOffset+9 < len(out) {
				// Image descriptor: separator(1) + left(2) + top(2) + width(2) + height(2) + packed(1)
				putLe16(out[imgOffset+1:], uint16(60000)) // left offset way outside screen
				putLe16(out[imgOffset+3:], uint16(60000)) // top offset way outside screen
			}
		case 2:
			// Invalid disposal method in GCE (Graphic Control Extension).
			// GCE starts with 0x21 0xF9 0x04, packed byte at +3 from GCE start.
			for i := 0; i < len(out)-5; i++ {
				if out[i] == 0x21 && out[i+1] == 0xF9 && out[i+2] == 0x04 {
					// Packed byte: bits 2-4 are disposal method (0-3 valid, 4-7 reserved).
					packed := out[i+3]
					packed = (packed & 0xE3) | 0x1C // disposal = 7 (reserved/invalid)
					out[i+3] = packed
					break
				}
			}
			// Also corrupt dimensions.
			putLe16(out[6:], uint16(rng.Intn(65536)+1))
			putLe16(out[8:], uint16(rng.Intn(65536)+1))
		}
	}
	return out
}

// =============================================================================
// WAV corruption
// =============================================================================

// corruptWAV applies WAV-specific corruption.
//
// WAV structure: RIFF header (12 bytes), fmt chunk (8+16=24 bytes typical),
// data chunk (8 byte header + samples).
// RIFF header: "RIFF"(4) + file_size(4) + "WAVE"(4)
// fmt chunk:   "fmt "(4) + chunk_size(4) + audio_format(2) + channels(2) +
//
//	sample_rate(4) + byte_rate(4) + block_align(2) + bits_per_sample(2)
//
// data chunk:  "data"(4) + data_size(4) + samples(...)
func corruptWAV(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) < 44 {
		return corruptGeneric(data, intensity, rng)
	}
	out := make([]byte, len(data))
	copy(out, data)

	level := intensityLevel(intensity)

	switch level {
	case 0:
		// Low: flip bits in sample data (audio clicks/pops).
		dataOffset := findWAVChunk(out, "data")
		if dataOffset < 0 || dataOffset+8 >= len(out) {
			return corruptGeneric(out, intensity, rng)
		}
		sampleStart := dataOffset + 8
		sampleEnd := len(out)
		sampleLen := sampleEnd - sampleStart
		if sampleLen <= 0 {
			return corruptGeneric(out, intensity, rng)
		}
		numFlips := int(float64(sampleLen)*intensity*0.02) + 1
		for i := 0; i < numFlips; i++ {
			pos := sampleStart + rng.Intn(sampleLen)
			out[pos] ^= 1 << uint(rng.Intn(8))
		}

	case 1:
		// Medium: corrupt fmt chunk fields.
		variant := rng.Intn(3)
		fmtOffset := findWAVChunk(out, "fmt ")
		if fmtOffset < 0 || fmtOffset+24 > len(out) {
			return corruptGeneric(out, intensity, rng)
		}
		switch variant {
		case 0:
			// Corrupt sample rate.
			putLe32(out[fmtOffset+12:], uint32(rng.Intn(192001)+1))
		case 1:
			// Corrupt channel count.
			putLe16(out[fmtOffset+10:], uint16(rng.Intn(255)+1))
		case 2:
			// Block align doesn't match channels * bits_per_sample / 8.
			putLe16(out[fmtOffset+20:], uint16(rng.Intn(255)+1)) // wrong block align
		}

	default:
		// High: corrupt data chunk size, RIFF size, audio format, or truncate.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt data chunk size and truncate.
			dataOffset := findWAVChunk(out, "data")
			if dataOffset >= 0 && dataOffset+8 <= len(out) {
				putLe32(out[dataOffset+4:], uint32(rng.Intn(1<<31)))
			}
			cutAt := int(float64(len(out)) * 0.4)
			if cutAt < 44 {
				cutAt = 44
			}
			if cutAt < len(out) {
				out = out[:cutAt]
			}
		case 1:
			// Invalid audio format code (not 1/PCM).
			fmtOffset := findWAVChunk(out, "fmt ")
			if fmtOffset >= 0 && fmtOffset+10 <= len(out) {
				invalidFormats := []uint16{0, 99, 255, 0xFFFF}
				putLe16(out[fmtOffset+8:], invalidFormats[rng.Intn(len(invalidFormats))])
			}
		case 2:
			// RIFF size doesn't match file size; extra chunks with invalid FourCCs.
			putLe32(out[4:], uint32(rng.Intn(1<<31))) // corrupt RIFF size
			// Inject a chunk with an invalid FourCC at the end.
			invalidChunk := []byte{0xFF, 0xFE, 0xFD, 0xFC} // invalid FourCC
			invalidChunk = append(invalidChunk, 0x04, 0x00, 0x00, 0x00)
			invalidChunk = append(invalidChunk, 0xDE, 0xAD, 0xBE, 0xEF)
			out = append(out, invalidChunk...)
		}
	}
	return out
}

// =============================================================================
// WebP corruption
// =============================================================================

// corruptWebP applies WebP-specific corruption.
//
// WebP structure: RIFF(4) + filesize(4) + WEBP(4) + VP8 chunk(s)
// VP8 chunk:  "VP8 "(4) + chunksize(4) + VP8 bitstream
// VP8L chunk: "VP8L"(4) + chunksize(4) + VP8L bitstream
// VP8X chunk: "VP8X"(4) + chunksize(4) + flags(4) + canvas_width(3) + canvas_height(3)
// VP8 frame header: 3 bytes (frame_tag) then width(2) + height(2) for keyframes
func corruptWebP(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) < 20 {
		return corruptGeneric(data, intensity, rng)
	}
	out := make([]byte, len(data))
	copy(out, data)

	level := intensityLevel(intensity)

	switch level {
	case 0:
		// Low: flip bits in VP8 frame data (after RIFF+WEBP+VP8 headers).
		// VP8/VP8L chunk data starts after the 12-byte RIFF header + 8-byte chunk header = offset 20.
		frameStart := 20
		// Try to find VP8 chunk start more precisely.
		vp8Offset := findRIFFChunk(out[12:], "VP8 ")
		if vp8Offset >= 0 {
			frameStart = 12 + vp8Offset + 8
		} else {
			vp8Offset = findRIFFChunk(out[12:], "VP8L")
			if vp8Offset >= 0 {
				frameStart = 12 + vp8Offset + 8
			}
		}
		if frameStart >= len(out) {
			frameStart = 20
		}
		if frameStart >= len(out) {
			return corruptGeneric(out, intensity, rng)
		}
		dataLen := len(out) - frameStart
		numFlips := int(float64(dataLen)*intensity*0.05) + 1
		for i := 0; i < numFlips; i++ {
			pos := frameStart + rng.Intn(dataLen)
			out[pos] ^= 1 << uint(rng.Intn(8))
		}

	case 1:
		// Medium: corrupt VP8 keyframe dimensions (width/height in frame header).
		// For VP8 lossy: after chunk header, first 3 bytes are frame_tag,
		// then for keyframes: 3 bytes sync code (0x9D 0x01 0x2A), then width(2LE) + height(2LE).
		vp8Offset := findRIFFChunk(out[12:], "VP8 ")
		if vp8Offset >= 0 {
			frameDataStart := 12 + vp8Offset + 8
			// Look for VP8 keyframe sync code: 0x9D 0x01 0x2A
			for i := frameDataStart; i < len(out)-7 && i < frameDataStart+20; i++ {
				if out[i] == 0x9D && i+1 < len(out) && out[i+1] == 0x01 && i+2 < len(out) && out[i+2] == 0x2A {
					// Width at i+3 (2 bytes LE), height at i+5 (2 bytes LE).
					if i+7 <= len(out) {
						putLe16(out[i+3:], uint16(rng.Intn(16384)+1))
						putLe16(out[i+5:], uint16(rng.Intn(16384)+1))
					}
					break
				}
			}
		} else {
			// VP8L or VP8X: corrupt canvas dimensions.
			vp8xOffset := findRIFFChunk(out[12:], "VP8X")
			if vp8xOffset >= 0 {
				dimStart := 12 + vp8xOffset + 8 + 4 // after flags
				if dimStart+6 <= len(out) {
					// Canvas width (3 bytes LE) and height (3 bytes LE).
					rng.Read(out[dimStart : dimStart+6])
				}
			} else {
				return corruptGeneric(out, intensity, rng)
			}
		}

	default:
		// High: corrupt RIFF chunk size, truncate VP8 data, inject wrong FourCC.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt RIFF file size.
			putLe32(out[4:], uint32(rng.Intn(1<<31)))
		case 1:
			// Inject wrong FourCC (change WEBP to something else).
			badFourCCs := []string{"WEBQ", "RIFF", "WAVE", "AVI "}
			chosen := badFourCCs[rng.Intn(len(badFourCCs))]
			copy(out[8:12], chosen)
		case 2:
			// Corrupt VP8 chunk type and truncate.
			if len(out) > 16 {
				// Change VP8 chunk type to garbage.
				copy(out[12:16], "XXXX")
			}
		}
		// Always truncate in high intensity.
		cutAt := int(float64(len(out)) * 0.5)
		if cutAt < 20 {
			cutAt = 20
		}
		if cutAt < len(out) {
			out = out[:cutAt]
		}
	}
	return out
}

// =============================================================================
// BMP corruption
// =============================================================================

// corruptBMP applies BMP-specific corruption.
//
// BMP structure:
// File header (14 bytes): "BM"(2) + filesize(4) + reserved(4) + bfOffBits(4)
// DIB header (typically 40 bytes BITMAPINFOHEADER):
//
//	biSize(4) + biWidth(4) + biHeight(4) + biPlanes(2) + biBitCount(2) +
//	biCompression(4) + biSizeImage(4) + biXPelsPerMeter(4) + biYPelsPerMeter(4) +
//	biClrUsed(4) + biClrImportant(4)
//
// Pixel data starts at bfOffBits.
func corruptBMP(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) < 54 {
		return corruptGeneric(data, intensity, rng)
	}
	out := make([]byte, len(data))
	copy(out, data)

	level := intensityLevel(intensity)

	// Read pixel data offset from file header.
	pixelOffset := int(le32(out[10:]))
	if pixelOffset < 54 || pixelOffset >= len(out) {
		pixelOffset = 54
	}

	switch level {
	case 0:
		// Low: flip bits in pixel data region.
		if pixelOffset < len(out) {
			pixelLen := len(out) - pixelOffset
			numFlips := int(float64(pixelLen)*intensity*0.05) + 1
			for i := 0; i < numFlips; i++ {
				pos := pixelOffset + rng.Intn(pixelLen)
				out[pos] ^= 1 << uint(rng.Intn(8))
			}
		}

	case 1:
		// Medium: corrupt DIB header fields.
		variant := rng.Intn(4)
		switch variant {
		case 0:
			// Corrupt biWidth.
			putLe32(out[18:], uint32(rng.Intn(65536)+1))
		case 1:
			// Corrupt biHeight (can be negative for top-down; set to extreme).
			putLe32(out[22:], uint32(rng.Int31()))
		case 2:
			// Corrupt biBitCount to invalid value (e.g., 3, 7, 13).
			invalidBits := []uint16{3, 7, 13, 17, 0, 255}
			putLe16(out[28:], invalidBits[rng.Intn(len(invalidBits))])
		case 3:
			// Corrupt biCompression to unknown value.
			putLe32(out[30:], uint32(rng.Intn(100)+10))
		}

	default:
		// High: corrupt file header, pixel offset, truncate pixel data.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// bfOffBits pointing to wrong offset (past end of file or before headers).
			badOffsets := []uint32{0, 2, uint32(len(out) + 1000), uint32(len(out) * 2)}
			putLe32(out[10:], badOffsets[rng.Intn(len(badOffsets))])
		case 1:
			// Corrupt file size field.
			putLe32(out[2:], uint32(rng.Intn(1<<31)))
		case 2:
			// Corrupt DIB header size to impossible value.
			putLe32(out[14:], uint32(rng.Intn(1000)+1000))
		}
		// Truncate pixel data.
		cutAt := pixelOffset + rng.Intn(max(1, len(out)-pixelOffset)/2)
		if cutAt < 54 {
			cutAt = 54
		}
		if cutAt < len(out) {
			out = out[:cutAt]
		}
	}
	return out
}

// =============================================================================
// SVG corruption
// =============================================================================

// corruptSVG applies SVG-specific corruption.
// SVG is XML-based, so corruption targets XML structure and SVG attributes.
func corruptSVG(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) < 10 {
		return corruptGeneric(data, intensity, rng)
	}

	level := intensityLevel(intensity)
	text := string(data)

	switch level {
	case 0:
		// Low: corrupt numeric attribute values with invalid numbers.
		invalidNums := []string{"NaN", "Infinity", "-Infinity", "-0", "1e999", "-1e999", "0x1p1023"}
		// Replace numeric values in known attributes.
		attrs := []string{"width", "height", "x", "y", "r", "cx", "cy", "rx", "ry",
			"x1", "y1", "x2", "y2", "font-size", "stroke-width", "opacity"}
		result := text
		replacements := 0
		maxReplacements := int(intensity*10) + 1
		for _, attr := range attrs {
			if replacements >= maxReplacements {
				break
			}
			// Look for attr="<number>" pattern.
			search := attr + `="`
			idx := strings.Index(result, search)
			if idx >= 0 {
				valStart := idx + len(search)
				valEnd := strings.Index(result[valStart:], `"`)
				if valEnd > 0 {
					invalidVal := invalidNums[rng.Intn(len(invalidNums))]
					result = result[:valStart] + invalidVal + result[valStart+valEnd:]
					replacements++
				}
			}
		}
		return []byte(result)

	case 1:
		// Medium: inject malformed XML.
		variant := rng.Intn(4)
		switch variant {
		case 0:
			// Unclosed tags: remove some closing tags.
			result := text
			closingTags := []string{"</svg>", "</g>", "</text>", "</rect>", "</circle>", "</path>", "</defs>"}
			for _, tag := range closingTags {
				if rng.Float64() < 0.5 {
					result = strings.Replace(result, tag, "", 1)
				}
			}
			return []byte(result)
		case 1:
			// Invalid XML entities.
			invalidEntities := []string{"&#xFFFFFF;", "&#999999;", "&invalidEntity;", "&#x110000;", "&amp;&amp;&lt;&gt;&foo;"}
			insertAt := rng.Intn(max(1, len(text)))
			chosen := invalidEntities[rng.Intn(len(invalidEntities))]
			return []byte(text[:insertAt] + chosen + text[insertAt:])
		case 2:
			// Attributes without values.
			// Inject broken attributes into the opening svg tag.
			svgIdx := strings.Index(text, "<svg")
			if svgIdx >= 0 {
				closeIdx := strings.Index(text[svgIdx:], ">")
				if closeIdx > 0 {
					insertPos := svgIdx + closeIdx
					return []byte(text[:insertPos] + ` broken novalue !!!invalid` + text[insertPos:])
				}
			}
			return []byte(text)
		case 3:
			// Duplicate attributes (invalid XML).
			svgIdx := strings.Index(text, "<svg")
			if svgIdx >= 0 {
				closeIdx := strings.Index(text[svgIdx:], ">")
				if closeIdx > 0 {
					insertPos := svgIdx + closeIdx
					return []byte(text[:insertPos] + ` width="999" width="-1" height="NaN" height="Infinity"` + text[insertPos:])
				}
			}
			return []byte(text)
		}

	default:
		// High: inject script elements, destroy structure, or replace content.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Inject script elements.
			scripts := []string{
				`<script>alert('xss')</script>`,
				`<foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>document.write('hacked')</script></body></foreignObject>`,
				`<set attributeName="onmouseover" to="alert(1)"/>`,
			}
			svgIdx := strings.Index(text, "<svg")
			if svgIdx >= 0 {
				closeIdx := strings.Index(text[svgIdx:], ">")
				if closeIdx > 0 {
					insertAfter := svgIdx + closeIdx + 1
					if insertAfter < len(text) {
						inject := scripts[rng.Intn(len(scripts))]
						return []byte(text[:insertAfter] + inject + text[insertAfter:])
					}
				}
			}
			return []byte(text + scripts[0])
		case 1:
			// Remove all closing tags.
			result := text
			for _, tag := range []string{"</svg>", "</g>", "</text>", "</rect>", "</circle>",
				"</path>", "</defs>", "</style>", "</linearGradient>", "</radialGradient>"} {
				result = strings.ReplaceAll(result, tag, "")
			}
			return []byte(result)
		case 2:
			// Replace entire content with partial/broken XML.
			return []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="NaN" height="-1"><rect x="Infinity" y="-0" width="1e999"`)
		}
	}
	return data
}

// =============================================================================
// ICO corruption
// =============================================================================

// corruptICO applies ICO-specific corruption.
//
// ICO structure:
// ICONDIR (6 bytes): reserved(2) + type(2) + count(2)
// ICONDIRENTRY (16 bytes each): width(1) + height(1) + colorCount(1) + reserved(1) +
//
//	planes(2) + bitCount(2) + sizeInBytes(4) + dwImageOffset(4)
//
// Image data follows at dwImageOffset for each entry.
func corruptICO(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) < 22 { // Minimum: 6-byte header + at least one 16-byte entry
		return corruptGeneric(data, intensity, rng)
	}
	out := make([]byte, len(data))
	copy(out, data)

	level := intensityLevel(intensity)

	switch level {
	case 0:
		// Low: corrupt icon dimensions in ICONDIRENTRY.
		count := int(le16(out[4:]))
		if count < 1 {
			count = 1
		}
		for i := 0; i < count && 6+i*16+16 <= len(out); i++ {
			entryOffset := 6 + i*16
			if rng.Float64() < intensity {
				out[entryOffset] = byte(rng.Intn(256))   // width
				out[entryOffset+1] = byte(rng.Intn(256)) // height
			}
		}

	case 1:
		// Medium: corrupt image data offsets (dwImageOffset pointing to wrong locations).
		count := int(le16(out[4:]))
		if count < 1 {
			count = 1
		}
		for i := 0; i < count && 6+i*16+16 <= len(out); i++ {
			entryOffset := 6 + i*16
			if rng.Float64() < intensity+0.3 {
				// dwImageOffset is at bytes 12-15 of each entry.
				badOffsets := []uint32{0, 3, uint32(len(out) + 5000), uint32(rng.Intn(len(out)))}
				putLe32(out[entryOffset+12:], badOffsets[rng.Intn(len(badOffsets))])
			}
		}

	default:
		// High: corrupt ICONDIR header, set impossible count, truncate.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// idCount to impossible value.
			putLe16(out[4:], uint16(rng.Intn(10000)+1000))
		case 1:
			// Corrupt type field (should be 1 for ICO, 2 for CUR).
			putLe16(out[2:], uint16(rng.Intn(256)+3))
		case 2:
			// Corrupt reserved (should be 0) and type.
			putLe16(out[0:], uint16(rng.Intn(65536)+1)) // reserved != 0
			putLe16(out[2:], uint16(rng.Intn(256)+3))   // invalid type
		}
		// Truncate to remove image data.
		cutAt := 6 + 16 // Keep header + one entry
		if cutAt < len(out) {
			out = out[:cutAt]
		}
	}
	return out
}

// =============================================================================
// TIFF corruption
// =============================================================================

// corruptTIFF applies TIFF-specific corruption.
//
// TIFF structure:
// Header (8 bytes): byte_order(2: "II" or "MM") + magic(2: 42) + IFD_offset(4)
// IFD: entry_count(2) + entries(12 bytes each) + next_IFD_offset(4)
// Each IFD entry: tag(2) + type(2) + count(4) + value_offset(4)
// Strip/tile data at offsets specified in StripOffsets/TileOffsets tags.
func corruptTIFF(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) < 16 {
		return corruptGeneric(data, intensity, rng)
	}
	out := make([]byte, len(data))
	copy(out, data)

	level := intensityLevel(intensity)
	isLittleEndian := out[0] == 'I' && out[1] == 'I'

	switch level {
	case 0:
		// Low: flip bits in strip/tile data (skip header and IFD).
		// Assume strip data starts after offset 256 (or at least past the IFD).
		dataStart := 256
		if dataStart >= len(out) {
			dataStart = min(16, len(out))
		}
		dataLen := len(out) - dataStart
		if dataLen <= 0 {
			return corruptGeneric(out, intensity, rng)
		}
		numFlips := int(float64(dataLen)*intensity*0.05) + 1
		for i := 0; i < numFlips; i++ {
			pos := dataStart + rng.Intn(dataLen)
			out[pos] ^= 1 << uint(rng.Intn(8))
		}

	case 1:
		// Medium: corrupt IFD tag values (ImageWidth, ImageLength, StripOffsets).
		var ifdOffset uint32
		if isLittleEndian {
			ifdOffset = le32(out[4:])
		} else {
			ifdOffset = be32(out[4:])
		}
		ifd := int(ifdOffset)
		if ifd < 8 || ifd+2 > len(out) {
			return corruptGeneric(out, intensity, rng)
		}
		var entryCount uint16
		if isLittleEndian {
			entryCount = le16(out[ifd:])
		} else {
			entryCount = be16(out[ifd:])
		}
		// Corrupt known tag values.
		// ImageWidth=256, ImageLength=257, StripOffsets=273, RowsPerStrip=278
		targetTags := []uint16{256, 257, 273, 278}
		for i := 0; i < int(entryCount) && ifd+2+i*12+12 <= len(out); i++ {
			entryOffset := ifd + 2 + i*12
			var tag uint16
			if isLittleEndian {
				tag = le16(out[entryOffset:])
			} else {
				tag = be16(out[entryOffset:])
			}
			for _, target := range targetTags {
				if tag == target && rng.Float64() < intensity+0.3 {
					// Corrupt the value (bytes 8-11 of the entry).
					valOffset := entryOffset + 8
					if valOffset+4 <= len(out) {
						rng.Read(out[valOffset : valOffset+4])
					}
				}
			}
		}

	default:
		// High: corrupt byte order marker, IFD offset, truncate.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt byte order marker.
			badOrders := []string{"XX", "MI", "IM", "\x00\x00"}
			chosen := badOrders[rng.Intn(len(badOrders))]
			copy(out[0:2], chosen)
		case 1:
			// Corrupt magic number (should be 42).
			if isLittleEndian {
				putLe16(out[2:], uint16(rng.Intn(65536)))
			} else {
				putBe16(out[2:], uint16(rng.Intn(65536)))
			}
		case 2:
			// Corrupt IFD offset to point past end of file.
			if isLittleEndian {
				putLe32(out[4:], uint32(len(out)+rng.Intn(10000)))
			} else {
				putBe32(out[4:], uint32(len(out)+rng.Intn(10000)))
			}
		}
		// Truncate.
		cutAt := int(float64(len(out)) * 0.4)
		if cutAt < 16 {
			cutAt = 16
		}
		if cutAt < len(out) {
			out = out[:cutAt]
		}
	}
	return out
}

// =============================================================================
// MP3 corruption
// =============================================================================

// corruptMP3 applies MP3-specific corruption.
//
// MP3 structure:
// Optional ID3v2 tag at start: "ID3"(3) + version(2) + flags(1) + size(4)
// MPEG frames: sync word (11 bits = 0x7FF, typically FF FB/FA/F3/F2 bytes)
// Frame header (4 bytes): sync(12 bits) + version(2) + layer(2) + protection(1) +
//
//	bitrate_index(4) + sample_rate_index(2) + padding(1) + private(1) +
//	channel_mode(2) + ...
//
// Frame data follows the header.
func corruptMP3(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) < 10 {
		return corruptGeneric(data, intensity, rng)
	}
	out := make([]byte, len(data))
	copy(out, data)

	level := intensityLevel(intensity)

	// Find first MPEG frame sync (0xFF followed by 0xE0 or higher in top 3 bits).
	frameStart := findMP3Frame(out)

	switch level {
	case 0:
		// Low: flip bits in frame data (preserving frame headers).
		if frameStart < 0 || frameStart+4 >= len(out) {
			return corruptGeneric(out, intensity, rng)
		}
		// Corrupt data bytes after the 4-byte frame header, preserving sync words.
		pos := frameStart + 4
		dataLen := len(out) - pos
		if dataLen <= 0 {
			return corruptGeneric(out, intensity, rng)
		}
		numFlips := int(float64(dataLen)*intensity*0.03) + 1
		for i := 0; i < numFlips; i++ {
			flipPos := pos + rng.Intn(dataLen)
			// Avoid corrupting sync bytes (0xFF followed by 0xE0+).
			if flipPos > 0 && out[flipPos-1] == 0xFF && (out[flipPos]&0xE0) == 0xE0 {
				continue
			}
			if out[flipPos] == 0xFF && flipPos+1 < len(out) && (out[flipPos+1]&0xE0) == 0xE0 {
				continue
			}
			out[flipPos] ^= 1 << uint(rng.Intn(8))
		}

	case 1:
		// Medium: corrupt frame header fields (bitrate index, sample rate index to reserved values).
		if frameStart < 0 || frameStart+4 >= len(out) {
			return corruptGeneric(out, intensity, rng)
		}
		numFrames := int(intensity*5) + 1
		pos := frameStart
		for i := 0; i < numFrames && pos+4 <= len(out); i++ {
			// Frame header byte 2: bitrate_index(4 bits) + sample_rate_index(2 bits) + padding(1) + private(1)
			// Set bitrate_index to 0xF (reserved/bad) and sample_rate_index to 0x3 (reserved).
			headerByte2 := out[pos+2]
			variant := rng.Intn(2)
			if variant == 0 {
				// Set bitrate index to 1111 (reserved).
				headerByte2 = (headerByte2 & 0x0F) | 0xF0
			} else {
				// Set sample rate index to 11 (reserved).
				headerByte2 = (headerByte2 & 0xF3) | 0x0C
			}
			out[pos+2] = headerByte2
			// Move to next potential frame (estimate ~400 bytes per frame at 128kbps).
			pos += 400 + rng.Intn(200)
		}

	default:
		// High: corrupt sync word, corrupt ID3 tags, truncate mid-frame.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Break MPEG sync words throughout the file.
			for i := 0; i < len(out)-1; i++ {
				if out[i] == 0xFF && (out[i+1]&0xE0) == 0xE0 {
					if rng.Float64() < intensity*0.5 {
						out[i] = byte(rng.Intn(255))   // break sync
						out[i+1] = byte(rng.Intn(128)) // ensure not a valid sync
					}
				}
			}
		case 1:
			// Corrupt ID3v2 tags.
			if len(out) >= 10 && string(out[0:3]) == "ID3" {
				// Corrupt ID3 size (syncsafe integer in bytes 6-9).
				rng.Read(out[6:10])
				// Corrupt version.
				out[3] = byte(rng.Intn(256))
				out[4] = byte(rng.Intn(256))
			}
		case 2:
			// Corrupt first sync word and inject garbage.
			if frameStart >= 0 && frameStart+2 < len(out) {
				out[frameStart] = 0x00
				out[frameStart+1] = 0x00
			}
		}
		// Truncate mid-frame.
		cutAt := int(float64(len(out)) * 0.6)
		if cutAt < 10 {
			cutAt = 10
		}
		if cutAt < len(out) {
			out = out[:cutAt]
		}
	}
	return out
}

// =============================================================================
// OGG corruption
// =============================================================================

// corruptOGG applies OGG-specific corruption.
//
// OGG structure:
// Page header (27+ bytes): "OggS"(4) + version(1) + header_type(1) + granule_position(8) +
//
//	serial_number(4) + page_sequence(4) + checksum(4) + page_segments(1) +
//	segment_table(page_segments bytes)
//
// Page data follows segment table.
func corruptOGG(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) < 28 {
		return corruptGeneric(data, intensity, rng)
	}
	out := make([]byte, len(data))
	copy(out, data)

	level := intensityLevel(intensity)

	switch level {
	case 0:
		// Low: flip bits in audio data pages (preserving page headers).
		pages := findOggPages(out)
		if len(pages) == 0 {
			return corruptGeneric(out, intensity, rng)
		}
		for _, pageOffset := range pages {
			if pageOffset+27 >= len(out) {
				continue
			}
			numSegments := int(out[pageOffset+26])
			dataStart := pageOffset + 27 + numSegments
			if dataStart >= len(out) {
				continue
			}
			// Calculate total data size from segment table.
			dataSize := 0
			for s := 0; s < numSegments && pageOffset+27+s < len(out); s++ {
				dataSize += int(out[pageOffset+27+s])
			}
			dataEnd := dataStart + dataSize
			if dataEnd > len(out) {
				dataEnd = len(out)
			}
			actualDataLen := dataEnd - dataStart
			if actualDataLen <= 0 {
				continue
			}
			numFlips := int(float64(actualDataLen)*intensity*0.03) + 1
			for i := 0; i < numFlips; i++ {
				pos := dataStart + rng.Intn(actualDataLen)
				out[pos] ^= 1 << uint(rng.Intn(8))
			}
		}

	case 1:
		// Medium: corrupt page header CRC, granule position.
		pages := findOggPages(out)
		if len(pages) == 0 {
			return corruptGeneric(out, intensity, rng)
		}
		for _, pageOffset := range pages {
			if pageOffset+26 >= len(out) {
				continue
			}
			if rng.Float64() < intensity+0.3 {
				variant := rng.Intn(2)
				switch variant {
				case 0:
					// Corrupt CRC (bytes 22-25 from page start).
					if pageOffset+26 <= len(out) {
						rng.Read(out[pageOffset+22 : pageOffset+26])
					}
				case 1:
					// Corrupt granule position (bytes 6-13 from page start).
					if pageOffset+14 <= len(out) {
						rng.Read(out[pageOffset+6 : pageOffset+14])
					}
				}
			}
		}

	default:
		// High: corrupt page serial numbers, remove pages, truncate.
		pages := findOggPages(out)
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Different serial numbers on different pages (breaks stream continuity).
			for _, pageOffset := range pages {
				if pageOffset+18 < len(out) {
					putLe32(out[pageOffset+14:], uint32(rng.Int31()))
				}
			}
		case 1:
			// Remove a page from the middle by zeroing its capture pattern.
			if len(pages) > 2 {
				midPage := pages[len(pages)/2]
				if midPage+4 < len(out) {
					copy(out[midPage:midPage+4], "\x00\x00\x00\x00")
				}
			}
		case 2:
			// Corrupt version bytes (should be 0).
			for _, pageOffset := range pages {
				if pageOffset+5 < len(out) {
					out[pageOffset+4] = byte(rng.Intn(255) + 1)
				}
			}
		}
		// Truncate.
		cutAt := int(float64(len(out)) * 0.5)
		if cutAt < 28 {
			cutAt = 28
		}
		if cutAt < len(out) {
			out = out[:cutAt]
		}
	}
	return out
}

// =============================================================================
// FLAC corruption
// =============================================================================

// corruptFLAC applies FLAC-specific corruption.
//
// FLAC structure:
// Magic: "fLaC" (4 bytes)
// Metadata blocks: type_and_last(1) + length(3) + data
//
//	STREAMINFO (type 0, 34 bytes): min_block(2) + max_block(2) + min_frame(3) +
//	  max_frame(3) + sample_rate(20 bits) + channels(3 bits) + bits_per_sample(5 bits) +
//	  total_samples(36 bits) + md5(16)
//
// Audio frames follow metadata blocks.
func corruptFLAC(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) < 42 { // 4 magic + 4 block header + 34 STREAMINFO minimum
		return corruptGeneric(data, intensity, rng)
	}
	out := make([]byte, len(data))
	copy(out, data)

	level := intensityLevel(intensity)

	switch level {
	case 0:
		// Low: flip bits in audio frame data (skip magic + metadata blocks).
		audioStart := findFLACAudioStart(out)
		if audioStart >= len(out) {
			return corruptGeneric(out, intensity, rng)
		}
		dataLen := len(out) - audioStart
		numFlips := int(float64(dataLen)*intensity*0.03) + 1
		for i := 0; i < numFlips; i++ {
			pos := audioStart + rng.Intn(dataLen)
			out[pos] ^= 1 << uint(rng.Intn(8))
		}

	case 1:
		// Medium: corrupt STREAMINFO metadata (sample rate, channels, bits per sample).
		// STREAMINFO is the first metadata block, starting at offset 4.
		// Block header: 1 byte (type + is_last flag) + 3 bytes length.
		// STREAMINFO data starts at offset 8.
		if len(out) < 42 {
			return corruptGeneric(out, intensity, rng)
		}
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt sample rate (bytes 18-20 from file start, 20 bits starting at bit 0 of byte 18).
			// Bytes 18-19-20 hold: sample_rate(20 bits) + channels(3 bits) + bps(5 bits) + ...
			// Set sample rate to 0 (invalid) by clearing those bits.
			out[18] = 0
			out[19] = 0
			out[20] = out[20] & 0x0F // clear top 4 bits (last 4 of sample rate)
		case 1:
			// Corrupt channels (3 bits at bits 4-6 of byte 20) to invalid value.
			// Set to 0 (invalid, FLAC stores channels-1, so 0 means 1 channel).
			// Set to 7 (8 channels) for likely mismatch.
			out[20] = (out[20] & 0xF1) | (7 << 1) // channels-1 = 7 (8 channels)
		case 2:
			// Corrupt bits per sample (5 bits: bit 0 of byte 20 + bits 4-7 of byte 21).
			// Set to 0 (invalid, FLAC stores bps-1).
			out[20] = out[20] & 0xFE // clear bit 0
			out[21] = out[21] & 0x0F // clear top 4 bits
		}

	default:
		// High: corrupt fLaC magic, corrupt metadata block types, truncate.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt fLaC magic.
			badMagics := []string{"fLaX", "FLAC", "flac", "\x00\x00\x00\x00"}
			chosen := badMagics[rng.Intn(len(badMagics))]
			copy(out[0:4], chosen)
		case 1:
			// Corrupt metadata block type to unknown values.
			if len(out) > 4 {
				// Block type is in top 7 bits of byte 4. Valid types: 0-6, 127.
				// Set to invalid type (e.g., 50).
				isLast := out[4] & 0x80
				out[4] = isLast | (50 & 0x7F)
			}
		case 2:
			// Corrupt metadata block length to massive value.
			if len(out) > 7 {
				out[5] = 0xFF
				out[6] = 0xFF
				out[7] = 0xFF // 16MB block length
			}
		}
		// Truncate.
		cutAt := int(float64(len(out)) * 0.4)
		if cutAt < 42 {
			cutAt = 42
		}
		if cutAt < len(out) {
			out = out[:cutAt]
		}
	}
	return out
}

// =============================================================================
// MP4 corruption
// =============================================================================

// corruptMP4 applies MP4-specific corruption.
//
// MP4 structure (ISO BMFF):
// Boxes (atoms): size(4) + type(4) + data
// Key boxes: ftyp (file type), moov (movie metadata), mdat (media data),
//
//	trak (track), stbl (sample table), stsd (sample description)
//
// size=0 means box extends to EOF. size=1 means 64-bit extended size follows.
func corruptMP4(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) < 16 {
		return corruptGeneric(data, intensity, rng)
	}
	out := make([]byte, len(data))
	copy(out, data)

	level := intensityLevel(intensity)

	switch level {
	case 0:
		// Low: flip bits in mdat box data.
		mdatOffset := findMP4Box(out, "mdat")
		if mdatOffset < 0 {
			// No mdat found; corrupt the latter half of the file as generic media data.
			dataStart := len(out) / 2
			if dataStart < 8 {
				dataStart = 8
			}
			dataLen := len(out) - dataStart
			if dataLen > 0 {
				numFlips := int(float64(dataLen)*intensity*0.03) + 1
				for i := 0; i < numFlips; i++ {
					pos := dataStart + rng.Intn(dataLen)
					out[pos] ^= 1 << uint(rng.Intn(8))
				}
			}
			return out
		}
		boxSize := int(be32(out[mdatOffset:]))
		dataStart := mdatOffset + 8
		dataEnd := mdatOffset + boxSize
		if boxSize == 0 {
			dataEnd = len(out)
		}
		if dataEnd > len(out) {
			dataEnd = len(out)
		}
		if dataStart >= dataEnd {
			return corruptGeneric(out, intensity, rng)
		}
		dataLen := dataEnd - dataStart
		numFlips := int(float64(dataLen)*intensity*0.03) + 1
		for i := 0; i < numFlips; i++ {
			pos := dataStart + rng.Intn(dataLen)
			out[pos] ^= 1 << uint(rng.Intn(8))
		}

	case 1:
		// Medium: corrupt box sizes (moov, trak sizes too large/small), corrupt track header.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt moov box size.
			moovOffset := findMP4Box(out, "moov")
			if moovOffset >= 0 && moovOffset+4 <= len(out) {
				badSizes := []uint32{0, 8, uint32(len(out) * 2), uint32(rng.Intn(100) + 1)}
				putBe32(out[moovOffset:], badSizes[rng.Intn(len(badSizes))])
			}
		case 1:
			// Corrupt trak box size.
			trakOffset := findMP4Box(out, "trak")
			if trakOffset >= 0 && trakOffset+4 <= len(out) {
				putBe32(out[trakOffset:], uint32(rng.Intn(50)+1))
			}
		case 2:
			// Corrupt tkhd (track header) dimensions.
			tkhdOffset := findMP4Box(out, "tkhd")
			if tkhdOffset >= 0 {
				// tkhd version 0: width at offset 76, height at offset 80 (fixed-point 16.16).
				dimOffset := tkhdOffset + 8 + 76
				if dimOffset+8 <= len(out) {
					putBe32(out[dimOffset:], uint32(rng.Intn(1<<31)))   // width
					putBe32(out[dimOffset+4:], uint32(rng.Intn(1<<31))) // height
				}
			}
		}

	default:
		// High: remove essential boxes, corrupt ftyp, overlap boundaries, truncate mdat.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt ftyp brand.
			ftypOffset := findMP4Box(out, "ftyp")
			if ftypOffset >= 0 && ftypOffset+12 <= len(out) {
				// Major brand is at offset 8 from box start.
				copy(out[ftypOffset+8:ftypOffset+12], "XXXX")
			}
		case 1:
			// Remove essential boxes by zeroing their type field.
			for _, boxType := range []string{"stbl", "stsd", "stts", "stsc", "stsz"} {
				offset := findMP4Box(out, boxType)
				if offset >= 0 && offset+8 <= len(out) {
					copy(out[offset+4:offset+8], "\x00\x00\x00\x00")
				}
			}
		case 2:
			// Overlapping box boundaries: set a box size that overlaps the next box.
			moovOffset := findMP4Box(out, "moov")
			if moovOffset >= 0 && moovOffset+4 <= len(out) {
				// Set moov size to extend past end of file.
				putBe32(out[moovOffset:], uint32(len(out)-moovOffset+1000))
			}
		}
		// Truncate mdat.
		mdatOffset := findMP4Box(out, "mdat")
		if mdatOffset >= 0 {
			cutAt := mdatOffset + 8 + rng.Intn(max(1, (len(out)-mdatOffset-8)/3))
			if cutAt < len(out) {
				out = out[:cutAt]
			}
		} else {
			cutAt := int(float64(len(out)) * 0.5)
			if cutAt < 16 {
				cutAt = 16
			}
			if cutAt < len(out) {
				out = out[:cutAt]
			}
		}
	}
	return out
}

// =============================================================================
// WebM corruption
// =============================================================================

// corruptWebM applies WebM-specific corruption.
//
// WebM uses EBML (Extensible Binary Meta Language) container format.
// Structure:
// EBML header: 0x1A 0x45 0xDF 0xA3 (EBML element ID)
// Segment: 0x18 0x53 0x80 0x67
// Contains: Info, Tracks, Cluster elements
// Cluster: 0x1F 0x43 0xB6 0x75
// SimpleBlock/Block within clusters contain actual media data.
func corruptWebM(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) < 16 {
		return corruptGeneric(data, intensity, rng)
	}
	out := make([]byte, len(data))
	copy(out, data)

	level := intensityLevel(intensity)

	switch level {
	case 0:
		// Low: flip bits in cluster/block data.
		// Find first Cluster element (0x1F 0x43 0xB6 0x75).
		clusterOffset := findEBMLElement(out, []byte{0x1F, 0x43, 0xB6, 0x75})
		if clusterOffset < 0 {
			// No cluster found, corrupt second half of data.
			dataStart := len(out) / 2
			if dataStart < 4 {
				dataStart = 4
			}
			dataLen := len(out) - dataStart
			if dataLen > 0 {
				numFlips := int(float64(dataLen)*intensity*0.03) + 1
				for i := 0; i < numFlips; i++ {
					pos := dataStart + rng.Intn(dataLen)
					out[pos] ^= 1 << uint(rng.Intn(8))
				}
			}
			return out
		}
		// Corrupt data after cluster header (skip element ID + size).
		dataStart := clusterOffset + 8
		if dataStart >= len(out) {
			dataStart = clusterOffset + 4
		}
		if dataStart >= len(out) {
			return corruptGeneric(out, intensity, rng)
		}
		dataLen := len(out) - dataStart
		numFlips := int(float64(dataLen)*intensity*0.03) + 1
		for i := 0; i < numFlips; i++ {
			pos := dataStart + rng.Intn(dataLen)
			out[pos] ^= 1 << uint(rng.Intn(8))
		}

	case 1:
		// Medium: corrupt EBML element sizes, corrupt track codec ID.
		variant := rng.Intn(2)
		switch variant {
		case 0:
			// Corrupt Segment element size.
			segmentOffset := findEBMLElement(out, []byte{0x18, 0x53, 0x80, 0x67})
			if segmentOffset >= 0 && segmentOffset+8 < len(out) {
				// EBML sizes are variable-width. Corrupt the bytes after the element ID.
				for i := 4; i < 8 && segmentOffset+i < len(out); i++ {
					out[segmentOffset+i] = byte(rng.Intn(256))
				}
			}
		case 1:
			// Corrupt Tracks element or codec info.
			// Tracks element: 0x16 0x54 0xAE 0x6B
			tracksOffset := findEBMLElement(out, []byte{0x16, 0x54, 0xAE, 0x6B})
			if tracksOffset >= 0 {
				// Corrupt some bytes within the tracks element.
				corruptStart := tracksOffset + 8
				if corruptStart+20 < len(out) {
					for i := 0; i < 10; i++ {
						pos := corruptStart + rng.Intn(min(100, len(out)-corruptStart))
						out[pos] = byte(rng.Intn(256))
					}
				}
			}
		}

	default:
		// High: corrupt EBML header magic, remove essential elements, truncate.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt EBML header magic.
			if len(out) >= 4 {
				out[0] = byte(rng.Intn(256))
				out[1] = byte(rng.Intn(256))
			}
		case 1:
			// Zero out Segment element ID (breaks container structure).
			segmentOffset := findEBMLElement(out, []byte{0x18, 0x53, 0x80, 0x67})
			if segmentOffset >= 0 && segmentOffset+4 < len(out) {
				out[segmentOffset] = 0
				out[segmentOffset+1] = 0
				out[segmentOffset+2] = 0
				out[segmentOffset+3] = 0
			}
		case 2:
			// Remove Tracks element by zeroing its ID.
			tracksOffset := findEBMLElement(out, []byte{0x16, 0x54, 0xAE, 0x6B})
			if tracksOffset >= 0 && tracksOffset+4 < len(out) {
				copy(out[tracksOffset:tracksOffset+4], "\x00\x00\x00\x00")
			}
		}
		// Truncate.
		cutAt := int(float64(len(out)) * 0.4)
		if cutAt < 16 {
			cutAt = 16
		}
		if cutAt < len(out) {
			out = out[:cutAt]
		}
	}
	return out
}

// =============================================================================
// AVI corruption
// =============================================================================

// corruptAVI applies AVI-specific corruption.
//
// AVI structure (RIFF-based):
// RIFF(4) + size(4) + "AVI "(4)
// LIST hdrl: avih (main header), strl (stream headers)
// LIST movi: actual audio/video data chunks (00dc, 01wb, etc.)
// idx1: optional index chunk
// avih (56 bytes): dwMicroSecPerFrame(4) + dwMaxBytesPerSec(4) + ...
//
//	dwWidth at offset 32, dwHeight at offset 36 from avih data start
func corruptAVI(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) < 32 {
		return corruptGeneric(data, intensity, rng)
	}
	out := make([]byte, len(data))
	copy(out, data)

	level := intensityLevel(intensity)

	switch level {
	case 0:
		// Low: flip bits in movi chunk data.
		moviOffset := findRIFFSubChunk(out, "movi")
		if moviOffset < 0 {
			// Fall back to corrupting latter half.
			dataStart := len(out) / 2
			dataLen := len(out) - dataStart
			if dataLen > 0 {
				numFlips := int(float64(dataLen)*intensity*0.03) + 1
				for i := 0; i < numFlips; i++ {
					pos := dataStart + rng.Intn(dataLen)
					out[pos] ^= 1 << uint(rng.Intn(8))
				}
			}
			return out
		}
		dataStart := moviOffset + 12 // LIST + size + "movi"
		if dataStart >= len(out) {
			return corruptGeneric(out, intensity, rng)
		}
		dataLen := len(out) - dataStart
		numFlips := int(float64(dataLen)*intensity*0.03) + 1
		for i := 0; i < numFlips; i++ {
			pos := dataStart + rng.Intn(dataLen)
			out[pos] ^= 1 << uint(rng.Intn(8))
		}

	case 1:
		// Medium: corrupt stream header dimensions, frame rate.
		avihOffset := findRIFFSubChunk(out, "avih")
		if avihOffset < 0 {
			return corruptGeneric(out, intensity, rng)
		}
		avihDataStart := avihOffset + 8 // "avih" + size
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt dwMicroSecPerFrame (frame timing).
			if avihDataStart+4 <= len(out) {
				putLe32(out[avihDataStart:], uint32(rng.Intn(1<<31)))
			}
		case 1:
			// Corrupt dwWidth.
			if avihDataStart+36 <= len(out) {
				putLe32(out[avihDataStart+32:], uint32(rng.Intn(65536)+1))
			}
		case 2:
			// Corrupt dwHeight.
			if avihDataStart+40 <= len(out) {
				putLe32(out[avihDataStart+36:], uint32(rng.Intn(65536)+1))
			}
		}

	default:
		// High: corrupt RIFF size, corrupt index entries, truncate.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt RIFF file size.
			putLe32(out[4:], uint32(rng.Intn(1<<31)))
		case 1:
			// Corrupt idx1 index entries.
			idx1Offset := findWAVChunk(out, "idx1") // idx1 uses same RIFF chunk format
			if idx1Offset >= 0 && idx1Offset+16 <= len(out) {
				idxSize := int(le32(out[idx1Offset+4:]))
				idxDataStart := idx1Offset + 8
				idxDataEnd := idxDataStart + idxSize
				if idxDataEnd > len(out) {
					idxDataEnd = len(out)
				}
				// Each index entry is 16 bytes. Corrupt offsets within entries.
				for pos := idxDataStart; pos+16 <= idxDataEnd; pos += 16 {
					if rng.Float64() < intensity+0.3 {
						// Corrupt the chunk offset (bytes 8-11 of entry).
						putLe32(out[pos+8:], uint32(rng.Intn(1<<31)))
					}
				}
			}
		case 2:
			// Change AVI fourcc to something else.
			if len(out) >= 12 {
				copy(out[8:12], "AVIX") // non-standard
			}
		}
		// Truncate.
		cutAt := int(float64(len(out)) * 0.5)
		if cutAt < 32 {
			cutAt = 32
		}
		if cutAt < len(out) {
			out = out[:cutAt]
		}
	}
	return out
}

// =============================================================================
// MPEG-TS corruption
// =============================================================================

// corruptTS applies MPEG Transport Stream-specific corruption.
//
// TS structure: fixed 188-byte packets.
// Each packet: sync_byte(1: 0x47) + PID and flags(3) + payload(184)
// Packet header bits: sync(8) + TEI(1) + PUSI(1) + priority(1) + PID(13) +
//
//	scrambling(2) + adaptation(2) + continuity(4)
//
// PID 0x0000 = PAT, PID 0x0001 = CAT, PID 0x0010-0x001F = Network Information
func corruptTS(data []byte, intensity float64, rng *rand.Rand) []byte {
	if len(data) < 188 {
		return corruptGeneric(data, intensity, rng)
	}
	out := make([]byte, len(data))
	copy(out, data)

	level := intensityLevel(intensity)

	// Find the first sync byte alignment.
	syncOffset := -1
	for i := 0; i < min(188, len(out)); i++ {
		if out[i] == 0x47 {
			// Verify it's a real sync by checking next packet.
			if i+188 < len(out) && out[i+188] == 0x47 {
				syncOffset = i
				break
			}
			// Single packet file.
			if len(out)-i >= 188 {
				syncOffset = i
				break
			}
		}
	}
	if syncOffset < 0 {
		return corruptGeneric(out, intensity, rng)
	}

	switch level {
	case 0:
		// Low: flip bits in PES payload data (preserving 0x47 sync bytes).
		for pkt := syncOffset; pkt+188 <= len(out); pkt += 188 {
			// Payload starts at byte 4 of each packet (simplified; ignoring adaptation field).
			payloadStart := pkt + 4
			payloadEnd := pkt + 188
			if payloadStart >= payloadEnd {
				continue
			}
			payloadLen := payloadEnd - payloadStart
			numFlips := int(float64(payloadLen)*intensity*0.02) + 1
			for i := 0; i < numFlips; i++ {
				pos := payloadStart + rng.Intn(payloadLen)
				out[pos] ^= 1 << uint(rng.Intn(8))
			}
		}

	case 1:
		// Medium: corrupt PID values, corrupt continuity counters.
		variant := rng.Intn(2)
		for pkt := syncOffset; pkt+188 <= len(out); pkt += 188 {
			if rng.Float64() > intensity+0.2 {
				continue
			}
			switch variant {
			case 0:
				// Corrupt PID (13 bits across bytes 1-2 of packet).
				if pkt+3 < len(out) {
					newPID := uint16(rng.Intn(8192))
					out[pkt+1] = (out[pkt+1] & 0xE0) | byte(newPID>>8)
					out[pkt+2] = byte(newPID & 0xFF)
				}
			case 1:
				// Corrupt continuity counter (4 bits in byte 3).
				if pkt+4 <= len(out) {
					out[pkt+3] = (out[pkt+3] & 0xF0) | byte(rng.Intn(16))
				}
			}
		}

	default:
		// High: corrupt sync bytes, corrupt PAT/PMT tables, inject wrong PIDs.
		variant := rng.Intn(3)
		switch variant {
		case 0:
			// Corrupt sync bytes (change 0x47 to random values).
			for pkt := syncOffset; pkt+188 <= len(out); pkt += 188 {
				if rng.Float64() < intensity*0.5 {
					out[pkt] = byte(rng.Intn(256)) // no longer 0x47
				}
			}
		case 1:
			// Corrupt PAT/PMT tables (PID 0x0000 and 0x0001).
			for pkt := syncOffset; pkt+188 <= len(out); pkt += 188 {
				if pkt+3 >= len(out) {
					continue
				}
				pid := (uint16(out[pkt+1]&0x1F) << 8) | uint16(out[pkt+2])
				if pid == 0x0000 || pid == 0x0001 {
					// Corrupt the payload.
					payloadStart := pkt + 4
					payloadEnd := pkt + 188
					if payloadEnd > len(out) {
						payloadEnd = len(out)
					}
					for i := payloadStart; i < payloadEnd; i++ {
						out[i] = byte(rng.Intn(256))
					}
				}
			}
		case 2:
			// Inject packets with wrong PIDs in the middle.
			if len(out) >= 376 { // At least 2 packets
				midPkt := syncOffset + 188*(rng.Intn(max(1, (len(out)-syncOffset)/188-1)))
				if midPkt+188 <= len(out) {
					// Set PID to null PID (0x1FFF) — should be empty.
					out[midPkt+1] = (out[midPkt+1] & 0xE0) | 0x1F
					out[midPkt+2] = 0xFF
				}
			}
		}
		// Truncate mid-packet.
		numPackets := (len(out) - syncOffset) / 188
		cutPackets := numPackets/2 + 1
		cutAt := syncOffset + cutPackets*188 + rng.Intn(94) // cut mid-packet
		if cutAt < 188 {
			cutAt = 188
		}
		if cutAt < len(out) {
			out = out[:cutAt]
		}
	}
	return out
}

// =============================================================================
// HLS corruption (enhanced)
// =============================================================================

// corruptHLS corrupts an HLS (.m3u8) playlist by introducing:
// invalid segment URLs, duration mismatches, sequence number gaps,
// missing required tags, encryption chaos, and nested master playlists.
func corruptHLS(data []byte) []byte {
	variant := rand.Intn(7)
	original := string(data)
	switch variant {
	case 0:
		// Replace segment URLs with invalid ones.
		lines := strings.Split(original, "\n")
		for i, line := range lines {
			if !strings.HasPrefix(line, "#") && strings.TrimSpace(line) != "" {
				lines[i] = "https://invalid.example.com/nonexistent-segment-" + fmt.Sprintf("%d", rand.Intn(9999)) + ".ts"
			}
		}
		return []byte(strings.Join(lines, "\n"))

	case 1:
		// Corrupt EXTINF duration values.
		lines := strings.Split(original, "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, "#EXTINF:") {
				lines[i] = fmt.Sprintf("#EXTINF:%d,", rand.Intn(900)+100)
			}
		}
		return []byte(strings.Join(lines, "\n"))

	case 2:
		// Inject sequence gaps by mangling EXT-X-MEDIA-SEQUENCE.
		lines := strings.Split(original, "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, "#EXT-X-MEDIA-SEQUENCE:") {
				lines[i] = fmt.Sprintf("#EXT-X-MEDIA-SEQUENCE:%d", rand.Intn(100000)+9999)
			}
		}
		mid := len(lines) / 2
		newLines := make([]string, 0, len(lines)+1)
		newLines = append(newLines, lines[:mid]...)
		newLines = append(newLines, "#EXT-X-ENDLIST")
		newLines = append(newLines, lines[mid:]...)
		return []byte(strings.Join(newLines, "\n"))

	case 3:
		// Remove EXT-X-TARGETDURATION, duplicate EXT-X-DISCONTINUITY.
		lines := strings.Split(original, "\n")
		var result []string
		for _, line := range lines {
			if strings.HasPrefix(line, "#EXT-X-TARGETDURATION:") {
				continue // remove it
			}
			result = append(result, line)
			// Inject discontinuity after every segment URL.
			if !strings.HasPrefix(line, "#") && strings.TrimSpace(line) != "" {
				result = append(result, "#EXT-X-DISCONTINUITY")
				result = append(result, "#EXT-X-DISCONTINUITY") // duplicate
			}
		}
		return []byte(strings.Join(result, "\n"))

	case 4:
		// Inject invalid EXT-X-BYTERANGE.
		lines := strings.Split(original, "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, "#EXTINF:") {
				// Insert a byterange with negative offset before the segment.
				lines[i] = line + "\n#EXT-X-BYTERANGE:-500@-100"
			}
		}
		return []byte(strings.Join(lines, "\n"))

	case 5:
		// Mix segment encryption with invalid key URI.
		lines := strings.Split(original, "\n")
		var result []string
		for i, line := range lines {
			result = append(result, line)
			if strings.HasPrefix(line, "#EXTINF:") && i%2 == 0 {
				result = append(result, `#EXT-X-KEY:METHOD=AES-128,URI="https://invalid.example.com/key-`+fmt.Sprintf("%d", rand.Intn(999))+`",IV=0x00000000000000000000000000000000`)
			}
		}
		return []byte(strings.Join(result, "\n"))

	case 6:
		// Nested master playlists (master referencing another master).
		return []byte(`#EXTM3U
#EXT-X-STREAM-INF:BANDWIDTH=1000000
https://invalid.example.com/master2.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=2000000
https://invalid.example.com/master3.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=500000
https://invalid.example.com/master4.m3u8
`)
	}
	return data
}

// =============================================================================
// DASH corruption (enhanced)
// =============================================================================

// corruptDASH corrupts a DASH (.mpd) manifest by introducing
// invalid XML, duration mismatches, broken segment URLs, circular references,
// impossible values, and conflicting mime types.
func corruptDASH(data []byte) []byte {
	variant := rand.Intn(7)
	original := string(data)
	switch variant {
	case 0:
		// Truncate the XML mid-element to produce a parse error.
		cutAt := len(original) / 2
		if cutAt < 1 {
			cutAt = 1
		}
		return []byte(original[:cutAt])

	case 1:
		// Replace mediaPresentationDuration with an invalid value.
		original = strings.ReplaceAll(original, "mediaPresentationDuration=", "mediaPresentationDuration=\"INVALID_DURATION\" data-orig=")
		return []byte(original)

	case 2:
		// Inject a malformed segment template.
		inject := `<SegmentTemplate timescale="NOTANUMBER" media="$Number$.ts" startNumber="NOTANUMBER"/>`
		insertAt := strings.Index(original, "</AdaptationSet>")
		if insertAt < 0 {
			return []byte(original + inject)
		}
		return []byte(original[:insertAt] + inject + original[insertAt:])

	case 3:
		// Circular period references.
		inject := `<Period id="circular-1" start="PT0S"><AdaptationSet><Representation id="loop" bandwidth="0"><BaseURL>../manifest.mpd</BaseURL></Representation></AdaptationSet></Period>`
		insertAt := strings.Index(original, "</MPD>")
		if insertAt < 0 {
			return []byte(original + inject)
		}
		return []byte(original[:insertAt] + inject + original[insertAt:])

	case 4:
		// Impossible bandwidth values and negative durations.
		original = strings.ReplaceAll(original, "bandwidth=", "bandwidth=\"-999999\" data-orig-bandwidth=")
		original = strings.ReplaceAll(original, "duration=", "duration=\"PT-1S\" data-orig-duration=")
		return []byte(original)

	case 5:
		// Missing required attributes in Representation.
		// Remove bandwidth attribute from Representation elements.
		result := original
		for {
			idx := strings.Index(result, "<Representation ")
			if idx < 0 {
				break
			}
			endIdx := strings.Index(result[idx:], ">")
			if endIdx < 0 {
				break
			}
			tag := result[idx : idx+endIdx+1]
			// Remove bandwidth, id, and mimeType from the tag.
			newTag := tag
			for _, attr := range []string{"bandwidth", "id", "mimeType", "codecs"} {
				attrIdx := strings.Index(newTag, attr+"=")
				if attrIdx >= 0 {
					// Find the end of this attribute's value.
					quoteStart := strings.IndexByte(newTag[attrIdx:], '"')
					if quoteStart >= 0 {
						quoteEnd := strings.IndexByte(newTag[attrIdx+quoteStart+1:], '"')
						if quoteEnd >= 0 {
							removeEnd := attrIdx + quoteStart + 1 + quoteEnd + 1
							newTag = newTag[:attrIdx] + newTag[removeEnd:]
						}
					}
				}
			}
			result = result[:idx] + newTag + result[idx+endIdx+1:]
			// Move past this tag to avoid infinite loop.
			idx += len(newTag)
			if idx >= len(result) {
				break
			}
			remaining := result[idx:]
			nextIdx := strings.Index(remaining, "<Representation ")
			if nextIdx < 0 {
				break
			}
			result = result[:idx] + remaining // continue from where we left off
			break                              // safety: just do the first one to avoid complexity
		}
		return []byte(result)

	case 6:
		// Conflicting mimeType in AdaptationSet vs Representation.
		inject := `<AdaptationSet mimeType="video/mp4"><Representation mimeType="audio/webm" bandwidth="1000"><BaseURL>conflict.mp4</BaseURL></Representation></AdaptationSet>`
		insertAt := strings.Index(original, "</Period>")
		if insertAt < 0 {
			insertAt = strings.Index(original, "</MPD>")
		}
		if insertAt < 0 {
			return []byte(original + inject)
		}
		return []byte(original[:insertAt] + inject + original[insertAt:])
	}
	return data
}

// =============================================================================
// Helper functions
// =============================================================================

// intensityLevel converts a 0.0-1.0 intensity to 0 (low), 1 (medium), or 2 (high).
func intensityLevel(intensity float64) int {
	switch {
	case intensity < 0.33:
		return 0
	case intensity < 0.67:
		return 1
	default:
		return 2
	}
}

// be32 reads a big-endian uint32 from b.
func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// putBe32 writes a big-endian uint32 into b.
func putBe32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

// be16 reads a big-endian uint16 from b.
func be16(b []byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}

// putBe16 writes a big-endian uint16 into b.
func putBe16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

// le32 reads a little-endian uint32 from b.
func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// le16 reads a little-endian uint16 from b.
func le16(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}

// putLe32 writes a little-endian uint32 into b.
func putLe32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

// putLe16 writes a little-endian uint16 into b.
func putLe16(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}

// findJPEGMarker scans data for the two-byte JPEG marker 0xFF markerByte and returns the
// byte offset of the 0xFF byte, or -1 if not found.
// It skips the SOI (FF D8) at the start.
func findJPEGMarker(data []byte, markerByte byte) int {
	for i := 2; i < len(data)-1; i++ {
		if data[i] == 0xFF && data[i+1] == markerByte {
			return i
		}
	}
	return -1
}

// findWAVChunk scans data for a 4-byte RIFF chunk identifier (e.g. "fmt ", "data") and
// returns the offset of the identifier, or -1 if not found.
func findWAVChunk(data []byte, id string) int {
	if len(id) != 4 {
		return -1
	}
	target := []byte(id)
	for i := 0; i <= len(data)-8; i++ {
		if data[i] == target[0] && data[i+1] == target[1] &&
			data[i+2] == target[2] && data[i+3] == target[3] {
			return i
		}
	}
	return -1
}

// findRIFFChunk scans a RIFF data region for a 4-byte chunk identifier.
// Similar to findWAVChunk but scans within a sub-region.
func findRIFFChunk(data []byte, id string) int {
	if len(id) != 4 || len(data) < 8 {
		return -1
	}
	target := []byte(id)
	for i := 0; i <= len(data)-8; i++ {
		if data[i] == target[0] && data[i+1] == target[1] &&
			data[i+2] == target[2] && data[i+3] == target[3] {
			return i
		}
	}
	return -1
}

// findRIFFSubChunk scans data for a RIFF LIST sub-chunk with the given list type
// (e.g. "movi", "hdrl"). Returns offset of the LIST keyword, or -1.
func findRIFFSubChunk(data []byte, listType string) int {
	if len(listType) != 4 || len(data) < 12 {
		return -1
	}
	target := []byte(listType)
	for i := 0; i <= len(data)-12; i++ {
		if data[i] == 'L' && data[i+1] == 'I' && data[i+2] == 'S' && data[i+3] == 'T' {
			if i+8+4 <= len(data) &&
				data[i+8] == target[0] && data[i+8+1] == target[1] &&
				data[i+8+2] == target[2] && data[i+8+3] == target[3] {
				return i
			}
		}
	}
	return -1
}

// findMP3Frame finds the first MPEG audio frame sync in data.
// MPEG sync: 0xFF followed by byte with top 3 bits set (0xE0).
// Returns offset of the sync byte, or -1.
func findMP3Frame(data []byte) int {
	// Skip ID3v2 tag if present.
	start := 0
	if len(data) >= 10 && string(data[0:3]) == "ID3" {
		// ID3v2 size is a 28-bit syncsafe integer in bytes 6-9.
		size := (int(data[6]) << 21) | (int(data[7]) << 14) | (int(data[8]) << 7) | int(data[9])
		start = 10 + size
		if start >= len(data) {
			return -1
		}
	}
	for i := start; i < len(data)-1; i++ {
		if data[i] == 0xFF && (data[i+1]&0xE0) == 0xE0 {
			return i
		}
	}
	return -1
}

// findOggPages returns the offsets of all OGG page capture patterns ("OggS") in data.
func findOggPages(data []byte) []int {
	var pages []int
	for i := 0; i <= len(data)-4; i++ {
		if data[i] == 'O' && data[i+1] == 'g' && data[i+2] == 'g' && data[i+3] == 'S' {
			pages = append(pages, i)
		}
	}
	return pages
}

// findFLACAudioStart returns the byte offset where FLAC audio frames begin
// (after magic + all metadata blocks).
func findFLACAudioStart(data []byte) int {
	if len(data) < 8 {
		return len(data)
	}
	offset := 4 // skip "fLaC" magic
	for offset+4 <= len(data) {
		blockHeader := data[offset]
		isLast := (blockHeader & 0x80) != 0
		blockLen := int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4 + blockLen
		if isLast {
			break
		}
	}
	if offset > len(data) {
		offset = len(data)
	}
	return offset
}

// findEBMLElement searches for an EBML element by its multi-byte ID.
// Returns the offset of the ID, or -1 if not found.
func findEBMLElement(data []byte, id []byte) int {
	if len(id) == 0 || len(data) < len(id) {
		return -1
	}
	return bytes.Index(data, id)
}

// findMP4Box searches for an MP4/ISO BMFF box by its 4-byte type.
// It walks the box structure starting from the beginning.
// Returns the offset of the box (at its size field), or -1 if not found.
func findMP4Box(data []byte, boxType string) int {
	return findMP4BoxRecursive(data, boxType, 0, len(data))
}

// findMP4BoxRecursive searches for a box type within a byte range,
// recursively descending into container boxes.
func findMP4BoxRecursive(data []byte, boxType string, start, end int) int {
	containerBoxes := map[string]bool{
		"moov": true, "trak": true, "mdia": true, "minf": true,
		"stbl": true, "edts": true, "dinf": true, "udta": true,
	}

	offset := start
	for offset+8 <= end {
		boxSize := int(be32(data[offset:]))
		if boxSize < 8 {
			if boxSize == 0 {
				// Box extends to end of data.
				boxSize = end - offset
			} else {
				break // invalid
			}
		}
		boxEnd := offset + boxSize
		if boxEnd > end {
			boxEnd = end
		}
		currentType := string(data[offset+4 : offset+8])
		if currentType == boxType {
			return offset
		}
		// Recurse into container boxes.
		if containerBoxes[currentType] && boxSize > 8 {
			found := findMP4BoxRecursive(data, boxType, offset+8, boxEnd)
			if found >= 0 {
				return found
			}
		}
		offset = boxEnd
	}
	return -1
}
