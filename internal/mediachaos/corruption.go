package mediachaos

import (
	"math/rand"
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
		// Walk the chunk list starting at offset 8, corrupt only IDAT data bytes.
		offset := 8
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
				break // corrupt first IDAT only
			}
			offset = dataEnd + 4 // skip CRC
		}

	case 1:
		// Medium: corrupt CRC values in one or more chunks.
		offset := 8
		corrupted := 0
		maxCorrupt := int(intensity*5) + 1
		for offset+8 <= len(out) && corrupted < maxCorrupt {
			chunkLen := int(be32(out[offset:]))
			crcStart := offset + 8 + chunkLen
			if crcStart+4 > len(out) {
				break
			}
			// Overwrite CRC with garbage.
			rng.Read(out[crcStart : crcStart+4])
			corrupted++
			offset = crcStart + 4
		}

	default:
		// High: corrupt IHDR dimensions, remove IEND, truncate IDAT.
		// Corrupt width and height in IHDR (offsets 16-23 from file start).
		if len(out) >= 24 {
			putBe32(out[16:], uint32(rng.Intn(65536)+1))
			putBe32(out[20:], uint32(rng.Intn(65536)+1))
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
	}
	return out
}

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
		// SOS segment header length is at sosOffset+2 (2 bytes big-endian).
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
		// Medium: corrupt quantization table values (DQT marker FF DB).
		dqtOffset := findJPEGMarker(out, 0xDB)
		if dqtOffset < 0 || dqtOffset+4 >= len(out) {
			return corruptGeneric(out, intensity, rng)
		}
		dqtLen := int(be16(out[dqtOffset+2:]))
		tableStart := dqtOffset + 4 // skip marker + length
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

	default:
		// High: corrupt SOF0 dimensions; remove EOI; truncate before SOS.
		sof0Offset := findJPEGMarker(out, 0xC0)
		if sof0Offset >= 0 && sof0Offset+9 < len(out) {
			// Height at sof0+5, width at sof0+7 (each 2 bytes big-endian).
			putBe16(out[sof0Offset+5:], uint16(rng.Intn(65536)+1))
			putBe16(out[sof0Offset+7:], uint16(rng.Intn(65536)+1))
		}
		// Find EOI (FF D9) and remove it by truncating.
		if len(out) >= 2 && out[len(out)-2] == 0xFF && out[len(out)-1] == 0xD9 {
			out = out[:len(out)-2]
		}
		// Truncate at a point before the likely end.
		cutAt := int(float64(len(out)) * 0.7)
		if cutAt < 4 {
			cutAt = 4
		}
		if cutAt < len(out) {
			out = out[:cutAt]
		}
	}
	return out
}

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
			// No global color table; fall back.
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
		// Medium: corrupt LZW data within Image Descriptor sub-blocks.
		// Image Descriptor starts with 0x2C; LZW minimum code size is one byte after.
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
		// After 10-byte Image Descriptor, sub-blocks start.
		subStart := imgOffset + 10 + 1 // +1 for LZW minimum code size
		// Flip bits in the first sub-block data.
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

	default:
		// High: corrupt screen descriptor dimensions; remove trailer (0x3B).
		putBe16(out[6:], uint16(rng.Intn(65536)+1))  // width
		putBe16(out[8:], uint16(rng.Intn(65536)+1))  // height
		// Remove GIF trailer byte.
		if len(out) > 0 && out[len(out)-1] == 0x3B {
			out = out[:len(out)-1]
		}
		// Truncate to drop sub-blocks.
		cutAt := int(float64(len(out)) * 0.6)
		if cutAt < 13 {
			cutAt = 13
		}
		if cutAt < len(out) {
			out = out[:cutAt]
		}
	}
	return out
}

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
		// Find data chunk — scan for "data" marker after fmt chunk.
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
		// Medium: corrupt sample rate or channel count in fmt chunk.
		fmtOffset := findWAVChunk(out, "fmt ")
		if fmtOffset < 0 || fmtOffset+24 > len(out) {
			return corruptGeneric(out, intensity, rng)
		}
		if rng.Intn(2) == 0 {
			// Corrupt sample rate (bytes 12-15 from file start, or fmtOffset+12).
			putLe32(out[fmtOffset+12:], uint32(rng.Intn(192001)+1))
		} else {
			// Corrupt channel count (bytes 10-11).
			putLe16(out[fmtOffset+10:], uint16(rng.Intn(255)+1))
		}

	default:
		// High: corrupt data chunk size; truncate samples.
		dataOffset := findWAVChunk(out, "data")
		if dataOffset >= 0 && dataOffset+8 <= len(out) {
			// Set data chunk size to a wildly wrong value.
			putLe32(out[dataOffset+4:], uint32(rng.Intn(1<<31)))
		}
		// Truncate.
		cutAt := int(float64(len(out)) * 0.4)
		if cutAt < 44 {
			cutAt = 44
		}
		if cutAt < len(out) {
			out = out[:cutAt]
		}
	}
	return out
}

// --- Helper functions ---

// intensityLevel converts a 0.0–1.0 intensity to 0 (low), 1 (medium), or 2 (high).
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
