package media

import (
	"bytes"
	"image/gif"
)

// encodeGIFHelper wraps gif.EncodeAll for use from infinite.go.
// This lives in its own file to avoid duplicate import declarations.
func encodeGIFHelper(w *bytes.Buffer, anim *gifAnim) {
	g := &gif.GIF{
		Image: anim.Image,
		Delay: anim.Delay,
	}
	_ = gif.EncodeAll(w, g)
}
