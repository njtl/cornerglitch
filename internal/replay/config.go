package replay

// Config controls replay behavior.
type Config struct {
	TimingMode string  `json:"timing_mode"` // "exact", "scaled", "burst"
	Speed      float64 `json:"speed"`       // multiplier for "scaled" mode (default 1.0)
	FilterPath string  `json:"filter_path"` // only replay paths matching this prefix
	Loop       bool    `json:"loop"`        // loop playback when reaching end
	MaxPackets int     `json:"max_packets"` // 0 = unlimited
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		TimingMode: "burst",
		Speed:      1.0,
	}
}
