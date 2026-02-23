package replay

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Stats tracks replay playback statistics.
type Stats struct {
	PacketsLoaded  int   `json:"packets_loaded"`
	PacketsPlayed  int   `json:"packets_played"`
	PacketsSkipped int   `json:"packets_skipped"`
	Errors         int   `json:"errors"`
	StartedAt      int64 `json:"started_at_unix,omitempty"`
	ElapsedMs      int64 `json:"elapsed_ms"`
}

// Player manages sequenced playback of captured packets.
type Player struct {
	packets []*Packet
	config  Config
	client  *http.Client

	mu      sync.Mutex
	playing atomic.Bool
	stopCh  chan struct{}

	stats Stats
}

// NewPlayer creates a Player with the given packets and configuration.
func NewPlayer(packets []*Packet, config Config) *Player {
	return &Player{
		packets: packets,
		config:  config,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		stats: Stats{
			PacketsLoaded: len(packets),
		},
	}
}

// Play replays request packets by sending them to targetURL.
func (p *Player) Play(ctx context.Context, targetURL string) error {
	if p.playing.Load() {
		return fmt.Errorf("already playing")
	}
	p.playing.Store(true)

	p.mu.Lock()
	p.stopCh = make(chan struct{})
	p.stats.StartedAt = time.Now().Unix()
	p.stats.PacketsPlayed = 0
	p.stats.PacketsSkipped = 0
	p.stats.Errors = 0
	p.mu.Unlock()

	defer p.playing.Store(false)

	start := time.Now()
	targetURL = strings.TrimRight(targetURL, "/")

	// Filter to requests only.
	var requests []*Packet
	for _, pkt := range p.packets {
		if !pkt.IsRequest {
			continue
		}
		if p.config.FilterPath != "" && !strings.HasPrefix(pkt.Path, p.config.FilterPath) {
			continue
		}
		requests = append(requests, pkt)
	}

	if len(requests) == 0 {
		return fmt.Errorf("no request packets to replay")
	}

	maxPackets := p.config.MaxPackets
	if maxPackets <= 0 {
		maxPackets = len(requests)
	}

	for {
		for i, pkt := range requests {
			if i >= maxPackets {
				break
			}

			select {
			case <-ctx.Done():
				p.mu.Lock()
				p.stats.ElapsedMs = time.Since(start).Milliseconds()
				p.mu.Unlock()
				return ctx.Err()
			case <-p.stopCh:
				p.mu.Lock()
				p.stats.ElapsedMs = time.Since(start).Milliseconds()
				p.mu.Unlock()
				return nil
			default:
			}

			// Apply timing.
			if i > 0 && p.config.TimingMode != "burst" {
				delay := requests[i].Timestamp.Sub(requests[i-1].Timestamp)
				if delay < 0 {
					delay = 0
				}
				if p.config.TimingMode == "scaled" && p.config.Speed > 0 {
					delay = time.Duration(float64(delay) / p.config.Speed)
				}
				if delay > 0 {
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						return ctx.Err()
					case <-p.stopCh:
						return nil
					}
				}
			}

			err := p.sendPacket(ctx, targetURL, pkt)

			p.mu.Lock()
			if err != nil {
				p.stats.Errors++
			} else {
				p.stats.PacketsPlayed++
			}
			p.stats.ElapsedMs = time.Since(start).Milliseconds()
			p.mu.Unlock()
		}

		if !p.config.Loop {
			break
		}
	}

	return nil
}

func (p *Player) sendPacket(ctx context.Context, targetURL string, pkt *Packet) error {
	url := targetURL + pkt.Path

	method := pkt.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if len(pkt.Body) > 0 {
		bodyReader = strings.NewReader(string(pkt.Body))
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return err
	}

	for k, v := range pkt.Headers {
		if strings.EqualFold(k, "Host") {
			continue // Don't override host
		}
		req.Header.Set(k, v)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

// Stop halts playback.
func (p *Player) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopCh != nil {
		select {
		case <-p.stopCh:
			// Already closed.
		default:
			close(p.stopCh)
		}
	}
}

// Stats returns current playback statistics.
func (p *Player) GetStats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stats
}

// IsPlaying returns whether playback is active.
func (p *Player) IsPlaying() bool {
	return p.playing.Load()
}

// Reset resets the player state for fresh playback.
func (p *Player) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stats.PacketsPlayed = 0
	p.stats.PacketsSkipped = 0
	p.stats.Errors = 0
	p.stats.ElapsedMs = 0
	p.stats.StartedAt = 0
}

// PacketCount returns the number of loaded packets.
func (p *Player) PacketCount() int {
	return len(p.packets)
}

// RequestCount returns the number of request packets.
func (p *Player) RequestCount() int {
	count := 0
	for _, pkt := range p.packets {
		if pkt.IsRequest {
			count++
		}
	}
	return count
}
