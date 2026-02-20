package errors

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// ErrorType defines the kind of glitch to inject.
type ErrorType string

const (
	ErrNone              ErrorType = "none"
	Err500               ErrorType = "500_internal"
	Err502               ErrorType = "502_bad_gateway"
	Err503               ErrorType = "503_unavailable"
	Err504               ErrorType = "504_timeout"
	Err404               ErrorType = "404_not_found"
	Err403               ErrorType = "403_forbidden"
	Err429               ErrorType = "429_rate_limit"
	Err408               ErrorType = "408_timeout"
	ErrSlowDrip          ErrorType = "slow_drip"          // send bytes very slowly
	ErrConnectionReset   ErrorType = "connection_reset"    // close mid-response
	ErrPartialBody       ErrorType = "partial_body"        // truncated JSON/HTML
	ErrWrongContentType  ErrorType = "wrong_content_type"  // lie about content-type
	ErrGarbageBody       ErrorType = "garbage_body"        // random bytes
	ErrEmptyBody         ErrorType = "empty_body"          // 200 with no body
	ErrHugeHeaders       ErrorType = "huge_headers"        // bloated response headers
	ErrDelayed1s         ErrorType = "delay_1s"
	ErrDelayed3s         ErrorType = "delay_3s"
	ErrDelayed10s        ErrorType = "delay_10s"
	ErrDelayedRandom     ErrorType = "delay_random"
	ErrRedirectLoop      ErrorType = "redirect_loop"
	ErrDoubleEncoding    ErrorType = "double_encoding"     // double gzip
	ErrFlipFlop          ErrorType = "flip_flop"           // alternate 200/500
)

// ErrorProfile defines probabilities for each error type.
type ErrorProfile struct {
	Weights map[ErrorType]float64
}

// DefaultProfile is the baseline error distribution.
func DefaultProfile() ErrorProfile {
	return ErrorProfile{
		Weights: map[ErrorType]float64{
			ErrNone:              0.65,
			Err500:               0.03,
			Err502:               0.02,
			Err503:               0.02,
			Err504:               0.01,
			Err404:               0.03,
			Err403:               0.01,
			Err429:               0.02,
			Err408:               0.01,
			ErrSlowDrip:          0.02,
			ErrConnectionReset:   0.01,
			ErrPartialBody:       0.02,
			ErrWrongContentType:  0.02,
			ErrGarbageBody:       0.01,
			ErrEmptyBody:         0.01,
			ErrHugeHeaders:       0.01,
			ErrDelayed1s:         0.03,
			ErrDelayed3s:         0.02,
			ErrDelayed10s:        0.01,
			ErrDelayedRandom:     0.01,
			ErrRedirectLoop:      0.01,
			ErrDoubleEncoding:    0.005,
			ErrFlipFlop:          0.005,
		},
	}
}

// AggressiveProfile ramps up error rates for identified bots/testers.
func AggressiveProfile() ErrorProfile {
	return ErrorProfile{
		Weights: map[ErrorType]float64{
			ErrNone:             0.30,
			Err500:              0.06,
			Err502:              0.05,
			Err503:              0.05,
			Err504:              0.03,
			Err404:              0.05,
			Err403:              0.03,
			Err429:              0.05,
			Err408:              0.03,
			ErrSlowDrip:         0.04,
			ErrConnectionReset:  0.03,
			ErrPartialBody:      0.04,
			ErrWrongContentType: 0.04,
			ErrGarbageBody:      0.03,
			ErrEmptyBody:        0.02,
			ErrHugeHeaders:      0.02,
			ErrDelayed1s:        0.04,
			ErrDelayed3s:        0.03,
			ErrDelayed10s:       0.02,
			ErrDelayedRandom:    0.02,
			ErrRedirectLoop:     0.02,
			ErrDoubleEncoding:   0.01,
			ErrFlipFlop:         0.01,
		},
	}
}

// Generator picks and applies error types.
type Generator struct{}

func NewGenerator() *Generator {
	return &Generator{}
}

// Pick selects an error type using the given profile's weighted distribution.
func (g *Generator) Pick(profile ErrorProfile) ErrorType {
	r := rand.Float64()
	cumulative := 0.0
	for errType, weight := range profile.Weights {
		cumulative += weight
		if r < cumulative {
			return errType
		}
	}
	return ErrNone
}

// Apply writes the error response. Returns true if the response was fully handled.
// Returns false if the caller should write a normal response.
func (g *Generator) Apply(w http.ResponseWriter, r *http.Request, errType ErrorType) bool {
	switch errType {
	case ErrNone:
		return false

	case Err500:
		http.Error(w, `{"error":"Internal Server Error","code":500}`, http.StatusInternalServerError)
		return true

	case Err502:
		http.Error(w, `<html><body><h1>502 Bad Gateway</h1><p>The server received an invalid response.</p></body></html>`, http.StatusBadGateway)
		return true

	case Err503:
		w.Header().Set("Retry-After", fmt.Sprintf("%d", rand.Intn(60)+5))
		http.Error(w, `{"error":"Service Unavailable","retry_after_seconds":30}`, http.StatusServiceUnavailable)
		return true

	case Err504:
		time.Sleep(time.Duration(rand.Intn(3)+1) * time.Second)
		http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
		return true

	case Err404:
		http.Error(w, `{"error":"Not Found","path":"`+r.URL.Path+`"}`, http.StatusNotFound)
		return true

	case Err403:
		http.Error(w, `{"error":"Forbidden","message":"Access denied"}`, http.StatusForbidden)
		return true

	case Err429:
		w.Header().Set("Retry-After", fmt.Sprintf("%d", rand.Intn(30)+1))
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Minute).Unix()))
		http.Error(w, `{"error":"Too Many Requests","message":"Rate limit exceeded"}`, http.StatusTooManyRequests)
		return true

	case Err408:
		time.Sleep(5 * time.Second)
		http.Error(w, "Request Timeout", http.StatusRequestTimeout)
		return true

	case ErrSlowDrip:
		g.slowDrip(w)
		return true

	case ErrConnectionReset:
		// Hijack and close the connection abruptly
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				conn.Close()
			}
		}
		return true

	case ErrPartialBody:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "500") // lie about length
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":"this response is truncated and the JSON is incomple`))
		return true

	case ErrWrongContentType:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>This is actually HTML despite the content-type header</body></html>`))
		return true

	case ErrGarbageBody:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		garbage := make([]byte, rand.Intn(1024)+256)
		rand.Read(garbage)
		w.Write(garbage)
		return true

	case ErrEmptyBody:
		w.WriteHeader(http.StatusOK)
		return true

	case ErrHugeHeaders:
		for i := 0; i < 50; i++ {
			w.Header().Set(fmt.Sprintf("X-Glitch-Padding-%d", i), strings.Repeat("x", 512))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return true

	case ErrDelayed1s:
		time.Sleep(1 * time.Second)
		return false

	case ErrDelayed3s:
		time.Sleep(3 * time.Second)
		return false

	case ErrDelayed10s:
		time.Sleep(10 * time.Second)
		return false

	case ErrDelayedRandom:
		time.Sleep(time.Duration(rand.Intn(15)+1) * time.Second)
		return false

	case ErrRedirectLoop:
		target := fmt.Sprintf("/redirect-loop/%d?t=%d", rand.Intn(10), time.Now().UnixNano())
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
		return true

	case ErrDoubleEncoding:
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Write non-gzipped data with gzip header — decoders will choke
		w.Write([]byte("<html><body>This claims to be gzipped but isn't</body></html>"))
		return true

	case ErrFlipFlop:
		if time.Now().UnixNano()%2 == 0 {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
		return true
	}

	return false
}

func (g *Generator) slowDrip(w http.ResponseWriter) {
	flusher, ok := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

	msg := "This response is being sent very slowly, one character at a time..."
	for _, ch := range msg {
		w.Write([]byte(string(ch)))
		if ok {
			flusher.Flush()
		}
		time.Sleep(time.Duration(rand.Intn(300)+100) * time.Millisecond)
	}
}

// IsError returns true if the error type represents a failure.
func IsError(et ErrorType) bool {
	switch et {
	case ErrNone, ErrDelayed1s, ErrDelayed3s, ErrDelayed10s, ErrDelayedRandom:
		return false
	default:
		return true
	}
}

// IsDelay returns true if the error type is a delay (but eventual success).
func IsDelay(et ErrorType) bool {
	switch et {
	case ErrDelayed1s, ErrDelayed3s, ErrDelayed10s, ErrDelayedRandom:
		return true
	default:
		return false
	}
}
