package errors

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPick_ReturnsValidType(t *testing.T) {
	g := NewGenerator()
	profile := DefaultProfile()
	known := profile.Weights
	for i := 0; i < 100; i++ {
		et := g.Pick(profile)
		if _, ok := known[et]; !ok && et != ErrNone {
			t.Fatalf("Pick returned unknown error type: %q", et)
		}
	}
}

func TestPick_WeightDistribution(t *testing.T) {
	g := NewGenerator()
	profile := DefaultProfile()
	counts := make(map[ErrorType]int)
	n := 10000
	for i := 0; i < n; i++ {
		counts[g.Pick(profile)]++
	}
	// ErrNone has weight 0.62, should appear most often
	for et, c := range counts {
		if et != ErrNone && c > counts[ErrNone] {
			t.Fatalf("expected ErrNone to be most frequent, but %q appeared %d times vs ErrNone %d", et, c, counts[ErrNone])
		}
	}
	if counts[ErrNone] < n/4 {
		t.Fatalf("ErrNone appeared only %d times out of %d, expected at least %d", counts[ErrNone], n, n/4)
	}
}

func TestApply_ErrNone(t *testing.T) {
	g := NewGenerator()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handled := g.Apply(w, r, ErrNone)
	if handled {
		t.Fatal("Apply(ErrNone) should return false so caller handles the response")
	}
}

func TestApply_Err500(t *testing.T) {
	g := NewGenerator()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handled := g.Apply(w, r, Err500)
	if !handled {
		t.Fatal("Apply(Err500) should return true")
	}
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestApply_Err404(t *testing.T) {
	g := NewGenerator()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/missing", nil)
	handled := g.Apply(w, r, Err404)
	if !handled {
		t.Fatal("Apply(Err404) should return true")
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestApply_EmptyBody(t *testing.T) {
	g := NewGenerator()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handled := g.Apply(w, r, ErrEmptyBody)
	if !handled {
		t.Fatal("Apply(ErrEmptyBody) should return true")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("expected empty body, got %d bytes", w.Body.Len())
	}
}

func TestIsError(t *testing.T) {
	if IsError(ErrNone) {
		t.Fatal("ErrNone should not be an error")
	}
	if !IsError(Err500) {
		t.Fatal("Err500 should be an error")
	}
	if !IsError(Err404) {
		t.Fatal("Err404 should be an error")
	}
	if IsError(ErrDelayed1s) {
		t.Fatal("ErrDelayed1s should not be an error")
	}
}

func TestIsDelay(t *testing.T) {
	if !IsDelay(ErrDelayed1s) {
		t.Fatal("ErrDelayed1s should be a delay")
	}
	if !IsDelay(ErrDelayed3s) {
		t.Fatal("ErrDelayed3s should be a delay")
	}
	if !IsDelay(ErrDelayed10s) {
		t.Fatal("ErrDelayed10s should be a delay")
	}
	if !IsDelay(ErrDelayedRandom) {
		t.Fatal("ErrDelayedRandom should be a delay")
	}
	if IsDelay(ErrNone) {
		t.Fatal("ErrNone should not be a delay")
	}
	if IsDelay(Err500) {
		t.Fatal("Err500 should not be a delay")
	}
}
