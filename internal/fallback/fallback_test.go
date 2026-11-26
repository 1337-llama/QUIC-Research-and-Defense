package fallback_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/beacon"
	"github.com/1337-llama/QUIC-Research-and-Defense/internal/fallback"
)

type fakeSession struct{ transport string }

func (s fakeSession) Do(context.Context, beacon.Request) (beacon.Response, error) {
	return beacon.Response{StatusCode: 200}, nil
}
func (s fakeSession) Info() beacon.SessionInfo { return beacon.SessionInfo{Transport: s.transport} }
func (s fakeSession) Close() error             { return nil }

type fakeTransport struct {
	name  string
	err   error
	opens int
}

func (f *fakeTransport) Open(context.Context) (beacon.Session, error) {
	f.opens++
	if f.err != nil {
		return nil, f.err
	}
	return fakeSession{transport: f.name}, nil
}

var errBlocked = errors.New("udp blocked")

func TestFallback(t *testing.T) {
	t.Parallel()
	permanent := beacon.Permanent(errors.New("not a lab address"))
	tests := []struct {
		name          string
		primary, back error
		wantTransport string
		wantErr       []error
		wantBackOpens int
	}{
		{name: "primary works", wantTransport: "quic"},
		{name: "falls back", primary: errBlocked, wantTransport: "tcp", wantBackOpens: 1},
		{name: "both fail", primary: errBlocked, back: errors.New("tcp refused"), wantErr: []error{errBlocked}, wantBackOpens: 1},
		{name: "permanent is not retried", primary: permanent, wantErr: []error{beacon.ErrPermanent}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := &fakeTransport{name: "quic", err: tc.primary}
			b := &fakeTransport{name: "tcp", err: tc.back}
			var logs bytes.Buffer
			tr := &fallback.Transport{Primary: p, Fallback: b, Log: slog.New(slog.NewTextHandler(&logs, nil))}
			s, err := tr.Open(context.Background())
			for _, want := range tc.wantErr {
				if !errors.Is(err, want) {
					t.Errorf("err = %v, want %v", err, want)
				}
			}
			if len(tc.wantErr) == 0 {
				if err != nil {
					t.Fatal(err)
				}
				if got := s.Info().Transport; got != tc.wantTransport {
					t.Errorf("transport = %q, want %q", got, tc.wantTransport)
				}
			}
			if b.opens != tc.wantBackOpens {
				t.Errorf("fallback opened %d times, want %d", b.opens, tc.wantBackOpens)
			}
			if fell := strings.Contains(logs.String(), "falling back"); fell != (tc.wantBackOpens > 0) {
				t.Errorf("fallback log = %v, logs: %s", fell, logs.String())
			}
		})
	}
}

func TestCanceledContextDoesNotFallBack(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := &fakeTransport{name: "tcp"}
	tr := &fallback.Transport{Primary: &fakeTransport{err: context.Canceled}, Fallback: b}
	if _, err := tr.Open(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if b.opens != 0 {
		t.Error("fallback tried after cancellation")
	}
}

func TestNilLogger(t *testing.T) {
	t.Parallel()
	tr := &fallback.Transport{Primary: &fakeTransport{err: errBlocked}, Fallback: &fakeTransport{name: "tcp"}}
	if _, err := tr.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
}
