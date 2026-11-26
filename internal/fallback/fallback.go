// Package fallback composes two beacon transports: it opens sessions on the
// primary and, when that fails in a way a retry might fix, on the fallback.
//
// This models the behavior defenders meet when they block UDP/443: QUIC
// implants, like browsers, retry over HTTPS on TCP. A network that only
// blocks QUIC therefore moves the beacon to a different sensor rather than
// stopping it.
package fallback

import (
	"context"
	"errors"
	"log/slog"

	"github.com/1337-llama/QUIC-Research-and-Defense/internal/beacon"
)

// Transport tries Primary, then Fallback.
type Transport struct {
	Primary  beacon.Transport
	Fallback beacon.Transport
	// Log, if set, records each fallback.
	Log *slog.Logger
}

var _ beacon.Transport = (*Transport)(nil)

// Open implements beacon.Transport. A permanent primary failure (such as a
// target the safety policy forbids) is returned as is: the fallback would
// reach the same forbidden destination. Context cancellation is also
// returned without trying the fallback.
func (t *Transport) Open(ctx context.Context) (beacon.Session, error) {
	s, err := t.Primary.Open(ctx)
	if err == nil {
		return s, nil
	}
	if errors.Is(err, beacon.ErrPermanent) || ctx.Err() != nil {
		return nil, err
	}
	if t.Log != nil {
		t.Log.Info("primary transport failed; falling back", "error", err.Error())
	}
	s, ferr := t.Fallback.Open(ctx)
	if ferr != nil {
		return nil, errors.Join(err, ferr)
	}
	return s, nil
}
