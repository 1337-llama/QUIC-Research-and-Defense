// Package eve reads alerts from Suricata's EVE JSON output.
package eve

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
)

// Alert is one Suricata alert.
type Alert struct {
	TS          time.Time
	Src         netip.AddrPort
	Dst         netip.AddrPort
	Proto       string
	AppProto    string
	Signature   string
	SignatureID int64
}

// MaxLineBytes bounds a single EVE line. EVE lines can be large when
// payload logging is enabled.
const MaxLineBytes = 16 << 20

// timeLayouts are the timestamp formats Suricata has used.
var timeLayouts = []string{
	"2006-01-02T15:04:05.999999-0700",
	"2006-01-02T15:04:05.999999Z07:00",
	time.RFC3339Nano,
}

type rawEvent struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   uint16 `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  uint16 `json:"dest_port"`
	Proto     string `json:"proto"`
	AppProto  string `json:"app_proto"`
	Alert     *struct {
		Signature   string `json:"signature"`
		SignatureID int64  `json:"signature_id"`
	} `json:"alert"`
}

// ReadAlerts returns every alert event in r, skipping other event types.
func ReadAlerts(r io.Reader) ([]Alert, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), MaxLineBytes)
	var out []Alert
	for line := 1; sc.Scan(); line++ {
		text := bytes.TrimSpace(sc.Bytes())
		if len(text) == 0 {
			continue
		}
		var ev rawEvent
		if err := json.Unmarshal(text, &ev); err != nil {
			return nil, fmt.Errorf("eve line %d: %w", line, err)
		}
		if ev.EventType != "alert" {
			continue
		}
		a, err := ev.toAlert()
		if err != nil {
			return nil, fmt.Errorf("eve line %d: %w", line, err)
		}
		out = append(out, a)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("eve: %w", err)
	}
	return out, nil
}

func (ev rawEvent) toAlert() (Alert, error) {
	if ev.Alert == nil || ev.Alert.Signature == "" {
		return Alert{}, fmt.Errorf("alert event without a signature")
	}
	ts, err := parseTime(ev.Timestamp)
	if err != nil {
		return Alert{}, err
	}
	src, err := netip.ParseAddr(ev.SrcIP)
	if err != nil {
		return Alert{}, fmt.Errorf("src_ip %q: %w", ev.SrcIP, err)
	}
	dst, err := netip.ParseAddr(ev.DestIP)
	if err != nil {
		return Alert{}, fmt.Errorf("dest_ip %q: %w", ev.DestIP, err)
	}
	return Alert{
		TS:          ts,
		Src:         netip.AddrPortFrom(src.Unmap(), ev.SrcPort),
		Dst:         netip.AddrPortFrom(dst.Unmap(), ev.DestPort),
		Proto:       strings.ToUpper(ev.Proto),
		AppProto:    ev.AppProto,
		Signature:   ev.Alert.Signature,
		SignatureID: ev.Alert.SignatureID,
	}, nil
}

func parseTime(s string) (time.Time, error) {
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil && !t.IsZero() {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid timestamp %q", s)
}
