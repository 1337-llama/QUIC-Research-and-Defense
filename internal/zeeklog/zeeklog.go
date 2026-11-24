// Package zeeklog reads Zeek logs in either of Zeek's formats: the default
// tab-separated (TSV) format with #-prefixed headers, or JSON Lines
// (LogAscii::use_json=T). The format is detected automatically.
package zeeklog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Record is one log entry. Unset and empty fields are absent or "".
type Record map[string]string

// MaxLineBytes bounds a single log line.
const MaxLineBytes = 4 << 20

// Read parses a whole Zeek log.
func Read(r io.Reader) ([]Record, error) {
	br := bufio.NewReader(r)
	first, err := peekFirstByte(br)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, err
	}
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 0, 64*1024), MaxLineBytes)
	if first == '{' {
		return readJSON(sc)
	}
	return readTSV(sc)
}

func peekFirstByte(br *bufio.Reader) (byte, error) {
	for {
		b, err := br.Peek(1)
		if err != nil {
			return 0, err
		}
		switch b[0] {
		case ' ', '\t', '\r', '\n':
			if _, err := br.ReadByte(); err != nil {
				return 0, err
			}
		default:
			return b[0], nil
		}
	}
}

func readJSON(sc *bufio.Scanner) ([]Record, error) {
	var out []Record
	for line := 1; sc.Scan(); line++ {
		text := bytes.TrimSpace(sc.Bytes())
		if len(text) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(text))
		dec.UseNumber()
		var raw map[string]any
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("zeek json line %d: %w", line, err)
		}
		rec := make(Record, len(raw))
		for k, v := range raw {
			if s, ok := jsonString(v); ok {
				rec[k] = s
			}
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("zeek json: %w", err)
	}
	return out, nil
}

// jsonString renders a decoded JSON value the way the TSV format would.
func jsonString(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", false
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	case bool:
		return strconv.FormatBool(x), true
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := jsonString(e); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ","), true
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return "", false
		}
		return string(b), true
	}
}

func readTSV(sc *bufio.Scanner) ([]Record, error) {
	sep, setSep, empty, unset := "\t", ",", "(empty)", "-"
	var fields []string
	var out []Record
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimRight(sc.Text(), "\r")
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "#") {
			key, val, _ := strings.Cut(text[1:], sep)
			if key == "separator" || strings.HasPrefix(key, "separator ") {
				// "#separator \x09" uses a space, since the separator is
				// not known yet.
				_, val, _ = strings.Cut(text, " ")
				s, err := unescapeSeparator(val)
				if err != nil {
					return nil, fmt.Errorf("zeek tsv line %d: %w", line, err)
				}
				sep = s
				continue
			}
			switch key {
			case "set_separator":
				setSep = val
			case "empty_field":
				empty = val
			case "unset_field":
				unset = val
			case "fields":
				fields = strings.Split(val, sep)
			}
			continue
		}
		if fields == nil {
			return nil, fmt.Errorf("zeek tsv line %d: data before #fields header", line)
		}
		vals := strings.Split(text, sep)
		if len(vals) != len(fields) {
			return nil, fmt.Errorf("zeek tsv line %d: %d values for %d fields", line, len(vals), len(fields))
		}
		rec := make(Record, len(fields))
		for i, f := range fields {
			switch v := vals[i]; v {
			case unset:
			case empty:
				rec[f] = ""
			default:
				if setSep != "," {
					v = strings.ReplaceAll(v, setSep, ",")
				}
				rec[f] = v
			}
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("zeek tsv: %w", err)
	}
	return out, nil
}

func unescapeSeparator(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, `\x`) && len(s) == 4 {
		b, err := strconv.ParseUint(s[2:], 16, 8)
		if err != nil {
			return "", fmt.Errorf("bad #separator %q", s)
		}
		return string(rune(b)), nil
	}
	if s == "" {
		return "", errors.New("empty #separator")
	}
	return s, nil
}

// Time parses a Zeek timestamp: epoch seconds with a fractional part (the
// default), or RFC 3339 (LogAscii::json_timestamps=JSON::TS_ISO8601).
func Time(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("empty timestamp")
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return time.Time{}, fmt.Errorf("invalid timestamp %q", s)
		}
		sec, frac := math.Modf(f)
		return time.Unix(int64(sec), int64(math.Round(frac*1e6))*1e3).UTC(), nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timestamp %q", s)
	}
	return t.UTC(), nil
}

// Interval parses a Zeek interval (seconds, possibly fractional).
func Interval(s string) (time.Duration, error) {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
		return 0, fmt.Errorf("invalid interval %q", s)
	}
	return time.Duration(math.Round(f * float64(time.Second))), nil
}

// Endpoints holds a connection's 4-tuple.
type Endpoints struct {
	Orig netip.AddrPort
	Resp netip.AddrPort
}

// endpoints reads the standard id.* fields.
func endpoints(r Record) (Endpoints, error) {
	o, err := addrPort(r["id.orig_h"], r["id.orig_p"])
	if err != nil {
		return Endpoints{}, fmt.Errorf("originator: %w", err)
	}
	p, err := addrPort(r["id.resp_h"], r["id.resp_p"])
	if err != nil {
		return Endpoints{}, fmt.Errorf("responder: %w", err)
	}
	return Endpoints{Orig: o, Resp: p}, nil
}

func addrPort(h, p string) (netip.AddrPort, error) {
	a, err := netip.ParseAddr(h)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("address %q: %w", h, err)
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("port %q: %w", p, err)
	}
	return netip.AddrPortFrom(a.Unmap(), uint16(port)), nil
}

// Conn is a conn.log entry.
type Conn struct {
	UID string
	TS  time.Time
	Endpoints
	Proto     string
	Service   []string
	Duration  time.Duration
	OrigBytes int64
	RespBytes int64
}

// HasService reports whether the connection was identified as svc.
func (c Conn) HasService(svc string) bool {
	for _, s := range c.Service {
		if strings.EqualFold(s, svc) {
			return true
		}
	}
	return false
}

// ParseConn converts a conn.log record.
func ParseConn(r Record) (Conn, error) {
	ts, err := Time(r["ts"])
	if err != nil {
		return Conn{}, fmt.Errorf("conn %s: %w", r["uid"], err)
	}
	ep, err := endpoints(r)
	if err != nil {
		return Conn{}, fmt.Errorf("conn %s: %w", r["uid"], err)
	}
	c := Conn{UID: r["uid"], TS: ts, Endpoints: ep, Proto: r["proto"]}
	if s := r["service"]; s != "" {
		c.Service = strings.Split(s, ",")
	}
	if s := r["duration"]; s != "" {
		if c.Duration, err = Interval(s); err != nil {
			return Conn{}, fmt.Errorf("conn %s: %w", c.UID, err)
		}
	}
	if c.OrigBytes, err = optInt(r["orig_bytes"]); err != nil {
		return Conn{}, fmt.Errorf("conn %s orig_bytes: %w", c.UID, err)
	}
	if c.RespBytes, err = optInt(r["resp_bytes"]); err != nil {
		return Conn{}, fmt.Errorf("conn %s resp_bytes: %w", c.UID, err)
	}
	return c, nil
}

func optInt(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	return strconv.ParseInt(s, 10, 64)
}

// QUIC is a quic.log entry.
type QUIC struct {
	UID string
	TS  time.Time
	Endpoints
	Version        string
	ServerName     string
	ClientProtocol string
	History        string
}

// ParseQUIC converts a quic.log record.
func ParseQUIC(r Record) (QUIC, error) {
	ts, err := Time(r["ts"])
	if err != nil {
		return QUIC{}, fmt.Errorf("quic %s: %w", r["uid"], err)
	}
	ep, err := endpoints(r)
	if err != nil {
		return QUIC{}, fmt.Errorf("quic %s: %w", r["uid"], err)
	}
	return QUIC{
		UID: r["uid"], TS: ts, Endpoints: ep,
		Version: r["version"], ServerName: r["server_name"], ClientProtocol: r["client_protocol"], History: r["history"],
	}, nil
}

// Notice is a notice.log entry. Endpoints are zero if the notice has none.
type Notice struct {
	UID string
	TS  time.Time
	Endpoints
	Note string
	Msg  string
}

// ParseNotice converts a notice.log record.
func ParseNotice(r Record) (Notice, error) {
	ts, err := Time(r["ts"])
	if err != nil {
		return Notice{}, fmt.Errorf("notice: %w", err)
	}
	n := Notice{UID: r["uid"], TS: ts, Note: r["note"], Msg: r["msg"]}
	if n.Note == "" {
		return Notice{}, errors.New("notice: missing note")
	}
	if r["id.orig_h"] != "" {
		if n.Endpoints, err = endpoints(r); err != nil {
			return Notice{}, fmt.Errorf("notice %s: %w", n.Note, err)
		}
	}
	return n, nil
}

// ReadConns reads and parses a conn.log, sorted by timestamp.
func ReadConns(r io.Reader) ([]Conn, error) {
	return readTyped(r, ParseConn, func(c Conn) time.Time { return c.TS })
}

// ReadQUIC reads and parses a quic.log, sorted by timestamp.
func ReadQUIC(r io.Reader) ([]QUIC, error) {
	return readTyped(r, ParseQUIC, func(q QUIC) time.Time { return q.TS })
}

// ReadNotices reads and parses a notice.log, sorted by timestamp.
func ReadNotices(r io.Reader) ([]Notice, error) {
	return readTyped(r, ParseNotice, func(n Notice) time.Time { return n.TS })
}

func readTyped[T any](r io.Reader, parse func(Record) (T, error), ts func(T) time.Time) ([]T, error) {
	recs, err := Read(r)
	if err != nil {
		return nil, err
	}
	out := make([]T, 0, len(recs))
	for i, rec := range recs {
		v, err := parse(rec)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", i+1, err)
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return ts(out[i]).Before(ts(out[j])) })
	return out, nil
}
