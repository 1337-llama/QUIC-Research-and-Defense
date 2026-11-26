package certs

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"
)

func TestSelfSigned(t *testing.T) {
	t.Parallel()
	now := time.Now()
	g, err := SelfSigned([]string{"c2", "127.0.0.1"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := g.TLS.Leaf
	if leaf.Subject.CommonName != "c2" {
		t.Errorf("CN = %q", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "c2" {
		t.Errorf("DNSNames = %v", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IPAddresses = %v", leaf.IPAddresses)
	}
	if !leaf.NotAfter.After(now) || leaf.NotAfter.After(now.Add(time.Hour+time.Second)) {
		t.Errorf("NotAfter = %v", leaf.NotAfter)
	}

	pool, err := PoolFromPEM(g.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"c2", "127.0.0.1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: pool, CurrentTime: now}); err != nil {
			t.Errorf("verify for %s: %v", name, err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "other", Roots: pool, CurrentTime: now}); err == nil {
		t.Error("certificate verified for a name it does not cover")
	}
}

func TestSelfSignedTLSHandshake(t *testing.T) {
	t.Parallel()
	g, err := SelfSigned([]string{"lab.test"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := PoolFromPEM(g.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{g.TLS}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.WriteString(c, "ok")
	}()
	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "lab.test", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer c.Close()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("read = %q, %v", buf, err)
	}
}

func TestSelfSignedErrors(t *testing.T) {
	t.Parallel()
	if _, err := SelfSigned(nil, time.Now(), time.Hour); err == nil {
		t.Error("no hosts accepted")
	}
	if _, err := SelfSigned([]string{"x"}, time.Now(), 0); err == nil {
		t.Error("zero validity accepted")
	}
	if _, err := PoolFromPEM([]byte("not pem")); err == nil {
		t.Error("garbage PEM accepted")
	}
}

func TestSPKIHash(t *testing.T) {
	t.Parallel()
	g, err := SelfSigned([]string{"cdn"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got := SPKIHash(g.TLS.Leaf)
	sum := sha256.Sum256(g.TLS.Leaf.RawSubjectPublicKeyInfo)
	if want := base64.StdEncoding.EncodeToString(sum[:]); got != want || len(got) != 44 {
		t.Fatalf("SPKIHash = %q, want %q", got, want)
	}
	other, _ := SelfSigned([]string{"cdn"}, time.Now(), time.Hour)
	if SPKIHash(other.TLS.Leaf) == got {
		t.Error("different keys produced the same hash")
	}
}
