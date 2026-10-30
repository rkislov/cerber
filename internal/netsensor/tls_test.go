// SPDX-License-Identifier: Apache-2.0
package netsensor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/rkislov/cerber/internal/eventstore"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTLSRequiresTrustedClientCertificate(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	capath := filepath.Join(dir, "ca.pem")
	os.WriteFile(capath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	issue := func(name string, usage x509.ExtKeyUsage) (string, string, tls.Certificate) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(len(name) + 2)), Subject: pkix.Name{CommonName: name}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		d, e := x509.CreateCertificate(rand.Reader, template, ca, &k.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		priv, e := x509.MarshalPKCS8PrivateKey(k)
		if e != nil {
			t.Fatal(e)
		}
		cpath, kpath := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key")
		os.WriteFile(cpath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}), 0600)
		os.WriteFile(kpath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}), 0600)
		pair, e := tls.LoadX509KeyPair(cpath, kpath)
		if e != nil {
			t.Fatal(e)
		}
		return cpath, kpath, pair
	}
	cert, keypath, _ := issue("server", x509.ExtKeyUsageServerAuth)
	_, _, clientCert := issue("client", x509.ExtKeyUsageClientAuth)
	i := Input{ID: "tls", Format: "syslog", Protocol: "tls", Allow: []string{"127.0.0.1/32"}, Cert: cert, Key: keypath, ClientCA: capath}
	cfg, e := tlsConfig(i)
	if e != nil {
		t.Fatal(e)
	}
	l, e := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, e := eventstore.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	r := newReceiver(s, "sensor")
	done := make(chan error, 1)
	go func() { done <- r.serveStream(ctx, l, i) }()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	client := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	// TLS 1.3 can report the missing-client-cert alert on first I/O, not Dial.
	if c, e := tls.Dial("tcp", l.Addr().String(), client); e == nil {
		c.SetDeadline(time.Now().Add(time.Second))
		c.Write([]byte("<34>Oct 30 10:12:13 fake port: up\n"))
		c.Read(make([]byte, 1))
		c.Close()
	}
	client.Certificates = []tls.Certificate{clientCert}
	c, e := tls.Dial("tcp", l.Addr().String(), client)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.Write([]byte("<34>Oct 30 10:12:13 trusted port: up\n"))
	deadline := time.Now().Add(3 * time.Second)
	for r.stored.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.stored.Load() != 1 || r.rejected.Load() == 0 {
		t.Fatal("mTLS admission failed", r.stored.Load(), r.rejected.Load())
	}
	cancel()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
