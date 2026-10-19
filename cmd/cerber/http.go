// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

func serveHTTP(ctx context.Context, handler http.Handler, listen, cert, key, label string, readTimeout, writeTimeout time.Duration, errOut io.Writer) error {
	if (cert == "") != (key == "") {
		return fmt.Errorf("both TLS certificate and key are required")
	}
	if cert == "" {
		host, _, err := net.SplitHostPort(listen)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Unmap().IsLoopback() {
			return fmt.Errorf("plaintext listener requires an explicit loopback IP; use TLS for network access")
		}
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: readTimeout, IdleTimeout: 60 * time.Second, WriteTimeout: writeTimeout, MaxHeaderBytes: 16 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	// Validate TLS files before opening a socket or reporting readiness.
	if cert != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return err
		}
		server.TLSConfig.Certificates = []tls.Certificate{pair}
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Fprintf(errOut, "%s listening on %s\n", label, listener.Addr())
	done := make(chan error, 1)
	go func() {
		if cert != "" {
			done <- server.ServeTLS(listener, "", "")
		} else {
			done <- server.Serve(listener)
		}
	}()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := server.Shutdown(shutdown)
		if err != nil {
			server.Close()
		}
		<-done
		return err
	}
}
