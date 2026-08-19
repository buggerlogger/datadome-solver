package datadome

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

const (
	proxyDialTimeout    = 15 * time.Second
	proxyConnectTimeout = 20 * time.Second
	proxyDialAttempts   = 3
	proxyRetryBackoff   = 300 * time.Millisecond
)

type chromeTransport struct {
	proxy *url.URL
	h2t   *http2.Transport
	h1t   *http.Transport

	mu       sync.Mutex
	protoFor map[string]string
}

func newChromeTransport(proxyURL string) (*chromeTransport, error) {
	ct := &chromeTransport{protoFor: make(map[string]string)}
	if proxyURL != "" {

		normalized, err := NormalizeProxyURL(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("datadome: invalid proxy: %w", err)
		}
		pu, err := url.Parse(normalized)
		if err != nil {
			return nil, fmt.Errorf("datadome: invalid proxy URL: %w", err)
		}
		ct.proxy = pu
	}
	ct.h2t = &http2.Transport{
		DialTLSContext:     ct.dialTLSH2,
		MaxHeaderListSize:  262144,
		DisableCompression: false,
	}
	ct.h1t = &http.Transport{
		DialTLSContext:        ct.dialTLSH1,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return ct, nil
}

func (ct *chromeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	proto, err := ct.negotiate(req.Context(), req.URL)
	if err != nil {
		return nil, err
	}
	if proto == "h2" {
		return ct.h2t.RoundTrip(req)
	}
	return ct.h1t.RoundTrip(req)
}

func (ct *chromeTransport) negotiate(ctx context.Context, u *url.URL) (string, error) {
	addr := canonicalAddr(u)

	ct.mu.Lock()
	if p, ok := ct.protoFor[addr]; ok {
		ct.mu.Unlock()
		return p, nil
	}
	ct.mu.Unlock()

	conn, err := ct.dialTLS(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	proto := conn.ConnectionState().NegotiatedProtocol
	conn.Close()
	if proto != "h2" {
		proto = "http/1.1"
	}

	ct.mu.Lock()
	ct.protoFor[addr] = proto
	ct.mu.Unlock()
	return proto, nil
}

func (ct *chromeTransport) dialTLSH2(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	return ct.dialTLS(ctx, network, addr)
}

func (ct *chromeTransport) dialTLSH1(ctx context.Context, network, addr string) (net.Conn, error) {
	return ct.dialTLS(ctx, network, addr)
}

func (ct *chromeTransport) dialTLS(ctx context.Context, network, addr string) (*utls.UConn, error) {

	attempts := 1
	if ct.proxy != nil {
		attempts = proxyDialAttempts
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}

		uConn, err := ct.dialTLSOnce(ctx, network, addr)
		if err == nil {
			return uConn, nil
		}
		lastErr = err
		var nonRetryable nonRetryableError
		if errors.As(err, &nonRetryable) {
			return nil, err
		}
		if attempt < attempts {
			select {
			case <-time.After(proxyRetryBackoff):
			case <-ctx.Done():
				return nil, lastErr
			}
		}
	}
	if attempts > 1 {
		return nil, fmt.Errorf("after %d proxy attempts: %w", attempts, lastErr)
	}
	return nil, lastErr
}

func (ct *chromeTransport) dialTLSOnce(ctx context.Context, network, addr string) (*utls.UConn, error) {
	var rawConn net.Conn
	var err error

	switch {
	case ct.proxy == nil:
		rawConn, err = (&net.Dialer{Timeout: proxyDialTimeout}).DialContext(ctx, network, addr)
	case isSocksScheme(ct.proxy.Scheme):
		rawConn, err = ct.dialViaSOCKS(ctx, network, addr)
	default:
		rawConn, err = ct.dialViaProxy(ctx, addr)
	}
	if err != nil {
		return nil, err
	}

	host, _, _ := net.SplitHostPort(addr)
	uConn := utls.UClient(rawConn, &utls.Config{ServerName: host}, utls.HelloChrome_Auto)

	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}
	return uConn, nil
}

func canonicalAddr(u *url.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	return net.JoinHostPort(host, port)
}

type nonRetryableError struct{ err error }

func (e nonRetryableError) Error() string { return e.err.Error() }
func (e nonRetryableError) Unwrap() error { return e.err }

func isSocksScheme(scheme string) bool {
	return scheme == "socks5" || scheme == "socks5h"
}

func (ct *chromeTransport) dialViaSOCKS(ctx context.Context, network, addr string) (net.Conn, error) {
	var auth *proxy.Auth
	if ct.proxy.User != nil {
		pass, _ := ct.proxy.User.Password()
		auth = &proxy.Auth{User: ct.proxy.User.Username(), Password: pass}
	}
	proxyAddr := ct.proxy.Host
	if ct.proxy.Port() == "" {
		proxyAddr = net.JoinHostPort(proxyAddr, "1080")
	}
	d, err := proxy.SOCKS5("tcp", proxyAddr, auth, &net.Dialer{Timeout: 15 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("socks5 proxy: %w", err)
	}
	if cd, ok := d.(proxy.ContextDialer); ok {
		conn, err := cd.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("socks5 dial: %w", err)
		}
		return conn, nil
	}
	conn, err := d.Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("socks5 dial: %w", err)
	}
	return conn, nil
}

func (ct *chromeTransport) dialViaProxy(ctx context.Context, addr string) (net.Conn, error) {
	proxyAddr := ct.proxy.Host
	if ct.proxy.Port() == "" {
		proxyAddr = net.JoinHostPort(proxyAddr, "80")
	}

	conn, err := (&net.Dialer{Timeout: proxyDialTimeout}).DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy dial: %w", err)
	}

	deadline := time.Now().Add(proxyConnectTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if ct.proxy.User != nil {
		user := ct.proxy.User.Username()
		pass, _ := ct.proxy.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Set("Proxy-Authorization", "Basic "+auth)
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT write: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT response: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		err := fmt.Errorf("proxy CONNECT failed: %s", resp.Status)

		if resp.StatusCode == http.StatusProxyAuthRequired || resp.StatusCode == http.StatusForbidden {
			return nil, nonRetryableError{err}
		}
		return nil, err
	}
	if br.Buffered() > 0 {

		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT: %d unexpected bytes after response", br.Buffered())
	}

	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
