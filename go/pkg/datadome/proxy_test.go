package datadome

import "testing"

func TestNormalizeProxyURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{

		{"host:port:user:pass", "1.2.3.4:8080:bob:s3cret", "http://bob:s3cret@1.2.3.4:8080"},
		{"hostname:port:user:pass", "gate.proxy.io:9000:user1:pw1", "http://user1:pw1@gate.proxy.io:9000"},
		{"password containing colons", "1.2.3.4:8080:bob:a:b:c", "http://bob:a%3Ab%3Ac@1.2.3.4:8080"},
		{"scheme + host:port:user:pass", "socks5://1.2.3.4:1080:bob:pw", "socks5://bob:pw@1.2.3.4:1080"},

		{"host:port", "1.2.3.4:8080", "http://1.2.3.4:8080"},
		{"scheme + host:port", "https://1.2.3.4:8443", "https://1.2.3.4:8443"},

		{"user:pass@host:port", "bob:pw@1.2.3.4:8080", "http://bob:pw@1.2.3.4:8080"},
		{"scheme + user:pass@host:port", "http://bob:pw@1.2.3.4:8080", "http://bob:pw@1.2.3.4:8080"},
		{"socks5h", "socks5h://bob:pw@1.2.3.4:1080", "socks5h://bob:pw@1.2.3.4:1080"},

		{"whitespace is trimmed", "  1.2.3.4:8080  ", "http://1.2.3.4:8080"},
		{"ipv6 literal", "[::1]:8080", "http://[::1]:8080"},
		{"empty stays empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeProxyURL(tc.in)
			if err != nil {
				t.Fatalf("NormalizeProxyURL(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeProxyURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeProxyURLErrors(t *testing.T) {
	bad := []struct {
		name string
		in   string
	}{
		{"no port", "1.2.3.4"},
		{"bad port", "1.2.3.4:notaport"},
		{"port out of range", "1.2.3.4:70000"},
		{"unsupported scheme", "ftp://1.2.3.4:21"},
		{"empty host", ":8080"},
		{"scheme only", "http://"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := NormalizeProxyURL(tc.in); err == nil {
				t.Errorf("NormalizeProxyURL(%q) = %q, want an error", tc.in, got)
			}
		})
	}
}

func TestNewChromeTransportAcceptsShorthandProxy(t *testing.T) {
	for _, in := range []string{
		"1.2.3.4:8080:bob:pw",
		"1.2.3.4:8080",
		"socks5://1.2.3.4:1080:bob:pw",
	} {
		ct, err := newChromeTransport(in)
		if err != nil {
			t.Fatalf("newChromeTransport(%q) error: %v", in, err)
		}
		if ct.proxy == nil {
			t.Fatalf("newChromeTransport(%q): proxy not set", in)
		}
	}
	if _, err := newChromeTransport("1.2.3.4:bogus"); err == nil {
		t.Error("newChromeTransport with an invalid proxy should fail")
	}
}

func TestNewChromeTransportSocksSchemeDetected(t *testing.T) {
	ct, err := newChromeTransport("socks5://1.2.3.4:1080:bob:pw")
	if err != nil {
		t.Fatalf("newChromeTransport: %v", err)
	}
	if !isSocksScheme(ct.proxy.Scheme) {
		t.Errorf("scheme %q should be detected as SOCKS", ct.proxy.Scheme)
	}
	http, err := newChromeTransport("1.2.3.4:8080:bob:pw")
	if err != nil {
		t.Fatalf("newChromeTransport: %v", err)
	}
	if isSocksScheme(http.proxy.Scheme) {
		t.Errorf("scheme %q should NOT be SOCKS", http.proxy.Scheme)
	}
}
