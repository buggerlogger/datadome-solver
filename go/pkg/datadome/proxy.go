package datadome

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func NormalizeProxyURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}

	scheme := "http"
	rest := raw
	if i := strings.Index(raw, "://"); i >= 0 {
		scheme = strings.ToLower(strings.TrimSpace(raw[:i]))
		rest = raw[i+3:]
	}
	switch scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", fmt.Errorf("unsupported proxy scheme %q (want http, https, socks5 or socks5h)", scheme)
	}
	if rest == "" {
		return "", fmt.Errorf("proxy %q has no host", raw)
	}

	var creds, hostport string
	if at := strings.LastIndex(rest, "@"); at >= 0 {

		creds, hostport = rest[:at], rest[at+1:]
	} else if strings.HasPrefix(rest, "[") {

		hostport = rest
	} else if parts := strings.SplitN(rest, ":", 4); len(parts) == 4 && isPort(parts[1]) {

		hostport = parts[0] + ":" + parts[1]
		creds = parts[2] + ":" + parts[3]
	} else {
		hostport = rest
	}

	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", fmt.Errorf("proxy %q must be host:port (%v)", raw, err)
	}
	if host == "" {
		return "", fmt.Errorf("proxy %q has an empty host", raw)
	}
	if !isPort(port) {
		return "", fmt.Errorf("proxy %q has an invalid port %q", raw, port)
	}

	u := &url.URL{Scheme: scheme, Host: net.JoinHostPort(host, port)}
	if creds != "" {
		user, pass, found := strings.Cut(creds, ":")
		if user == "" {
			return "", fmt.Errorf("proxy %q has an empty username", raw)
		}
		if found {
			u.User = url.UserPassword(user, pass)
		} else {
			u.User = url.User(user)
		}
	}
	return u.String(), nil
}

func isPort(s string) bool {
	if s == "" {
		return false
	}
	n, err := strconv.Atoi(s)
	return err == nil && n > 0 && n <= 65535
}
