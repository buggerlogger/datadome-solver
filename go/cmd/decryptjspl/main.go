package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	ddcrypto "github.com/buggerlogger/datadome-solver/internal/crypto"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: decryptjspl <payload.txt> [hours]")
		os.Exit(1)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	hours := 48.0
	if len(os.Args) >= 3 {
		fmt.Sscanf(os.Args[2], "%f", &hours)
	}

	q := string(raw)
	if !strings.Contains(q, "jspl=") {
		q = "jspl=" + strings.TrimSpace(q)
	}
	vals := parseQuery(q)
	jspl, cid, ddk := vals["jspl"], vals["cid"], vals["ddk"]
	if jspl == "" || cid == "" || ddk == "" {
		fmt.Fprintln(os.Stderr, "payload needs jspl, cid, ddk")
		os.Exit(1)
	}

	now := time.Now().UnixMilli()
	window := int64(hours * 3600 * 1000)
	start := time.Now()
	obj, ts, err := ddcrypto.DecryptBrute(jspl, ddk, cid, now, window)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAILED in %s: %v\n", time.Since(start), err)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "DECRYPTED in %s  ts=%d  hoursAgo=%.3f  keys=%d  ddv=%s\n",
		time.Since(start), ts, float64(now-ts)/3600000, len(obj), vals["ddv"])
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(map[string]any{
		"ddv":         vals["ddv"],
		"timestampMs": ts,
		"hoursAgo":    float64(now-ts) / 3600000,
		"keyCount":    len(obj),
		"keys":        keyList(obj),
		"signals":     obj,
	})
}

func keyList(obj map[string]any) []string {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	return keys
}

func parseQuery(q string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(strings.TrimSpace(q), "&") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		out[k] = v
	}
	return out
}
