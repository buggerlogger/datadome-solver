package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/buggerlogger/datadome-solver/pkg/datadome"
)

const serverVersion = "5.9.2"

type solveRequest struct {
	DDK      string `json:"ddk"`
	Site     string `json:"site"`
	CID      string `json:"cid"`
	Proxy    string `json:"proxy"`
	Profile  string `json:"profile"`
	TwoPhase *bool  `json:"two_phase"`
	Delay    *int   `json:"delay"`
	Verify   bool   `json:"verify"`
}

type verifyInfo struct {
	ScrapingStatus int    `json:"scraping_status"`
	Clean          bool   `json:"clean"`
	Note           string `json:"note"`
}

type solveResponse struct {
	OK          bool        `json:"ok"`
	Status      int         `json:"status,omitempty"`
	Cookie      string      `json:"cookie,omitempty"`
	CookieValue string      `json:"cookie_value,omitempty"`
	CID         string      `json:"cid,omitempty"`
	Site        string      `json:"site,omitempty"`
	TwoPhase    bool        `json:"two_phase"`
	Proxy       string      `json:"proxy,omitempty"`
	Verify      *verifyInfo `json:"verify,omitempty"`
	ElapsedMs   int64       `json:"elapsed_ms"`
	Error       string      `json:"error,omitempty"`
}

var reqCounter atomic.Int64

func main() {
	addr := flag.String("addr", ":8080", "listen address, e.g. :8080 or 127.0.0.1:8080")
	defProfile := flag.String("profile", "chrome_win10", "default browser profile")
	defDelay := flag.Int("delay", 5, "default seconds between phase 1 and 2")
	defProxy := flag.String("proxy", "", "default proxy URL applied when a request omits one")
	flag.Parse()

	srvDefaults := solveRequest{Profile: *defProfile, Proxy: *defProxy}
	dd := &defaultsHolder{req: srvDefaults, delay: *defDelay}

	mux := http.NewServeMux()
	mux.HandleFunc("/solve", dd.handleSolve)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/", handleIndex)

	server := &http.Server{
		Addr:              *addr,
		Handler:           logMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("datadome-server %s listening on %s", serverVersion, *addr)
	log.Printf("POST http://%s/solve  {\"ddk\":\"...\",\"site\":\"https://...\"[,\"cid\":\"...\"]}", displayAddr(*addr))
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}

type defaultsHolder struct {
	req   solveRequest
	delay int
}

func (d *defaultsHolder) handleSolve(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	req, err := parseRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, solveResponse{OK: false, Error: err.Error()})
		return
	}

	if req.Profile == "" {
		req.Profile = d.req.Profile
	}

	if h := proxyFromHeader(r); h != "" {
		req.Proxy = h
	}
	if req.Proxy == "" {
		req.Proxy = d.req.Proxy
	}

	if req.Proxy != "" {
		normalized, perr := datadome.NormalizeProxyURL(req.Proxy)
		if perr != nil {
			writeJSON(w, http.StatusBadRequest, solveResponse{OK: false, Error: "invalid proxy: " + perr.Error()})
			return
		}
		req.Proxy = normalized
	}
	delay := d.delay
	if req.Delay != nil {
		delay = *req.Delay
	}
	twoPhase := true
	if req.TwoPhase != nil {
		twoPhase = *req.TwoPhase
	}

	if req.DDK == "" || req.Site == "" {
		writeJSON(w, http.StatusBadRequest, solveResponse{OK: false, Error: "both 'ddk' and 'site' are required"})
		return
	}

	opts := []datadome.Option{
		datadome.WithDDJSKey(req.DDK),
		datadome.WithProfile(req.Profile),
	}
	if req.CID != "" {
		opts = append(opts, datadome.WithCID(req.CID))
	}
	if req.Proxy != "" {
		opts = append(opts, datadome.WithProxy(req.Proxy))
	}

	client, err := datadome.New(req.Site, opts...)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, solveResponse{OK: false, Error: err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(delay+45)*time.Second)
	defer cancel()

	var result *datadome.Result
	if twoPhase {
		result, err = client.SolveTwoPhase(ctx, time.Duration(delay)*time.Second, "")
	} else {
		result, err = client.Solve(ctx)
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, solveResponse{
			OK: false, Site: client.SiteURL, TwoPhase: twoPhase, Proxy: redactProxy(req.Proxy),
			Error: err.Error(), ElapsedMs: time.Since(start).Milliseconds(),
		})
		return
	}

	cookieValue := firstCookiePair(result.Cookie)
	resp := solveResponse{
		OK:          true,
		Status:      result.Status,
		Cookie:      result.Cookie,
		CookieValue: cookieValue,
		CID:         cidFromCookie(cookieValue),
		Site:        client.SiteURL,
		TwoPhase:    twoPhase,
		Proxy:       redactProxy(req.Proxy),
		ElapsedMs:   time.Since(start).Milliseconds(),
	}

	if req.Verify {
		resp.Verify = runVerify(ctx, client, cookieValue)
	}

	w.Header().Set("X-Datadome-Cookie", cookieValue)
	if result.Cookie != "" {
		w.Header().Add("Set-Cookie", result.Cookie)
	}
	writeJSON(w, http.StatusOK, resp)
}

func runVerify(ctx context.Context, client *datadome.Client, cookieValue string) *verifyInfo {
	scrapingURL := strings.TrimSuffix(client.SiteURL, "/") + "/scraping"
	vctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	status, body, err := client.VerifyURL(vctx, cookieValue, scrapingURL)
	if err != nil {
		return &verifyInfo{ScrapingStatus: 0, Clean: false, Note: "verify request failed: " + err.Error()}
	}
	clean := status == 200 && !looksBlocked(body)
	note := "trusted cookie: /scraping served clean content"
	if !clean {
		note = "cookie was issued but /scraping did not serve clean content (bot-scored or blocked)"
	}
	return &verifyInfo{ScrapingStatus: status, Clean: clean, Note: note}
}

func parseRequest(r *http.Request) (solveRequest, error) {
	var req solveRequest
	ct := r.Header.Get("Content-Type")
	if r.Method == http.MethodPost && strings.Contains(ct, "application/json") {
		dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
		if err := dec.Decode(&req); err != nil {
			return req, fmt.Errorf("invalid JSON body: %w", err)
		}
		return req, nil
	}

	if err := r.ParseForm(); err != nil {
		return req, fmt.Errorf("invalid form: %w", err)
	}
	get := func(k string) string { return strings.TrimSpace(r.Form.Get(k)) }
	req.DDK = firstNonEmpty(get("ddk"), get("key"))
	req.Site = firstNonEmpty(get("site"), get("url"))
	req.CID = get("cid")
	req.Proxy = get("proxy")
	req.Profile = get("profile")
	req.Verify = parseBool(get("verify"))
	if v := get("two_phase"); v != "" {
		b := parseBool(v)
		req.TwoPhase = &b
	}
	if v := get("delay"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			req.Delay = &n
		}
	}
	return req, nil
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": serverVersion, "ddv": serverVersion})
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, `datadome-server %s

POST /solve   application/json  {"ddk":"...","site":"https://...","cid":"(optional)","proxy":"(optional)","two_phase":true,"delay":5,"verify":false}
GET  /solve?ddk=...&site=https://...&cid=...&verify=true
GET  /health

PROXY (optional) — send it as a request header, in ip:port:user:pass form:
    Proxy: 1.2.3.4:8080:username:password
Also accepted: host:port, user:pass@host:port, http(s)://..., socks5://...
Precedence: "Proxy:" header  >  "proxy" body/query field  >  server -proxy default.

Response: {"ok":true,"status":200,"cookie":"datadome=...; ...","cookie_value":"datadome=...","cid":"...","site":"...","proxy":"(redacted)"}
The datadome cookie is also returned in the X-Datadome-Cookie and Set-Cookie response headers.
`, serverVersion)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func firstCookiePair(cookieHeader string) string {
	return strings.TrimSpace(strings.SplitN(cookieHeader, ";", 2)[0])
}

func cidFromCookie(cookiePair string) string {
	parts := strings.SplitN(cookiePair, "=", 2)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

func proxyFromHeader(r *http.Request) string {
	return firstNonEmpty(
		strings.TrimSpace(r.Header.Get("Proxy")),
		strings.TrimSpace(r.Header.Get("X-Proxy")),
	)
}

func redactProxy(proxyURL string) string {
	if proxyURL == "" {
		return ""
	}
	u, err := url.Parse(proxyURL)
	if err != nil || u.User == nil {
		return proxyURL
	}
	if _, hasPass := u.User.Password(); !hasPass {
		return proxyURL
	}
	return u.Scheme + "://" + u.User.Username() + ":***@" + u.Host
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "y", "on":
		return true
	}
	return false
}

func looksBlocked(body string) bool {
	markers := []string{"captcha-delivery", "interstitial", "geo.captcha", "Please enable JS", "data-cfasync", "You have been blocked", "Vous avez"}
	for _, m := range markers {
		if strings.Contains(body, m) {
			return true
		}
	}
	return false
}

func displayAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "localhost" + addr
	}
	return addr
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := reqCounter.Add(1)
		start := time.Now()
		fmt.Fprintf(os.Stderr, "[#%d] %s %s from %s\n", id, r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
		fmt.Fprintf(os.Stderr, "[#%d] done in %s\n", id, time.Since(start).Round(time.Millisecond))
	})
}
