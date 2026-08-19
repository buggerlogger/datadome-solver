package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/buggerlogger/datadome-solver/pkg/datadome"
)

const (
	domain  = "bounty-nodejs.datashield.co"
	baseURL = "https://" + domain
	ddk     = "E8518C242C1949A9B37C3394607069"
	ua      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
)

var unreserved = func() [256]bool {
	var t [256]bool
	for c := 'A'; c <= 'Z'; c++ {
		t[c] = true
	}
	for c := 'a'; c <= 'z'; c++ {
		t[c] = true
	}
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	for _, c := range []byte("-_.~") {
		t[c] = true
	}
	return t
}()

func pctEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if unreserved[c] {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func grab(html, name string) string {
	m := regexp.MustCompile(regexp.QuoteMeta(name) + `:\s*'([^']*)'`).FindStringSubmatch(html)
	if m != nil {
		return m[1]
	}
	return ""
}

func grabEnc(html, name string) string {
	m := regexp.MustCompile(regexp.QuoteMeta(name) + `.*?encodeURIComponent\(\s*'([^']*)'`).FindStringSubmatch(html)
	if m != nil {
		return m[1]
	}
	return ""
}

func main() {
	solverDir := os.Getenv("DD_SOLVER_DIR")
	if solverDir == "" {
		solverDir = `C:\Users\ASOO\Desktop\ctf challenge\datadome-scraping-solver\solver`
	}
	solverJS := os.Getenv("DD_SOLVER")
	if solverJS == "" {
		solverJS = "solve_bounty_gold.js"
	}
	proxy := os.Getenv("DD_PROXY")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Second)
	defer cancel()

	opts := []datadome.Option{datadome.WithDDJSKey(ddk)}
	if proxy != "" {
		opts = append(opts, datadome.WithProxy(proxy))
	}
	c, err := datadome.New(baseURL, opts...)
	if err != nil {
		fail("client: %v", err)
	}

	fmt.Println("[1] GET /scraping (cold, uTLS navigate) — expect 403 + dd block")
	r1, err := c.FetchRaw(ctx, "GET", baseURL+"/scraping", map[string]string{
		"accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		"accept-language":           "en-US,en;q=0.9",
		"sec-fetch-dest":            "document",
		"sec-fetch-mode":            "navigate",
		"sec-fetch-site":            "none",
		"sec-fetch-user":            "?1",
		"upgrade-insecure-requests": "1",
	})
	if err != nil {
		fail("step1: %v", err)
	}
	body1 := string(r1.Body)
	fmt.Printf("    HTTP %d  len=%d  x-dd-b=%s\n", r1.Status, len(body1), hdr(r1, "x-dd-b"))
	if r1.Status == 200 && strings.Contains(body1, "pagehash_") {
		fmt.Println("    already cleared (200 + pagehash); nothing to solve.")
		return
	}
	dd := parseDD(body1)
	if dd["cid"] == "" {
		fail("no dd.cid parsed from 403 page")
	}
	fmt.Printf("    dd.cid=%.22s...  host=%s  rt=%s\n", dd["cid"], dd["host"], dd["rt"])

	host := strings.ReplaceAll(dd["host"], "&#x2d;", "-")
	if host == "" {
		host = "geo.captcha-delivery.com"
	}
	hsh := orDefault(dd["hsh"], ddk)
	capQP := strings.Join([]string{
		"initialCid=" + pctEscape(dd["cid"]),
		"hash=" + pctEscape(hsh),
		"cid=" + pctEscape(dd["cookie"]),
		"t=" + pctEscape(orDefault(dd["t"], "fe")),
		"referer=" + pctEscape(baseURL+"/scraping"),
		"s=" + dd["s"],
		"e=" + pctEscape(dd["e"]),
		"dm=cd",
	}, "&")
	capURL := "https://" + host + "/captcha/?" + capQP
	fmt.Println("[2] GET captcha page (uTLS iframe)")
	r2, err := c.FetchRaw(ctx, "GET", capURL, map[string]string{
		"accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		"accept-language": "en-US,en;q=0.9",
		"sec-fetch-dest":  "iframe",
		"sec-fetch-mode":  "navigate",
		"sec-fetch-site":  "cross-site",
		"referer":         baseURL + "/scraping",
	})
	if err != nil {
		fail("step2: %v", err)
	}
	capHTML := string(r2.Body)
	mode := "puzzle"
	if strings.Contains(capHTML, "noPuzzle: true") {
		mode = "simple/noPuzzle"
	}
	fmt.Printf("    HTTP %d  %d bytes from %s  mode=%s\n", r2.Status, len(capHTML), host, mode)
	if r2.Status != 200 {
		fail("captcha page status %d", r2.Status)
	}

	tok := map[string]string{
		"cid":     grab(capHTML, "cid"),
		"hash":    orDefault(grab(capHTML, "hash"), hsh),
		"userEnv": grab(capHTML, "userEnv"),
		"s":       orDefault(grab(capHTML, "s"), orDefault(dd["s"], "9193")),
	}
	if m := regexp.MustCompile(`ddm\.referer\s*=\s*htmlDecode\(\s*'([^']*)'\s*\)`).FindStringSubmatch(capHTML); m != nil {
		tok["referer"] = m[1]
	} else {
		tok["referer"] = baseURL + "/scraping"
	}
	tok["icid"] = orDefault(grabEnc(capHTML, "icid"), dd["cid"])
	tok["ddCaptchaChallenge"] = grabEnc(capHTML, "ddCaptchaChallenge")
	tok["ddCaptchaEnv"] = grabEnc(capHTML, "ddCaptchaEnv")
	tok["ddCaptchaAudioChallenge"] = grabEnc(capHTML, "ddCaptchaAudioChallenge")
	tok["e"] = dd["e"]
	if tok["cid"] == "" {
		fail("no check cid parsed from captcha page")
	}

	fmt.Println("[3] Solve captcha (node " + solverJS + ")")
	eVal := tok["e"]
	if eVal == "" {
		eVal = strings.Repeat("0", 64)
	}
	live := map[string]string{
		"initialCid": tok["icid"], "cid": tok["cid"], "hash": tok["hash"],
		"refererUrl": baseURL + "/scraping", "s": tok["s"], "e": eVal,
		"userEnv": tok["userEnv"], "fonts": "",
	}
	liveJSON, _ := json.Marshal(live)
	cfg := filepath.Join(solverDir, "_go_captcha_tokens.json")
	if err := os.WriteFile(cfg, liveJSON, 0644); err != nil {
		fail("write tokens: %v", err)
	}
	defer os.Remove(cfg)
	cmd := exec.CommandContext(ctx, "node", solverJS, "--config="+cfg)
	cmd.Dir = solverDir
	solOut, err := cmd.Output()
	if err != nil {
		fail("node solver: %v (%s)", err, tailStderr(err))
	}
	var built struct {
		Payload string `json:"ddCaptchaEncodedPayload"`
		Plv3    string `json:"plv3"`
		Cid     string `json:"cid"`
		SLLAjC  any    `json:"sLLAjC"`
		Keys    int    `json:"keys"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(solOut, &built); err != nil {
		fail("solver output not JSON: %.200s", string(solOut))
	}
	if built.Error != "" {
		fail("solver error: %.200s", built.Error)
	}
	fmt.Printf("    keys=%d  payload=%d  plv3=%d\n", built.Keys, len(built.Payload), len(built.Plv3))

	pairs := [][2]string{
		{"cid", tok["cid"]}, {"icid", tok["icid"]}, {"ccid", ""},
		{"userEnv", tok["userEnv"]}, {"dm", "cd"},
		{"ddCaptchaChallenge", tok["ddCaptchaChallenge"]},
		{"ddCaptchaEncodedPayload", built.Payload}, {"plv3", built.Plv3},
		{"ddCaptchaEnv", tok["ddCaptchaEnv"]},
		{"ddCaptchaAudioChallenge", tok["ddCaptchaAudioChallenge"]},
		{"hash", tok["hash"]}, {"ua", ua}, {"referer", tok["referer"]},
		{"parent_url", ""}, {"x-forwarded-for", ""}, {"s", tok["s"]}, {"ir", ""},
	}
	var qb []string
	for _, p := range pairs {
		qb = append(qb, p[0]+"="+pctEscape(p[1]))
	}
	checkURL := "https://" + host + "/captcha/check?" + strings.Join(qb, "&")
	fmt.Println("[4] GET /captcha/check (uTLS xhr) — expect a datadome cookie")
	r4, err := c.FetchRaw(ctx, "GET", checkURL, map[string]string{
		"accept":          "*/*",
		"accept-language": "en-US,en;q=0.9",
		"sec-fetch-dest":  "empty",
		"sec-fetch-mode":  "cors",
		"sec-fetch-site":  "cross-site",
		"referer":         "https://" + host + "/",
		"origin":          "https://" + host,
	})
	if err != nil {
		fail("step4: %v", err)
	}
	cookie := extractCookie(r4.Body)
	fmt.Printf("    HTTP %d  cookie=%s\n", r4.Status, tern(cookie != "", "issued", "NONE"))
	if cookie == "" {
		fail("no cookie issued. body: %.200s", string(r4.Body))
	}
	fmt.Printf("    datadome=%.46s...\n", cookie)

	fmt.Println("[5] GET /scraping WITH captcha cookie (uTLS navigate) — want 200 + pagehash")
	r5, err := c.FetchRaw(ctx, "GET", baseURL+"/scraping", map[string]string{
		"accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		"accept-language":           "en-US,en;q=0.9",
		"cookie":                    "datadome=" + cookie,
		"referer":                   baseURL + "/",
		"sec-fetch-dest":            "document",
		"sec-fetch-mode":            "navigate",
		"sec-fetch-site":            "none",
		"sec-fetch-user":            "?1",
		"upgrade-insecure-requests": "1",
	})
	if err != nil {
		fail("step5: %v", err)
	}
	body5 := string(r5.Body)
	ph := regexp.MustCompile(`pagehash_[a-f0-9]+`).FindString(body5)
	fmt.Printf("    HTTP %d  len=%d  x-dd-b=%s  x-datadome=%s  pagehash=%s\n",
		r5.Status, len(body5), hdr(r5, "x-dd-b"), hdr(r5, "x-datadome"), orDefault(ph, "none"))

	if r5.Status == 200 && ph != "" {
		fmt.Println("\n*** SUCCESS — captcha-solve cookie cleared /scraping over uTLS (200 + pagehash) ***")
		return
	}
	fmt.Println("\n    captcha cookie still bot-scored over uTLS — the offline-solve cookie is")
	fmt.Println("    low-trust independent of transport; the api-js telemetry path remains the win.")
	os.Exit(6)
}

func parseDD(html string) map[string]string {
	dd := map[string]string{}
	bm := regexp.MustCompile(`(?s)var dd=\{(.+?)\}`).FindStringSubmatch(html)
	if bm == nil {
		return dd
	}
	raw := "{" + bm[1] + "}"
	for _, m := range regexp.MustCompile(`'(\w+)'\s*:\s*'([^']*)'`).FindAllStringSubmatch(raw, -1) {
		dd[m[1]] = m[2]
	}
	if m := regexp.MustCompile(`'s'\s*:\s*(\d+)`).FindStringSubmatch(raw); m != nil {
		dd["s"] = m[1]
	}
	return dd
}

func extractCookie(body []byte) string {
	var j map[string]any
	if err := json.Unmarshal(body, &j); err != nil {
		return ""
	}
	cs, _ := j["cookie"].(string)
	if cs == "" {
		return ""
	}
	if i := strings.Index(cs, "datadome="); i >= 0 {
		cs = cs[i+len("datadome="):]
	}
	if i := strings.Index(cs, ";"); i >= 0 {
		cs = cs[:i]
	}
	return strings.TrimSpace(cs)
}

func hdr(r *datadome.FetchResult, k string) string {
	if v := r.Headers.Get(k); v != "" {
		return v
	}
	return "-"
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func tern(b bool, a, c string) string {
	if b {
		return a
	}
	return c
}

func tailStderr(err error) string {
	if ee, ok := err.(*exec.ExitError); ok {
		s := string(ee.Stderr)
		if len(s) > 300 {
			return s[len(s)-300:]
		}
		return s
	}
	return ""
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", a...)
	os.Exit(1)
}
