package datadome

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/buggerlogger/datadome-solver/internal/builder"
	ddcrypto "github.com/buggerlogger/datadome-solver/internal/crypto"
)

const (
	clientVersion = "5.9.2"

	defaultUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
	chromeFull = "151.0.7922.138"

	chUA              = `"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"`
	chUAFull          = `"Not=A?Brand";v="99.0.0.0", "Google Chrome";v="` + chromeFull + `", "Chromium";v="` + chromeFull + `"`
	chPlatformVersion = `"19.0.0"`
)

type Client struct {
	SiteURL  string
	ProxyURL string
	DDJSKey  string
	CID      string
	Profile  string
	TagsURL  string
	HTTP     *http.Client
}

type Result struct {
	Status int            `json:"status"`
	Cookie string         `json:"cookie"`
	Raw    map[string]any `json:"-"`
}

type Option func(*Client)

func WithProxy(proxyURL string) Option     { return func(c *Client) { c.ProxyURL = proxyURL } }
func WithDDJSKey(key string) Option        { return func(c *Client) { c.DDJSKey = key } }
func WithCID(cid string) Option            { return func(c *Client) { c.CID = cid } }
func WithProfile(profile string) Option    { return func(c *Client) { c.Profile = profile } }
func WithTagsURL(tagsURL string) Option    { return func(c *Client) { c.TagsURL = tagsURL } }
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.HTTP = h } }

func New(siteURL string, opts ...Option) (*Client, error) {
	if siteURL == "" {
		return nil, fmt.Errorf("datadome: site URL is required")
	}
	if !strings.HasPrefix(siteURL, "http://") && !strings.HasPrefix(siteURL, "https://") {
		siteURL = "https://" + siteURL
	}
	u, err := url.Parse(siteURL)
	if err != nil {
		return nil, fmt.Errorf("datadome: invalid site URL: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("datadome: site URL must include a host")
	}

	c := &Client{
		SiteURL: strings.TrimSuffix(siteURL, "/") + "/",
		Profile: "chrome_win10",
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.DDJSKey == "" {
		return nil, fmt.Errorf("datadome: DDJSKey is required (use WithDDJSKey)")
	}
	if c.HTTP == nil {
		c.HTTP, err = newHTTPClient(c.ProxyURL)
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Client) BuildPayload(serverHash *string, bpc int) []ddcrypto.Signal {
	return builder.BuildPayload(builder.Options{
		Profile:    c.Profile,
		URL:        c.SiteURL,
		ServerHash: serverHash,
		BPC:        bpc,
	})
}

func (c *Client) EncryptJSPL(signals []ddcrypto.Signal) (string, error) {
	return ddcrypto.Encrypt(signals, c.DDJSKey, c.CID, nil)
}

type SolveOptions struct {
	BPC           int
	JsType        string
	EventCounters string
}

func (c *Client) Solve(ctx context.Context) (*Result, error) {
	return c.SolveWith(ctx, SolveOptions{})
}

func (c *Client) SolveWith(ctx context.Context, opts SolveOptions) (*Result, error) {
	bpc := max(opts.BPC, 1)
	jsType := opts.JsType
	if jsType == "" {
		jsType = "ch"
	}
	eventCounters := opts.EventCounters
	if eventCounters == "" {
		eventCounters = "[]"
	}

	signals := c.BuildPayload(nil, bpc)
	jspl, err := c.EncryptJSPL(signals)
	if err != nil {
		return nil, fmt.Errorf("datadome: encrypt: %w", err)
	}

	endpoint, origin, referer, err := c.endpoints()
	if err != nil {
		return nil, err
	}

	return c.postPayload(ctx, endpoint, origin, referer, jspl, jsType, eventCounters, c.CID)
}

func (c *Client) SolveTwoPhase(ctx context.Context, delay time.Duration, eventCounters string) (*Result, error) {
	signals := c.BuildPayload(nil, 1)

	endpoint, origin, referer, err := c.endpoints()
	if err != nil {
		return nil, err
	}

	jspl1, err := ddcrypto.Encrypt(signals, c.DDJSKey, c.CID, nil)
	if err != nil {
		return nil, fmt.Errorf("datadome: encrypt phase1: %w", err)
	}

	result1, err := c.postPayload(ctx, endpoint, origin, referer, jspl1, "ch", "[]", c.CID)
	if err != nil {
		return nil, fmt.Errorf("datadome: phase1: %w", err)
	}

	cid := extractCIDFromCookie(result1.Cookie)
	if cid == "" {
		return result1, fmt.Errorf("datadome: could not extract CID from phase1 cookie")
	}
	fmt.Fprintf(os.Stderr, "phase1: status=%d cid=%s...\n", result1.Status, truncate(cid, 30))

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return result1, ctx.Err()
		}
	}

	for i := range signals {
		if signals[i].Key == "bpc" {
			signals[i].Value = 2
		}
		if signals[i].Key == "jset" {
			signals[i].Value = time.Now().UnixMilli() / 1000
		}
	}

	jspl2, err := ddcrypto.Encrypt(signals, c.DDJSKey, cid, nil)
	if err != nil {
		return nil, fmt.Errorf("datadome: encrypt phase2: %w", err)
	}

	if eventCounters == "" {
		eventCounters = Build590EventCounters()
	}

	result2, err := c.postPayload(ctx, endpoint, origin, referer, jspl2, "le", eventCounters, cid)
	if err != nil {
		return nil, fmt.Errorf("datadome: phase2: %w", err)
	}
	fmt.Fprintf(os.Stderr, "phase2: status=%d\n", result2.Status)
	return result2, nil
}

type FetchResult struct {
	Status  int
	Headers http.Header
	Body    []byte
}

func (c *Client) Fetch(ctx context.Context, method, targetURL, cookie, referer, mode string) (*FetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil, err
	}
	switch mode {
	case "check":

		req.Header.Set("accept", "*/*")
		req.Header.Set("content-type", "application/x-www-form-urlencoded; charset=UTF-8")
		if referer != "" {
			req.Header.Set("referer", referer)
		}
		req.Header.Set("sec-ch-ua", chUA)
		req.Header.Set("sec-ch-ua-mobile", "?0")
		req.Header.Set("sec-ch-ua-platform", `"Windows"`)
		req.Header.Set("user-agent", defaultUA)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, fmt.Errorf("datadome: fetch failed: %w", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return &FetchResult{Status: resp.StatusCode, Headers: resp.Header, Body: body}, nil
	case "xhr":
		req.Header.Set("accept", "*/*")
		req.Header.Set("sec-fetch-dest", "empty")
		req.Header.Set("sec-fetch-mode", "cors")
		req.Header.Set("sec-fetch-site", "same-origin")
	case "iframe":
		req.Header.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		req.Header.Set("sec-fetch-dest", "iframe")
		req.Header.Set("sec-fetch-mode", "navigate")
		req.Header.Set("sec-fetch-site", "cross-site")
		req.Header.Set("upgrade-insecure-requests", "1")
	default:
		req.Header.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		req.Header.Set("sec-fetch-dest", "document")
		req.Header.Set("sec-fetch-mode", "navigate")
		req.Header.Set("sec-fetch-site", "none")
		req.Header.Set("sec-fetch-user", "?1")
		req.Header.Set("upgrade-insecure-requests", "1")
	}
	req.Header.Set("accept-language", "en-US,en;q=0.9")
	if cookie != "" {
		req.Header.Set("cookie", cookie)
	}
	if referer != "" {
		req.Header.Set("referer", referer)
	}
	setChromeHeaders(req)
	req.Header.Set("user-agent", defaultUA)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("datadome: fetch failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return &FetchResult{Status: resp.StatusCode, Headers: resp.Header, Body: body}, nil
}

func (c *Client) Verify(ctx context.Context, cookie string) (int, string, error) {
	return c.VerifyURL(ctx, cookie, c.SiteURL)
}

func (c *Client) VerifyURL(ctx context.Context, cookie, targetURL string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("accept-language", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("cache-control", "max-age=0")
	req.Header.Set("cookie", cookie)
	setChromeHeaders(req)
	req.Header.Set("sec-fetch-dest", "document")
	req.Header.Set("sec-fetch-mode", "navigate")
	req.Header.Set("sec-fetch-site", "none")
	req.Header.Set("sec-fetch-user", "?1")
	req.Header.Set("upgrade-insecure-requests", "1")
	req.Header.Set("user-agent", defaultUA)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("datadome: verify failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

func (c *Client) postPayload(ctx context.Context, endpoint, origin, referer, jspl, jsType, eventCounters, cid string) (*Result, error) {
	form := url.Values{}
	form.Set("jspl", jspl)
	form.Set("eventCounters", eventCounters)
	form.Set("jsType", jsType)
	form.Set("cid", cid)
	form.Set("ddk", c.DDJSKey)
	form.Set("Referer", url.QueryEscape(c.SiteURL))
	form.Set("request", "%2F")
	form.Set("responsePage", "origin")
	form.Set("ddv", clientVersion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "*/*")
	req.Header.Set("accept-language", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("downlink", "10")
	req.Header.Set("ect", "4g")
	req.Header.Set("origin", origin)
	req.Header.Set("priority", "u=1, i")
	req.Header.Set("referer", referer)
	req.Header.Set("rtt", "0")
	setChromeHeaders(req)
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-site", "cross-site")
	req.Header.Set("user-agent", defaultUA)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("datadome: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("datadome: invalid JSON (%d): %s", resp.StatusCode, truncate(string(body), 200))
	}

	result := &Result{Raw: raw}
	if st, ok := raw["status"].(float64); ok {
		result.Status = int(st)
	}
	if cookie, ok := raw["cookie"].(string); ok {
		result.Cookie = cookie
	}

	if result.Status != 200 {
		return result, fmt.Errorf("datadome: solve failed (status %d)", result.Status)
	}
	return result, nil
}

func setChromeHeaders(req *http.Request) {
	req.Header.Set("dpr", "1")
	req.Header.Set("sec-ch-dpr", "1")
	req.Header.Set("sec-ch-ua", chUA)
	req.Header.Set("sec-ch-ua-arch", `"x86"`)
	req.Header.Set("sec-ch-ua-bitness", `"64"`)
	req.Header.Set("sec-ch-ua-full-version-list", chUAFull)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"Windows"`)
	req.Header.Set("sec-ch-ua-platform-version", chPlatformVersion)
}

func (c *Client) endpoints() (tagsEndpoint, origin, referer string, err error) {
	u, err := url.Parse(c.SiteURL)
	if err != nil {
		return "", "", "", err
	}
	origin = u.Scheme + "://" + u.Host
	referer = c.SiteURL
	if c.TagsURL != "" {
		tagsEndpoint = c.TagsURL
	} else {
		tagsEndpoint = "https://api-js.datadome.co/js/"
	}
	return tagsEndpoint, origin, referer, nil
}

func extractCIDFromCookie(cookieHeader string) string {
	parts := strings.SplitN(cookieHeader, "=", 2)
	if len(parts) < 2 {
		return cookieHeader
	}
	val := parts[1]
	if idx := strings.Index(val, ";"); idx >= 0 {
		val = val[:idx]
	}
	return val
}

func newHTTPClient(proxyURL string) (*http.Client, error) {
	ct, err := newChromeTransport(proxyURL)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: ct,
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func Build590EventCounters() string {
	ri := func(lo, hi int) int { return lo + rand590.Intn(hi-lo+1) }
	rf := func(lo, hi float64) float64 { return lo + rand590.Float64()*(hi-lo) }

	mousemove := ri(60, 129)
	click := ri(2, 8)
	scroll := ri(0, 3)

	cmR := -1.0
	if mousemove > 0 {
		cmR = float64(click) / float64(mousemove)
	}
	msR := -1.0
	if scroll > 0 {
		msR = float64(mousemove) / float64(scroll)
	}

	esSig := rf(0.004, 0.08)
	esMu := rf(6.9, 10.4)
	esDist := rf(35, 380)
	esAngS := rf(-3.14159, 3.14159)
	esAngE := rf(-3.14159, 3.14159)

	pFc := ri(48, 100)
	pCf := ri(40, pFc)
	clsd := pCf * ri(2, 5)
	pCmx := ri(3, 12)
	pPf := ri(0, pFc-10)
	pPs := pPf * ri(1, 3)

	fmi := ri(180, 3200)

	return fmt.Sprintf(
		`{"m_s_c":%d,"m_m_c":%d,"m_c_c":%d,"m_cm_r":%s,"m_ms_r":%s,"m_fmi":%d,`+
			`"es_sigmdn":%s,"es_mumdn":%s,"es_distmdn":%s,"es_angsmdn":%s,"es_angemdn":%s,`+
			`"p_fc":%d,"m_clsdcnt":%d,"p_cf":%d,"p_cmx":%d,"p_ps":%d,"p_pf":%d,`+
			`"jset":%d,"nddc":1,"exp8":0,"nowd":false,"sfex":false}`,
		scroll, mousemove, click, trimFloat(cmR), trimFloat(msR), fmi,
		f6(esSig), f6(esMu), f6(esDist), f6(esAngS), f6(esAngE),
		pFc, clsd, pCf, pCmx, pPs, pPf,
		time.Now().Unix(),
	)
}

func trimFloat(f float64) string {
	if f == -1 {
		return "-1"
	}
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func f6(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

var rand590 = rand.New(rand.NewSource(time.Now().UnixNano()))
