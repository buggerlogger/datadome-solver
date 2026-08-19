package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/buggerlogger/datadome-solver/internal/builder"
	ddcrypto "github.com/buggerlogger/datadome-solver/internal/crypto"
	"github.com/buggerlogger/datadome-solver/pkg/datadome"
)

func main() {
	site := flag.String("site", "", "Target site URL (required)")
	proxy := flag.String("proxy", "", "Proxy: ip:port:user:pass | host:port | user:pass@host:port | http(s)://... | socks5://...")
	profile := flag.String("profile", "chrome_win10", "Browser profile name")
	key := flag.String("key", "", "DataDome JS key (ddk)")
	cid := flag.String("cid", "", "Existing DataDome CID")
	tagsURL := flag.String("tags-url", "", "Custom tags.js POST endpoint")
	solve := flag.Bool("solve", false, "Solve and print cookie")
	verify := flag.Bool("verify", false, "Solve, then verify cookie with GET request")
	twoPhase := flag.Bool("two-phase", false, "Two-phase solve (initial + behavioral)")
	delay := flag.Int("delay", 10, "Delay between phases in seconds")
	bpc := flag.Int("bpc", 1, "BPC value (1=initial, 2+=behavioral)")
	jsType := flag.String("jstype", "ch", "jsType field value")
	eventCounters := flag.String("event-counters", "[]", "Event counters JSON")
	seed := flag.Int64("seed", 0, "PRNG seed for reproducible output")
	encrypt := flag.Bool("encrypt", false, "Print encrypted jspl only")
	output := flag.String("output", "", "Write payload JSON to file")
	scrape := flag.Int("scrape", 0, "After solving, GET /scraping/0..N-1 with the cookie and harvest pagehashes")
	scrapeDelay := flag.Int("scrape-delay", 0, "Milliseconds to sleep between scrape GETs (rate-limit probe)")
	fetchURL := flag.String("fetch", "", "Generic uTLS GET of a single URL (prints status+headers, saves body)")
	fetchMode := flag.String("fetch-mode", "navigate", "Fetch header profile: navigate|iframe|xhr")
	fetchCookie := flag.String("fetch-cookie", "", "Cookie header for -fetch")
	fetchReferer := flag.String("fetch-referer", "", "Referer header for -fetch")
	save := flag.String("save", "", "Write -fetch response body to this file")
	flag.Parse()

	scrapeDelayMs = *scrapeDelay

	if *fetchURL != "" {
		runFetch(*fetchURL, *fetchMode, *fetchCookie, *fetchReferer, *save, *key, *proxy)
		return
	}

	if *site == "" {
		fmt.Fprintln(os.Stderr, "error: -site is required")
		flag.Usage()
		os.Exit(2)
	}

	if *solve || *verify || *twoPhase || *scrape > 0 {
		runSolver(*site, *key, *cid, *proxy, *profile, *tagsURL, *bpc, *jsType, *eventCounters, *delay, *twoPhase, *verify, *scrape)
		return
	}

	signals := builder.BuildPayload(builder.Options{
		Profile: *profile, URL: *site, BPC: *bpc, Seed: *seed,
	})

	if *encrypt {
		if *key == "" {
			fatal("error: -key is required with -encrypt")
		}
		jspl, err := ddcrypto.Encrypt(signals, *key, *cid, nil)
		if err != nil {
			fatal("encrypt: %v", err)
		}
		fmt.Println(jspl)
		return
	}

	m := make(map[string]any, len(signals))
	for _, s := range signals {
		m[s.Key] = s.Value
	}
	data, _ := json.MarshalIndent(m, "", "  ")
	if *output != "" {
		if err := os.WriteFile(*output, data, 0644); err != nil {
			fatal("write: %v", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %d signals to %s\n", len(signals), *output)
		return
	}
	fmt.Print(string(data))
}

func runSolver(site, key, cid, proxy, profile, tagsURL string, bpc int, jsType, eventCounters string, delaySec int, twoPhase, doVerify bool, scrapeN int) {
	if key == "" {
		fatal("error: -key is required with -solve/-verify/-two-phase")
	}

	opts := []datadome.Option{
		datadome.WithDDJSKey(key),
		datadome.WithProfile(profile),
	}
	if cid != "" {
		opts = append(opts, datadome.WithCID(cid))
	}
	if proxy != "" {
		opts = append(opts, datadome.WithProxy(proxy))
	}
	if tagsURL != "" {
		opts = append(opts, datadome.WithTagsURL(tagsURL))
	}

	client, err := datadome.New(site, opts...)
	if err != nil {
		fatal("error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(delaySec+30)*time.Second)
	defer cancel()

	var result *datadome.Result

	if twoPhase {
		result, err = client.SolveTwoPhase(ctx, time.Duration(delaySec)*time.Second, eventCounters)
	} else {
		result, err = client.SolveWith(ctx, datadome.SolveOptions{
			BPC: bpc, JsType: jsType, EventCounters: eventCounters,
		})
	}

	if err != nil {
		fatal("error: %v", err)
	}
	fmt.Println(result.Cookie)

	if doVerify {
		verifyCookie(client, result.Cookie)
	}
	if scrapeN > 0 {
		runScrape(client, result.Cookie, scrapeN)
	}
}

var pagehashRe = regexp.MustCompile(`pagehash_[0-9a-f]+`)

var scrapeDelayMs int

func runScrape(client *datadome.Client, cookieHeader string, n int) {
	cookieVal := strings.SplitN(cookieHeader, ";", 2)[0]
	ok, blocked := 0, 0
	seen := make(map[string]bool)
	start := time.Now()
	for i := 0; i < n; i++ {
		if i > 0 && scrapeDelayMs > 0 {
			time.Sleep(time.Duration(scrapeDelayMs) * time.Millisecond)
		}
		pageURL := fmt.Sprintf("%sscraping/%d", client.SiteURL, i)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		status, body, err := client.VerifyURL(ctx, cookieVal, pageURL)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "scraping/%d ERROR %v\n", i, err)
			blocked++
			continue
		}
		ph := pagehashRe.FindString(body)
		cls := classifyBody(body)
		clean := status == 200 && cls == "CLEAN(no-dd-markers)"
		if clean {
			ok++
			if ph != "" {
				seen[ph] = true
			}
		} else {
			blocked++
		}
		fmt.Printf("[%6.1fs] scraping/%-4d status=%d len=%-5d %-22s %s\n", time.Since(start).Seconds(), i, status, len(body), cls, ph)
	}
	fmt.Fprintf(os.Stderr, "\nSCRAPE SUMMARY: %d/%d clean 200, %d blocked/other, %d unique pagehashes (one cookie, delay=%dms)\n", ok, n, blocked, len(seen), scrapeDelayMs)
}

func runFetch(targetURL, mode, cookie, referer, savePath, key, proxy string) {
	u, err := url.Parse(targetURL)
	if err != nil {
		fatal("fetch: bad url: %v", err)
	}
	origin := u.Scheme + "://" + u.Host
	if key == "" {
		key = "x"
	}
	opts := []datadome.Option{datadome.WithDDJSKey(key)}
	if proxy != "" {
		opts = append(opts, datadome.WithProxy(proxy))
	}
	client, err := datadome.New(origin, opts...)
	if err != nil {
		fatal("fetch: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := client.Fetch(ctx, http.MethodGet, targetURL, cookie, referer, mode)
	if err != nil {
		fatal("fetch: %v", err)
	}
	fmt.Fprintf(os.Stderr, "GET %s -> %d  len=%d  %s\n", targetURL, res.Status, len(res.Body), classifyBody(string(res.Body)))
	for _, h := range []string{"Set-Cookie", "X-Datadome-Cid", "X-Dd-B", "Location", "Content-Type"} {
		for _, v := range res.Headers.Values(h) {
			fmt.Fprintf(os.Stderr, "  %s: %s\n", h, v)
		}
	}
	if savePath != "" {
		if err := os.WriteFile(savePath, res.Body, 0644); err != nil {
			fatal("save: %v", err)
		}
		fmt.Fprintf(os.Stderr, "  saved %d bytes -> %s\n", len(res.Body), savePath)
	} else {
		os.Stdout.Write(res.Body)
	}
}

func classifyBody(body string) string {
	markers := []string{"captcha-delivery", "interstitial", "'rt':'c'", "\"rt\":\"c\"", "geo.captcha", "Please enable JS", "data-cfasync", "DataDome", "ddm =", "Vous avez", "blocked"}
	var hits []string
	for _, m := range markers {
		if strings.Contains(body, m) {
			hits = append(hits, m)
		}
	}
	if len(hits) == 0 {
		return "CLEAN(no-dd-markers)"
	}
	return "CHALLENGE[" + strings.Join(hits, ",") + "]"
}

func verifyCookie(client *datadome.Client, cookieHeader string) {
	cookieVal := strings.SplitN(cookieHeader, ";", 2)[0]

	scrapingURLc := strings.TrimSuffix(client.SiteURL, "/") + "/scraping"
	cctx, ccancel := context.WithTimeout(context.Background(), 15*time.Second)
	cstatus, cbody, cerr := client.VerifyURL(cctx, "datadome=GARBAGE_CONTROL_0000000000", scrapingURLc)
	ccancel()
	if cerr != nil {
		fmt.Fprintf(os.Stderr, "[control] GET /scraping (bogus cookie) error: %v\n", cerr)
	} else {
		os.WriteFile("control_scraping.html", []byte(cbody), 0644)
		fmt.Fprintf(os.Stderr, "[control] GET /scraping (bogus cookie): %d  len=%d  %s\n", cstatus, len(cbody), classifyBody(cbody))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	status, body, err := client.Verify(ctx, cookieVal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify error: %v\n", err)
		return
	}
	os.WriteFile("verify_root.html", []byte(body), 0644)
	fmt.Fprintf(os.Stderr, "GET /: %d  len=%d  %s\n", status, len(body), classifyBody(body))

	ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel2()

	scrapingURL := strings.TrimSuffix(client.SiteURL, "/") + "/scraping"
	status2, body2, err2 := client.VerifyURL(ctx2, cookieVal, scrapingURL)
	if err2 != nil {
		fmt.Fprintf(os.Stderr, "verify /scraping error: %v\n", err2)
		return
	}
	os.WriteFile("verify_scraping.html", []byte(body2), 0644)
	fmt.Fprintf(os.Stderr, "GET /scraping: %d  len=%d  %s\n", status2, len(body2), classifyBody(body2))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
