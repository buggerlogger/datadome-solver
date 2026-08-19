package datadome_test

import (
	"strings"
	"testing"

	"github.com/buggerlogger/datadome-solver/internal/builder"
	ddcrypto "github.com/buggerlogger/datadome-solver/internal/crypto"
	"github.com/buggerlogger/datadome-solver/pkg/datadome"
)

func TestNewRequiresSiteAndKey(t *testing.T) {
	_, err := datadome.New("")
	if err == nil {
		t.Fatal("expected error for empty site")
	}
	_, err = datadome.New("https://example.com/")
	if err == nil {
		t.Fatal("expected error without DDJSKey")
	}
}

func TestNewWithProxy(t *testing.T) {
	c, err := datadome.New(
		"https://example.com/",
		datadome.WithDDJSKey("0000000000000000000000000000000"),
		datadome.WithProxy("http://127.0.0.1:8080"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if c.ProxyURL != "http://127.0.0.1:8080" {
		t.Fatalf("proxy = %q", c.ProxyURL)
	}
}

func TestBuildAndEncrypt(t *testing.T) {
	c, err := datadome.New(
		"https://example.com/",
		datadome.WithDDJSKey("0000000000000000000000000000000"),
	)
	if err != nil {
		t.Fatal(err)
	}
	signals := c.BuildPayload(nil, 1)
	if len(signals) < 100 {
		t.Fatalf("expected many signals, got %d", len(signals))
	}
	jspl, err := c.EncryptJSPL(signals)
	if err != nil {
		t.Fatal(err)
	}
	if len(jspl) < 100 {
		t.Fatalf("jspl too short: %d", len(jspl))
	}

	ts := int64(1787043822000)
	jspl2, err := ddcrypto.Encrypt(signals, "0000000000000000000000000000000", "cid592", &ts)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := ddcrypto.Decrypt(jspl2, "0000000000000000000000000000000", "cid592", ts)
	if err != nil {
		t.Fatalf("build→encrypt→decrypt: %v rem=%d", err, len(jspl2)%4)
	}
	ua, _ := obj["ua"].(string)
	if !strings.Contains(ua, "Chrome/151") {
		t.Fatalf("decrypted ua = %q", ua)
	}
	for _, k := range []string{"ftsa", "tzp", "wglo", "addt", "vpbq", "muev", "wdifrm", "m_scw", "m_sch", "cpup", "br_iw", "csssp", "wwl"} {
		if _, ok := obj[k]; !ok {
			t.Errorf("decrypted payload missing %s", k)
		}
	}
}

func TestEncryptDeterministic(t *testing.T) {
	signals := []ddcrypto.Signal{{Key: "log3", Value: "gl,tzp"}}
	ts := int64(1700000000000)
	key := "0000000000000000000000000000000"

	a, err := ddcrypto.Encrypt(signals, key, "", &ts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ddcrypto.Encrypt(signals, key, "", &ts)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("same inputs should yield same jspl")
	}
}

func TestBuilderSignalCount(t *testing.T) {
	signals := builder.BuildPayload(builder.Options{
		Profile: "chrome_win10",
		URL:     "https://example.com/",
		BPC:     1,
	})
	if len(signals) < 150 {
		t.Fatalf("expected 150+ signals, got %d", len(signals))
	}
	found := map[string]bool{}
	for _, s := range signals {
		found[s.Key] = true
	}
	for _, required := range []string{
		"ua", "bchk", "log3", "fph", "sgb", "sgc", "bpc",
		"ftsa", "tzp", "muev", "wglo", "addt", "vpbq", "wdifrm",
		"m_scw", "m_sch", "cpup", "br_iw", "csssp", "wwl",
	} {
		if !found[required] {
			t.Errorf("missing required signal: %s", required)
		}
	}
	ua, _ := payloadValue(signals, "ua").(string)
	if !strings.Contains(ua, "Chrome/151") {
		t.Errorf("ua must be Chrome 151, got %q", ua)
	}
	nhi, _ := payloadValue(signals, "nhi").(string)
	if !strings.Contains(nhi, "151.0.7922.138") {
		t.Errorf("nhi must carry Chrome 151 full version, got %q", nhi)
	}
}

func payloadValue(signals []ddcrypto.Signal, key string) any {
	for _, s := range signals {
		if s.Key == key {
			return s.Value
		}
	}
	return nil
}
