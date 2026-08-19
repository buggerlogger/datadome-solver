package crypto

import (
	"fmt"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := "E8518C242C1949A9B37C3394607069"
	cid := "testcid592"
	ts := int64(1787043822000)

	signals := []Signal{
		{Key: "log3", Value: "gl,tzp"},
		{Key: "ftsa", Value: `caption:Arial,icon:Arial`},
		{Key: "tzp", Value: "Africa/Cairo"},
		{Key: "wglo", Value: true},
		{Key: "addt", Value: true},
		{Key: "vpbq", Value: true},
		{Key: "muev", Value: false},
		{Key: "wdifrm", Value: false},
		{Key: "m_scw", Value: 1920},
		{Key: "m_sch", Value: 1080},
		{Key: "cpup", Value: -1},
		{Key: "bpc", Value: 1},
		{Key: "jset", Value: ts / 1000},
	}

	jspl, err := Encrypt(signals, key, cid, &ts)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := Decrypt(jspl, key, cid, ts)
	if err != nil {
		t.Fatalf("decrypt: %v  jspl_len=%d rem=%d", err, len(jspl), len(jspl)%4)
	}
	if obj["log3"] != "gl,tzp" {
		t.Fatalf("log3 = %#v", obj["log3"])
	}
	if obj["tzp"] != "Africa/Cairo" {
		t.Fatalf("tzp = %#v", obj["tzp"])
	}
	if obj["cpup"].(float64) != -1 {
		t.Fatalf("cpup = %#v", obj["cpup"])
	}
}

func TestEncryptDecryptRemainderClasses(t *testing.T) {
	key := "0000000000000000000000000000000"
	cid := "cid"
	ts := int64(1700000000000)
	seen := map[int]bool{}

	for n := 1; n <= 40 && len(seen) < 3; n++ {
		signals := make([]Signal, 0, n)
		for i := 0; i < n; i++ {
			signals = append(signals, Signal{Key: fmt.Sprintf("k%02d", i), Value: i})
		}
		jspl, err := Encrypt(signals, key, cid, &ts)
		if err != nil {
			t.Fatal(err)
		}
		rem := len(jspl) % 4
		obj, err := Decrypt(jspl, key, cid, ts)
		if err != nil {
			t.Fatalf("n=%d rem=%d decrypt: %v", n, rem, err)
		}
		if int(obj["k00"].(float64)) != 0 {
			t.Fatalf("n=%d rem=%d k00=%#v", n, rem, obj["k00"])
		}
		seen[rem] = true
	}
	for _, rem := range []int{0, 2, 3} {
		if !seen[rem] {
			t.Errorf("never hit jspl len %% 4 == %d (rem=1 is unused by the codec)", rem)
		}
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	ts := int64(1700000000000)
	jspl, err := Encrypt([]Signal{{Key: "ua", Value: "Chrome/151"}}, "key-a", "cid", &ts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(jspl, "key-b", "cid", ts); err == nil {
		t.Fatal("wrong ddk must fail")
	}
	if _, err := Decrypt(jspl, "key-a", "other-cid", ts); err == nil {
		t.Fatal("wrong cid must fail")
	}
	if _, err := Decrypt(jspl, "key-a", "cid", ts); err != nil {
		t.Fatalf("correct key must decrypt: %v", err)
	}
}

func TestTwoStringSignals(t *testing.T) {
	cid := "c"
	ts := int64(1700000000000)
	cases := [][]Signal{
		{{Key: "a", Value: "x"}},
		{{Key: "a", Value: "x"}, {Key: "b", Value: "y"}},
		{{Key: "log3", Value: "gl,tzp"}, {Key: "ftsa", Value: "caption:Arial"}},
		{{Key: "log3", Value: "gl,tzp"}, {Key: "ftsa", Value: `caption:Arial,icon:Arial`}},
		{{Key: "log3", Value: "gl,tzp"}, {Key: "ftsa", Value: `caption:Arial,icon:Arial`}, {Key: "tzp", Value: "Africa/Cairo"}},
		{{Key: "log3", Value: "gl,tzp"}, {Key: "wglo", Value: true}},
		{{Key: "log3", Value: "gl,tzp"}, {Key: "cpup", Value: -1}},
		{{Key: "log3", Value: "gl,tzp"}, {Key: "m_scw", Value: 1920}, {Key: "jset", Value: int64(1787043822)}},
	}
	keys := []string{"k", "E8518C242C1949A9B37C3394607069"}
	for _, key := range keys {
		for i, signals := range cases {
			jspl, err := Encrypt(signals, key, cid, &ts)
			if err != nil {
				t.Fatal(err)
			}
			obj, err := Decrypt(jspl, key, cid, ts)
			if err != nil {
				t.Errorf("key=%q case %d n=%d rem=%d: %v", key, i, len(signals), len(jspl)%4, err)
				continue
			}
			_ = obj
		}
	}
}

func TestWCodecIdentity(t *testing.T) {
	for n := 0; n < 64; n++ {
		enc := wEncode(n)
		got := wDecode(enc)
		if got != n {
			t.Fatalf("n=%d encoded=%d (%q) decoded=%d", n, enc, string([]byte{enc}), got)
		}
	}
}

func TestPackUnpackIdentity(t *testing.T) {
	aIV0 := int32(1901646009)
	for v0 := 0; v0 < 256; v0 += 17 {
		for v1 := 0; v1 < 256; v1 += 19 {
			for v2 := 0; v2 < 256; v2 += 23 {
				aIV := aIV0
				aIV = toInt32(int64(aIV) - 1)
				e0 := (255 & int(aIV)) ^ v0
				aIV = toInt32(int64(aIV) - 1)
				e1 := (255 & int(aIV)) ^ v1
				aIV = toInt32(int64(aIV) - 1)
				e2 := (255 & int(aIV)) ^ v2
				u := (e0 << 16) | (e1 << 8) | e2
				chars := []byte{
					wEncode((u >> 18) & 63),
					wEncode((u >> 12) & 63),
					wEncode((u >> 6) & 63),
					wEncode(u & 63),
				}
				aIV = aIV0
				combined := (wDecode(chars[0]) << 18) | (wDecode(chars[1]) << 12) | (wDecode(chars[2]) << 6) | wDecode(chars[3])
				aIV = toInt32(int64(aIV) - 1)
				g0 := (combined >> 16 & 255) ^ (255 & int(aIV))
				aIV = toInt32(int64(aIV) - 1)
				g1 := (combined >> 8 & 255) ^ (255 & int(aIV))
				aIV = toInt32(int64(aIV) - 1)
				g2 := (combined & 255) ^ (255 & int(aIV))
				if g0 != v0 || g1 != v1 || g2 != v2 {
					t.Fatalf("v=(%d,%d,%d) got=(%d,%d,%d) u=%d chars=%q", v0, v1, v2, g0, g1, g2, u, chars)
				}
			}
		}
	}
}
