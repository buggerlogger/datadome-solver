package crypto

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

const (
	seedO       = 1789537805
	seedE       = 9959949970
	encryptSeed = 1809053797
	ivXorConst  = 11027890091
	defaultV    = 741130091
)

type Signal struct {
	Key   string
	Value any
}

func Encrypt(signals []Signal, ddjskey, cid string, timestampMs *int64) (string, error) {
	var ts int64
	if timestampMs != nil {
		ts = *timestampMs
	} else {
		ts = time.Now().UnixMilli()
	}

	nKey := toInt32(int64(toInt32(int64(seedE))) ^ int64(hashL(ddjskey)) ^ int64(defaultV))
	tsShifted := toInt32(int64(toInt32(ts>>3)) ^ int64(ivXorConst))
	inner := xorshift32(tsShifted)
	product := float64(inner) * float64(seedE)
	f := xorshift32(float64ToInt32(product))

	sPrng := newPRNGStream(nKey, f, true)
	var d []int
	first := true

	for _, sig := range signals {
		if sig.Key == "" {
			continue
		}
		if sig.Value != nil {
			switch sig.Value.(type) {
			case int, int32, int64, float32, float64, string, bool:
			default:
				continue
			}
		}

		keyJSON, err := json.Marshal(sig.Key)
		if err != nil {
			return "", err
		}
		valJSON, err := json.Marshal(sig.Value)
		if err != nil {
			return "", err
		}

		separator := 123
		if !first {
			separator = 44
		}
		d = append(d, sPrng.next(false)^separator)

		for _, b := range keyJSON {
			d = append(d, int(b)^sPrng.next(false))
		}
		d = append(d, 58^sPrng.next(false))
		for _, b := range valJSON {
			d = append(d, int(b)^sPrng.next(false))
		}
		first = false
	}

	tPrng := newPRNGStream(toInt32(int64(encryptSeed^int64(hashL(cid)))), f, false)

	c := make([]int, len(d))
	for i, b := range d {
		c[i] = b ^ tPrng.next(false)
	}
	c = append(c, 125^sPrng.next(true)^tPrng.next(false))

	aIV := toInt32(int64(f))
	var output []byte
	rPos := 0
	for rPos < len(c) {
		b0, b1, b2 := 0, 0, 0
		if rPos < len(c) {
			b0 = c[rPos]
		}
		if rPos+1 < len(c) {
			b1 = c[rPos+1]
		}
		if rPos+2 < len(c) {
			b2 = c[rPos+2]
		}

		aIV = toInt32(int64(aIV) - 1)
		v0 := (255 & int(aIV)) ^ b0
		aIV = toInt32(int64(aIV) - 1)
		v1 := (255 & int(aIV)) ^ b1
		aIV = toInt32(int64(aIV) - 1)
		v2 := (255 & int(aIV)) ^ b2

		uCombined := (v0 << 16) | (v1 << 8) | v2
		output = append(output, wEncode((uCombined>>18)&63))
		output = append(output, wEncode((uCombined>>12)&63))
		output = append(output, wEncode((uCombined>>6)&63))
		output = append(output, wEncode(uCombined&63))
		rPos += 3
	}

	remainder := len(c) % 3
	if remainder != 0 {
		output = output[:len(output)-(3-remainder)]
	}
	return string(output), nil
}

func computeF(ts int64) int32 {
	tsShifted := toInt32(int64(toInt32(ts>>3)) ^ int64(ivXorConst))
	inner := xorshift32(tsShifted)
	product := float64(inner) * float64(seedE)
	return xorshift32(float64ToInt32(product))
}

func wDecode(c byte) int {
	switch {
	case c == 95:
		return 1
	case c >= 96:
		return int(c) - 59
	case c >= 65:
		return int(c) - 53
	case c >= 48:
		return int(c) - 46
	default:
		return 0
	}
}

func firstByteIsObject(jspl []byte, nKey, tKey, f int32) bool {
	if len(jspl) < 4 {
		return false
	}
	aIV := toInt32(int64(f))
	combined := (wDecode(jspl[0]) << 18) | (wDecode(jspl[1]) << 12) | (wDecode(jspl[2]) << 6) | wDecode(jspl[3])
	aIV = toInt32(int64(aIV) - 1)
	c0 := (combined >> 16 & 255) ^ (255 & int(aIV))
	d0 := c0 ^ (255 & int(toInt32(int64(tKey)>>16)))
	sI := toInt32(int64(f) - 1)
	plain0 := d0 ^ (255 & int(toInt32(int64(nKey)>>16)^sI))
	return plain0 == 123
}

func Decrypt(jspl, ddjskey, cid string, timestampMs int64) (map[string]any, error) {
	nKey := toInt32(int64(toInt32(int64(seedE))) ^ int64(hashL(ddjskey)) ^ int64(defaultV))
	tKey := toInt32(int64(encryptSeed) ^ int64(hashL(cid)))
	f := computeF(timestampMs)
	raw := []byte(jspl)

	aIV := toInt32(int64(f))
	c := make([]int, 0, len(raw))
	pos := 0
	for pos+3 < len(raw) {
		combined := (wDecode(raw[pos]) << 18) | (wDecode(raw[pos+1]) << 12) | (wDecode(raw[pos+2]) << 6) | wDecode(raw[pos+3])
		aIV = toInt32(int64(aIV) - 1)
		c = append(c, (combined>>16&255)^(255&int(aIV)))
		aIV = toInt32(int64(aIV) - 1)
		c = append(c, (combined>>8&255)^(255&int(aIV)))
		aIV = toInt32(int64(aIV) - 1)
		c = append(c, (combined&255)^(255&int(aIV)))
		pos += 4
	}
	rem := len(raw) - pos
	if rem >= 2 {
		v0, v1, v2 := wDecode(raw[pos]), wDecode(raw[pos+1]), 0
		if rem >= 3 {
			v2 = wDecode(raw[pos+2])
		}
		combined := (v0 << 18) | (v1 << 12) | (v2 << 6)
		aIV = toInt32(int64(aIV) - 1)
		c = append(c, (combined>>16&255)^(255&int(aIV)))
		if rem >= 3 {
			aIV = toInt32(int64(aIV) - 1)
			c = append(c, (combined>>8&255)^(255&int(aIV)))
		}
	}
	if len(c) == 0 {
		return nil, ErrDecrypt
	}
	c = c[:len(c)-1]

	tPrng := newPRNGStream(tKey, f, false)
	d := make([]int, len(c))
	for i, b := range c {
		d[i] = b ^ tPrng.next(false)
	}
	sPrng := newPRNGStream(nKey, f, true)
	chars := make([]byte, len(d)+1)
	for i, b := range d {
		chars[i] = byte(b ^ sPrng.next(false))
	}
	chars[len(d)] = '}'
	var obj map[string]any
	if err := json.Unmarshal(chars, &obj); err != nil {
		head := chars
		if len(head) > 96 {
			head = head[:96]
		}
		return nil, fmt.Errorf("%w: %q", err, head)
	}
	return obj, nil
}

var ErrDecrypt = errors.New("datadome: jspl decrypt failed")

func DecryptBrute(jspl, ddjskey, cid string, nowMs, windowMs int64) (map[string]any, int64, error) {
	nKey := toInt32(int64(toInt32(int64(seedE))) ^ int64(hashL(ddjskey)) ^ int64(defaultV))
	tKey := toInt32(int64(encryptSeed) ^ int64(hashL(cid)))
	raw := []byte(jspl)
	for off := int64(0); off < windowMs; off += 8 {
		ts := nowMs - off
		f := computeF(ts)
		if !firstByteIsObject(raw, nKey, tKey, f) {
			continue
		}
		for fine := int64(0); fine < 8; fine++ {
			exact := ts - fine
			obj, err := Decrypt(jspl, ddjskey, cid, exact)
			if err == nil && obj != nil {
				return obj, exact, nil
			}
		}
	}
	return nil, 0, ErrDecrypt
}

func toInt32(n int64) int32 {
	n &= 0xFFFFFFFF
	if n >= 0x80000000 {
		return int32(n - 0x100000000)
	}
	return int32(n)
}

func xorshift32(n int32) int32 {
	n = toInt32(int64(n))
	n = toInt32(int64(n) ^ int64(toInt32(int64(n)<<13)))
	n = toInt32(int64(n) ^ int64(int64(n)>>17))
	n = toInt32(int64(n) ^ int64(toInt32(int64(n)<<5)))
	return n
}

func hashL(s string) int32 {
	if s == "" {
		return seedO
	}
	var t int32
	for _, ch := range s {
		t = toInt32(int64(toInt32(int64(t)<<5)) - int64(t) + int64(ch))
	}
	if t == 0 {
		return seedO
	}
	return t
}

func float64ToInt32(f float64) int32 {
	if math.IsNaN(f) || math.IsInf(f, 0) || f == 0 {
		return 0
	}
	n := int64(f) & 0xFFFFFFFF
	return toInt32(n)
}

func wEncode(n int) byte {
	switch {
	case n > 37:
		return byte(59 + n)
	case n > 11:
		return byte(53 + n)
	case n > 1:
		return byte(46 + n)
	default:
		return byte(50*n + 45)
	}
}

type prngStream struct {
	c      int32
	e      int
	i      int32
	r      bool
	cached *int
}

func newPRNGStream(seed, iv int32, xorWithIV bool) *prngStream {
	return &prngStream{c: toInt32(int64(seed)), e: -1, i: toInt32(int64(iv)), r: xorWithIV}
}

func (p *prngStream) next(peek bool) int {
	if p.cached != nil {
		t := *p.cached
		p.cached = nil
		return t
	}
	p.e++
	if p.e > 2 {
		p.c = xorshift32(p.c)
		p.e = 0
	}
	shift := 16 - 8*p.e
	var raw int32
	if shift >= 0 {
		raw = toInt32(int64(p.c) >> shift)
	} else {
		raw = toInt32(int64(p.c) << -shift)
	}
	ivVal := int32(0)
	if p.r {
		p.i = toInt32(int64(p.i) - 1)
		ivVal = p.i
	}
	t := 255 & int(raw^ivVal)
	if peek {
		p.cached = &t
	}
	return t
}
