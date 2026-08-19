# Changelog

Full history of the solver against live `tags.js` contracts: **v5.7.0 → v5.9.0 → v5.9.2**.

---

## v5.9.2

Aligned to live `tags.js` **5.9.2**. Codec seeds are unchanged from 5.9.0 (`seedO=1789537805`, `seedE=9959949970`, `encryptSeed=1809053797`, `ivXorConst=11027890091`, `defaultV=741130091`). `ddv` is a version label. Decrypt secrets are `cid` + `ddk`.

### Fingerprint

- Chrome **151** reduced UA, `nhi` full version `151.0.7922.138`, platform version `19.0.0`
- Client Hints GREASE/order for major 151: `"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"`
- Wire `User-Agent`, sensor `ua`, and `nhi` match

### New / required 5.9.2 signals

| key | role |
|-----|------|
| `ftsa` | CSS font sources |
| `tzp` | IANA time zone |
| `muev` | media/user-agent feature flag |
| `wglo` | WebGPU / related feature flag |
| `addt` | feature flag |
| `vpbq` | feature flag |
| `wdifrm` | iframe worker detection |
| `m_scw` / `m_sch` | screen metrics |
| `cpup` | `navigator.hardwareConcurrency` probe (`-1` when hidden) |
| `br_iw` | inner width (with `br_ih`) |
| `csssp` | CSS sample pad |
| `wwl` | webdriver/worker leak flag |

`eventCounters` stays on the 5.9.0 behavioral object (`m_s_c`, `m_m_c`, `m_c_c`, `m_cm_r`, `m_ms_r`, `m_fmi`, `es_*`, `p_*`).

### Codec

- `Encrypt` / `Decrypt` roundtrip, including `jspl` length `% 4` in `{0, 2, 3}`
- Remainder groups decode without slicing prior 4-char blocks
- Custom alphabet: `_` (sextet `1`) is decoded before `A–Z`, so it is not read as 42
- Decrypt takes `cid` + `ddk` (+ timestamp for `f`). No `Date.now()` brute-force

### Verified

Bounty origin `https://bounty-nodejs.datashield.co` (`ddk=E8518C242C1949A9B37C3394607069`):

- bogus cookie `GET /scraping` → 403 challenge
- solved cookie `GET /` → 200 clean
- solved cookie `GET /scraping` → 200 clean

---

## v5.9.0

Aligned to live `tags.js` **5.9.0** (bump from 5.8.0). Cipher seeds identical to 5.8.0 / 5.7.0. The payload contract changed.

### eventCounters

Replaced the flat `{ "mousemove": N, ... }` object with:

- mouse counts / ratios: `m_s_c`, `m_m_c`, `m_c_c`, `m_cm_r`, `m_ms_r`, `m_fmi`
- mouse-stroke medians: `es_sigmdn`, `es_mumdn`, `es_distmdn`, `es_angsmdn`, `es_angemdn`
- pointer coalesced / predicted stats: `p_fc`, `m_clsdcnt`, `p_cf`, `p_cmx`, `p_ps`, `p_pf`
- session flags: `jset`, `nddc`, `exp8`, `nowd` (must be false), `sfex`

A solve without plausible interaction stats reads as "no human input".

### Stack

- Chrome 149-class fingerprint + uTLS (`HelloChrome_Auto`) + HTTP/2
- Local HTTP API (`POST /solve`) and CLI (`-solve`, `-verify`, `-two-phase`, `-scrape`, `-fetch`)
- Proxy: `ip:port:user:pass`, `host:port`, `user:pass@host:port`, `http(s)://`, `socks5://`
- Captcha delivery helper over the same Chrome transport
- Signal checksums `sgb` / `sgd` / `sgc`, `bpc`, `jset`

---

## v5.7.0

First production Go solver line (CLI + library). No browser, no Node at runtime.

- Ordered fingerprint builder (`chrome_win10`, `chrome_win10_de`) ~190 signals
- `jspl` encrypt: xorshift PRNG, `cid`/`ddk` keyed streams, custom 64-char alphabet
- POST to DataDome `api-js` / origin `tags.js` with `ddk`, `cid`, `ddv`, `jsType`
- Public SDK: `datadome.New` → `Solve` / `BuildPayload` / `EncryptJSPL`
- Profiles for UA, WebGL, screen, plugins, codecs, bot-check flags

This is the baseline 5.9.0 and 5.9.2 still encrypt with. Later versions add signals and HTTP transport; they do not replace the cipher.
