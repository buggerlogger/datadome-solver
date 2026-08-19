package builder

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
)

func djb2Hash(s string) int64 {
	var t int64
	for _, ch := range s {
		t = ((t << 5) - t + int64(ch)) & 0xFFFFFFFF
		if t >= 0x80000000 {
			t -= 0x100000000
		}
	}
	return t + 2147483648
}

var bchkAPIs = []string{
	"AppBannerPromptResult", "webkitRTCPeerConnection", "webkitAudioContext",
	"webkitRequestAnimationFrame", "chrome.runtime", "chrome.webstore",
	"console.context", "InputMethodContext", "SVGAnimationElement",
	"SVGPathSegList", "PasswordCredential", "ViewTransition",
	"VisualViewport.prototype.segments", "DeprecationReportBody",
	"MathMLElement", "opr", "CSS2Properties.prototype.colorScheme",
	"WebKitCSSMatrix", "SVGTextPositioningElement",
	"XMLHttpRequestEventTarget", "TextDecoderStream", "onloadend",
	"WritableStream", "TransformStream", "TextTrackCue", "WeakRef",
	"VisualViewport", "StyleSheet", "RTCDtlsTransport", "Atomics",
	"StaticRange", "UIEvent", "VideoStreamTrack", "OfflineResourceList",
	"SVGGeometryElement", "RTCDataChannel", "VTTRegion", "AbortController",
	"Controllers", "onanimationcancel", "SVGDocument", "IIRFilterNode",
	"RTCStatsReport", "MediaStreamTrack",
	"CSS2Properties.prototype.MozOsxFontSmoothing", "CropTarget",
	"BatteryManager", "LaunchQueue", "CSSFontPaletteValuesRule",
	"PushSubscriptionOptions", "DOMSettableTokenList", "RTCTrackEvent",
	"MozSmsMessage", "ServiceWorkerContainer",
	"CanvasCaptureMediaStream", "DeviceStorage", "XPathNSResolver",
	"SmartCardEvent", "WeakSet", "MozMobileMessageManager",
	"External.prototype.getHostEnvironmentValue", "WindowUtils",
	"XPathNamespace", "SVGFEDropShadowElement", "SharedWorker",
	"WorkerMessageEvent", "CSS2Properties.prototype.MozOSXFontSmoothing",
	"AudioSinkInfo", "Notification.prototype.image",
	"ContentVisibilityAutoStateChangeEvent",
	"PerformanceResourceTiming.prototype.renderBlockingStatus",
	"console.createTask", "PerformanceServerTiming", "CanvasFilter",
	"structuredClone", "onslotchange", "EyeDropper", "URLPattern",
	"VideoFrame", "WritableStreamDefaultController", "SharedArrayBuffer",
	"CSSCounterStyleRule", "CustomStateSet",
	"ReadableStreamDefaultController",
	"XMLDocument.prototype.hasStorageAccess", "CryptoKey", "SubmitEvent",
	"MediaMetadata", "VideoPlaybackQuality",
	"ReadableStreamDefaultReader", "UserActivation", "FragmentDirective",
	"WebKitMediaKeyError", "RTCRtpTransceiver.prototype.stop",
	"Scheduling", "EventCounts", "VideoTrackList", "SourceBuffer",
	"RTCError", "FontFaceSet", "CSSCharsetRule", "MediaDeviceInfo",
	"RTCPeerConnectionIceErrorEvent", "RTCSctpTransport",
	"MediaSessionCoordinator", "XULPopupElement", "MediaSourceHandle",
	"RTCEncodedAudioFrame", "__REACT_DEVTOOLS_GLOBAL_HOOK__",
	"ShadowRealm", "HTMLSlotElement", "DetachedViewControlEvent",
	"GeolocationPosition", "SiteBoundCredential", "MediaSource",
	"WebTransport", "GPUSupportedLimits", "ToggleEvent",
}

const (
	bchkFound  = "52738db37a1ea50137e79e8181193ac872cd325ba5cacfbe7aab5b36b9c9879e7c0018dbd31a1832a8dc6528387b67451719dcd8b784a518904e3f07c69b9d30"
	bchkAbsent = "3829ae9642df0d791e41d2159da28bd18d056afadf1bd70fc9222a473eaf58e860ff950e7bf35b66e4aa90b156c80c96913dbd9c23c7262e4adbc3ddd77ff263"
)

var chromeAPIsPresent = map[string]struct{}{
	"webkitRTCPeerConnection": {}, "webkitRequestAnimationFrame": {}, "chrome.runtime": {},
	"console.context": {}, "SVGAnimationElement": {}, "PasswordCredential": {},
	"ViewTransition": {}, "MathMLElement": {}, "WebKitCSSMatrix": {},
	"SVGTextPositioningElement": {}, "XMLHttpRequestEventTarget": {}, "TextDecoderStream": {},
	"WritableStream": {}, "TransformStream": {}, "TextTrackCue": {}, "WeakRef": {},
	"VisualViewport": {}, "StyleSheet": {}, "RTCDtlsTransport": {}, "Atomics": {},
	"StaticRange": {}, "UIEvent": {}, "SVGGeometryElement": {}, "RTCDataChannel": {},
	"AbortController": {}, "onanimationcancel": {}, "IIRFilterNode": {}, "RTCStatsReport": {},
	"MediaStreamTrack": {}, "CropTarget": {}, "BatteryManager": {}, "LaunchQueue": {},
	"CSSFontPaletteValuesRule": {}, "PushSubscriptionOptions": {}, "RTCTrackEvent": {},
	"ServiceWorkerContainer": {}, "WeakSet": {}, "SVGFEDropShadowElement": {}, "SharedWorker": {},
	"AudioSinkInfo": {}, "Notification.prototype.image": {},
	"ContentVisibilityAutoStateChangeEvent":                    {},
	"PerformanceResourceTiming.prototype.renderBlockingStatus": {},
	"console.createTask":                                       {}, "PerformanceServerTiming": {}, "structuredClone": {},
	"onslotchange": {}, "EyeDropper": {}, "URLPattern": {}, "VideoFrame": {},
	"WritableStreamDefaultController": {}, "CSSCounterStyleRule": {}, "CustomStateSet": {},
	"ReadableStreamDefaultController":        {},
	"XMLDocument.prototype.hasStorageAccess": {}, "CryptoKey": {}, "SubmitEvent": {},
	"MediaMetadata": {}, "VideoPlaybackQuality": {}, "ReadableStreamDefaultReader": {},
	"UserActivation": {}, "FragmentDirective": {}, "RTCRtpTransceiver.prototype.stop": {},
	"Scheduling": {}, "EventCounts": {}, "SourceBuffer": {}, "RTCError": {},
	"MediaDeviceInfo": {}, "RTCPeerConnectionIceErrorEvent": {}, "RTCSctpTransport": {},
	"MediaSourceHandle": {}, "RTCEncodedAudioFrame": {}, "HTMLSlotElement": {},
	"GeolocationPosition": {}, "MediaSource": {}, "WebTransport": {},
	"GPUSupportedLimits": {}, "ToggleEvent": {},
	"WebGLObject": {}, "WebSocketStream": {}, "SVGDiscardElement": {},
}

var chromeVideoCodecs = map[string]any{
	"vco": "", "vcots": false, "vch": "probably", "vchts": true,
	"vcw": "probably", "vcwts": true, "vc3": "maybe", "vc3ts": false,
	"vcmp": "", "vcmpts": false, "vc1": "probably", "vc1ts": true,
	"vcmk": "maybe", "vcmkuts": false, "vcq": "", "vcqts": false,
}

var chromeAudioCodecs = map[string]any{
	"aco": "probably", "acots": false, "acmp": "probably", "acmpts": true,
	"acmpu": "maybe", "acmputs": false, "acw": "probably", "acwts": false,
	"acma": "maybe", "acmats": false, "acaa": "probably", "acaats": true,
	"ac3": "", "ac3ts": false, "acf": "probably", "acfts": false,
	"acmp4": "maybe", "acmp4ts": false, "acmp3": "probably", "acmp3ts": false,
	"acwm": "maybe", "acwmts": false,
}

var chromeFeatures = map[string]bool{
	"pro_t": true, "prso": true, "wbst": true, "psn": true,
	"edp": true, "wsdc": true, "ccsr": true, "nuad": true,
	"bcda": false, "idn": true, "capi": false, "svde": false,
	"wglo": true, "addt": true, "vpbq": true, "muev": false, "wdifrm": false,
}

var chromeBotChecks = map[string]bool{
	"awe": false, "phe": false, "dat": false, "nm": false,
	"geb": false, "sqt": false, "spwn": false, "emt": false,
}

func generateNavTiming() map[string]any {
	dns := roundRand(0, 3, 1)
	tcp := roundRand(0, 5, 1)
	tls := roundRand(3, 15, 6)
	requestStart := roundRand(0, 5, 6)
	responseTime := roundRand(80, 600, 6)
	responseEnd := responseTime + roundRand(5, 150, 6)
	swTime := roundRand(0, 5, 6)

	encodedSize := 200000
	decodedSize := encodedSize + rand.Intn(250001) + 50000
	compressionDiff := decodedSize - encodedSize

	domInteractive := roundRand(500, 2000, 6)
	loadEventDuration := roundRand(0, 2, 1)
	domCompleteOffset := roundRand(0, 100, 1)

	connectEnd := tcp + tls
	secureDiff := connectEnd - tcp
	var ntEsc any
	if secureDiff > 0 {
		ntEsc = roundRand(0, 2, 6)
	} else {
		ntEsc = 0.0
	}
	var ntTtrd any
	if secureDiff > 0 {
		ntTtrd = roundFloat((tcp-secureDiff)/secureDiff, 6)
	} else {
		ntTtrd = 0.0
	}

	return map[string]any{
		"nt_tcp": roundFloat(tcp, 1), "nt_dns": roundFloat(dns, 1),
		"nt_rd":  0,
		"nt_irt": roundFloat(-(dns + connectEnd + requestStart), 6),
		"nt_rt":  roundFloat(responseTime, 6), "nt_tls": roundFloat(tls, 6),
		"nt_ttf": roundFloat(responseEnd, 6),
		"nt_swt": roundFloat(swTime, 6), "nt_csd": compressionDiff,
		"nt_nhp": "h2", "nt_rdc": 0, "nt_it": "navigation",
		"nt_prs": roundFloat(requestStart, 6), "nt_esc": ntEsc,
		"nt_ttrd": ntTtrd,
		"nt_le":   roundFloat(loadEventDuration, 1),
		"nt_dcle": roundRand(0, 2, 6),
		"nt_di":   roundFloat(domInteractive, 6),
		"nt_dc":   roundFloat(domCompleteOffset, 1),
	}
}

func generateTrrd() float64 {
	sqrt2 := math.Sqrt(2)
	r1, r2, r3, r4 := rand.Float64(), rand.Float64(), rand.Float64(), rand.Float64()

	e := math.Sqrt(math.Abs(
		math.Sin(math.Pi/90*100-40*r1*(math.Pi/180)/2) +
			math.Cos(100*sqrt2*(math.Pi/180))*
				math.Sin(math.Pi/180*40-100*r2*(math.Pi/75)/2),
	))

	cVal := r3 * math.Sqrt(math.Abs(
		1-math.Sin(40*r4*(math.Pi/90)-100*sqrt2*(math.Pi/180)/2)+
			math.Cos(3.7055555555555557)*rand.Float64()*
				math.Sin(math.Pi/180*60-math.Pi/45*100/2),
	))
	return math.Atan2(e, cVal)
}

func generateBchk() string {
	result := make([]byte, 0, len(bchkAPIs))
	for i, api := range bchkAPIs {
		if _, ok := chromeAPIsPresent[api]; ok {
			result = append(result, bchkFound[i%len(bchkFound)])
		} else {
			result = append(result, bchkAbsent[i%len(bchkAbsent)])
		}
	}
	return string(result)
}

func generateErrorStacks(tagsURL string) map[string]any {
	line := 2
	colT := rand.Intn(2001) + 99000
	colB1 := rand.Intn(2001) + 77000
	colB2 := rand.Intn(2001) + 98000
	colB3 := rand.Intn(2001) + 105000

	fullStack := fmt.Sprintf(
		"Error\nat y1 (%s:%d:%d)\nat %s:%d:%d\nat %s:%d:%d\nat %s:%d:%d",
		tagsURL, line, colT,
		tagsURL, line, colB1,
		tagsURL, line, colB2,
		tagsURL, line, colB3,
	)
	ccsT := fullStack
	if len(ccsT) > 150 {
		ccsT = ccsT[:150]
	}
	ccsB := fullStack
	if len(ccsB) > 150 {
		ccsB = ccsB[len(ccsB)-150:]
	}
	sum := sha256.Sum256([]byte(fullStack))
	return map[string]any{
		"ccsT": ccsT, "ccsB": ccsB,
		"ccsH": djb2Hash(fullStack),
		"ccsV": hex.EncodeToString(sum[:]),
	}
}

func computeFph(prof Profile) int64 {
	parts := []string{
		str(prof["glrd"]), str(prof["glvd"]), str(prof["ua"]),
		str(prof["hc"]), str(prof["lgs"]), str(prof["ts_mtp"]),
		str(prof["pf"]), str(prof["br_oh"]), str(prof["br_ow"]),
		"", "", "", "", str(prof["dvm"]),
	}
	joined := ""
	for _, p := range parts {
		joined += p
	}
	return djb2Hash(joined)
}

func computeSignalChecksums(payload map[string]any) map[string]string {
	var L, P, j int64
	T := func(val any) {
		h := djb2Hash(str(val))
		L ^= h
		j ^= h
	}
	S := func(val any) {
		h := djb2Hash(str(val))
		P ^= h
		j ^= h
	}
	m := func(val any) {
		h := djb2Hash(str(val))
		j ^= h
	}

	T(payload["lgs"])
	S(payload["pf"])
	S(fmt.Sprintf("%va", payload["ts_mtp"]))
	m(fmt.Sprintf("%vbb", payload["mob"]))
	m(fmt.Sprintf("%vccc", payload["hc"]))
	m(fmt.Sprintf("%vdddd", payload["dvm"]))
	S(payload["tz"])
	T(payload["eva"])
	T(payload["wdifpnh"])

	return map[string]string{
		"sgb": fmt.Sprintf("%d", uint32(L)),
		"sgd": fmt.Sprintf("%d", uint32(P)),
		"sgc": fmt.Sprintf("%d", uint32(j)),
	}
}

func generateR3n(serverHash *string) any {
	if serverHash != nil && len(*serverHash) >= 4 {
		suffix := (*serverHash)[len(*serverHash)-4:]
		randHex := fmt.Sprintf("%08X", rand.Uint32())
		pos := rand.Intn(9)
		return randHex[:pos] + suffix + randHex[pos:]
	}
	return 33
}

func generateWdifpnh() string {
	return fmt.Sprintf("%d", rand.Intn(3294967296-1000000000)+1000000000)
}

func roundRand(min, max float64, prec int) float64 {
	v := min + rand.Float64()*(max-min)
	return roundFloat(v, prec)
}

func roundFloat(v float64, prec int) float64 {
	p := math.Pow(10, float64(prec))
	return math.Round(v*p) / p
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func intVal(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}
