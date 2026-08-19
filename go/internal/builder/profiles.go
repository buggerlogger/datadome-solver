package builder

type Profile map[string]any

var chromeWin10 = Profile{
	"ua":     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
	"pf":     "Win32",
	"hc":     8,
	"dvm":    8,
	"mob":    false,
	"ts_mtp": 0,
	"wbd":    false,
	"lg":     "en-US",
	"lgs":    `["en-US","en"]`,
	"vnd":    "Google Inc.",
	"bid":    "NA",
	"glvd":   "Google Inc. (NVIDIA)",
	"glrd":   "ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 (0x00002484) Direct3D11 vs_5_0 ps_5_0, D3D11)",
	"rs_w":   1920,
	"rs_h":   1080,
	"rs_cd":  24,
	"ars_w":  1920,
	"ars_h":  1040,
	"br_oh":  1040,
	"br_ow":  1920,
	"br_w":   1920,
	"br_h":   929,
	"br_ih":  929,
	"pr":     1,
	"cg_w":   1920,
	"cg_h":   0,
	"sg_w":   0,
	"sg_h":   48,
	"so":     "landscape-primary",
	"plu":    "PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF",
	"plg":    5,
	"plgne":  true,
	"plgre":  true,
	"plgof":  false,
	"plggt":  false,
	"plgod":  false,
	"mmt":    "application/pdf,text/pdf",
	"med":    "defined",
	"tz":     -60,
	"tzp":    "Europe/Berlin",
	"ftsa":   `caption:Arial,icon:Arial,menu:"Segoe UI",message-box:Arial,small-caption:"Segoe UI",status-bar:"Segoe UI"`,
	"m_scw":  1920,
	"m_sch":  1080,
	"cpup":   -1,
	"k_lyts": 48,
	"k_lytk": "qwertyuiopasdfghjklzxcvbnm1234567890-=[];'#,./\\` ",
	"nhi":    "x86,64,false,,Windows,19.0.0,151.0.7922.138,false",
	"eva":    40,
	"cokys":  ",loadTimes,csi,app,runtime",
	"stqe":   int64(10737418240),
	"stqu":   0,
	"cssS":   "4.93,13.26,9.01,0.22,4.57,2.12,14.38,6.39,7.07",
	"css0":   "33, 4, 4",
	"css1":   "0.218751, 0.0134708, -0.0191417, 0.00133113, -0.160945, 4.09828, 1.04485, -0.0726597, 0.28419, -1.99897, 1.84097, -0.128023, 4.08665, -28.7452, 26.4731, -0.840966",
	"niet":   "4g",
	"nid":    10,
	"nisd":   false,
	"nt_nhp": "h2",
}

var chromeWin10DE = func() Profile {
	p := copyProfile(chromeWin10)
	p["lg"] = "de-DE"
	p["lgs"] = `["de-DE","de","en-US","en"]`
	p["tz"] = -120
	p["glrd"] = "ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 (0x00001B80) Direct3D11 vs_5_0 ps_5_0, D3D11)"
	p["dvm"] = 32
	p["rs_w"], p["rs_h"], p["rs_cd"] = 2560, 1440, 32
	p["m_scw"], p["m_sch"] = 2560, 1440
	p["ars_w"], p["ars_h"] = 2560, 1392
	p["br_oh"], p["br_ow"] = 1392, 2560
	p["cg_w"], p["cg_h"] = 1711, 87
	p["br_w"], p["br_h"], p["br_ih"] = 849, 1305, 1305
	return p
}()

var Profiles = map[string]Profile{
	"chrome_win10":    chromeWin10,
	"chrome_win10_de": chromeWin10DE,
}

func copyProfile(src Profile) Profile {
	dst := make(Profile, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func getProfile(name string) Profile {
	if p, ok := Profiles[name]; ok {
		return copyProfile(p)
	}
	return copyProfile(chromeWin10)
}
