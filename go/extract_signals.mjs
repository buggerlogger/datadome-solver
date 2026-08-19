// Extract all signal keys from tags.js by running it in a VM with mocked browser globals
// and hooking the signal collector's .t() method
import { readFileSync } from 'fs';
import vm from 'vm';

const src = readFileSync('./tags_590.js', 'utf8');

const signals = [];
const signalCollector = {
  _signals: {},
  t(key, value) {
    signals.push({ key, value, type: typeof value });
    this._signals[key] = value;
  },
  i() {},
  s() { return this._signals; }
};

// Minimal browser mock
const mockWindow = {
  dataDomeOptions: {
    ddCookieSessionName: 'datadome',
    sessionByHeader: false,
    patternToRemoveFromReferrerUrl: null,
    ddResponsePage: 'origin',
    enableTagEvents: false,
    withCredentials: false,
    replayAfterChallenge: false,
    overrideAbortFetch: false,
    overrideCookieDomain: null,
    challengeRoot: null,
    disableAutoRefreshOnCaptchaPassed: false,
    isSalesforce: false,
  },
  ddjskey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  DataDomeResponseDisplayed: false,
  DataDomeCaptchaDisplayed: false,
  location: { href: 'https://example.com/', hostname: 'example.com', host: 'example.com', pathname: '/', protocol: 'https:', search: '', hash: '' },
  navigator: {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36',
    platform: 'Win32',
    language: 'en-US',
    languages: ['en-US', 'en'],
    hardwareConcurrency: 8,
    deviceMemory: 8,
    maxTouchPoints: 0,
    vendor: 'Google Inc.',
    appName: 'Netscape',
    appVersion: '5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36',
    plugins: { length: 5 },
    mimeTypes: { length: 2 },
    connection: { effectiveType: '4g', downlink: 10, rtt: 0, saveData: false },
    webdriver: false,
    sendBeacon: function() { return true; },
    mediaDevices: { enumerateDevices: async () => [] },
    getBattery: async () => ({ charging: true, chargingTime: 0, dischargingTime: Infinity, level: 1 }),
    keyboard: { getLayoutMap: async () => new Map() },
    locks: { request: async () => {} },
    storage: { estimate: async () => ({ quota: 10737418240, usage: 0 }) },
    permissions: { query: async () => ({ state: 'prompt' }) },
    credentials: { get: async () => null },
    scheduling: { isInputPending: () => false },
    userAgentData: {
      brands: [{ brand: 'Google Chrome', version: '149' }, { brand: 'Chromium', version: '149' }, { brand: 'Not)A;Brand', version: '24' }],
      mobile: false,
      platform: 'Windows',
      getHighEntropyValues: async () => ({
        architecture: 'x86',
        bitness: '64',
        fullVersionList: [{ brand: 'Google Chrome', version: '149.0.7827.53' }],
        mobile: false,
        model: '',
        platform: 'Windows',
        platformVersion: '14.0.0',
        uaFullVersion: '149.0.7827.53'
      })
    }
  },
  document: {
    cookie: '',
    hidden: false,
    visibilityState: 'visible',
    readyState: 'complete',
    title: 'Test',
    referrer: '',
    domain: 'example.com',
    URL: 'https://example.com/',
    documentElement: {
      addEventListener: () => {},
      removeEventListener: () => {},
      style: {},
      clientWidth: 1920,
      clientHeight: 929,
    },
    body: {
      style: {},
      clientWidth: 1920,
      clientHeight: 929,
      scrollWidth: 1920,
      scrollHeight: 929,
      appendChild: () => {},
      removeChild: () => {},
      children: [],
    },
    head: { appendChild: () => {}, removeChild: () => {} },
    createElement: (tag) => ({
      tagName: tag.toUpperCase(),
      style: {},
      setAttribute: () => {},
      getAttribute: () => null,
      appendChild: () => {},
      removeChild: () => {},
      addEventListener: () => {},
      getContext: () => null,
      toDataURL: () => 'data:',
      width: 0, height: 0,
      children: [],
      querySelectorAll: () => [],
      querySelector: () => null,
    }),
    getElementById: () => null,
    querySelector: () => null,
    querySelectorAll: () => [],
    getElementsByTagName: () => [],
    getElementsByClassName: () => [],
    createEvent: () => ({ initEvent: () => {} }),
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => {},
    createTextNode: () => ({}),
  },
  screen: { width: 1920, height: 1080, colorDepth: 24, availWidth: 1920, availHeight: 1040, orientation: { type: 'landscape-primary' } },
  innerWidth: 1920,
  innerHeight: 929,
  outerWidth: 1920,
  outerHeight: 1040,
  screenX: 0,
  screenY: 0,
  pageXOffset: 0,
  pageYOffset: 0,
  scrollX: 0,
  scrollY: 0,
  devicePixelRatio: 1,
  performance: {
    now: () => 1234.5,
    timing: {},
    getEntriesByType: () => [],
    getEntriesByName: () => [],
    memory: { jsHeapSizeLimit: 4294705152, totalJSHeapSize: 30000000, usedJSHeapSize: 20000000 },
    navigation: { type: 0, redirectCount: 0 },
  },
  PerformanceObserver: class { observe() {} disconnect() {} },
  Date: Date,
  Math: Math,
  JSON: JSON,
  Array: Array,
  Object: Object,
  String: String,
  Number: Number,
  Boolean: Boolean,
  RegExp: RegExp,
  Error: Error,
  TypeError: TypeError,
  RangeError: RangeError,
  parseInt: parseInt,
  parseFloat: parseFloat,
  isNaN: isNaN,
  isFinite: isFinite,
  encodeURIComponent: encodeURIComponent,
  decodeURIComponent: decodeURIComponent,
  encodeURI: encodeURI,
  decodeURI: decodeURI,
  setTimeout: (fn, ms) => { try { fn(); } catch(e) {} return 1; },
  clearTimeout: () => {},
  setInterval: () => 1,
  clearInterval: () => {},
  addEventListener: () => {},
  removeEventListener: () => {},
  dispatchEvent: () => {},
  fetch: async () => ({ ok: true, status: 200, json: async () => ({}), text: async () => '', headers: new Map() }),
  XMLHttpRequest: class {
    open() {} send() {} setRequestHeader() {}
    addEventListener() {} removeEventListener() {}
    get status() { return 200; }
    get responseText() { return ''; }
    getAllResponseHeaders() { return ''; }
  },
  Request: class { constructor(url) { this.url = url; } },
  Headers: class extends Map { set(k,v) { super.set(k,v); } get(k) { return super.get(k); } has(k) { return super.has(k); } },
  URL: URL,
  Blob: class { constructor() {} },
  FileReader: class { readAsText() {} },
  TextDecoder: TextDecoder,
  TextEncoder: TextEncoder,
  crypto: { getRandomValues: (arr) => { for(let i=0;i<arr.length;i++) arr[i]=Math.floor(Math.random()*256); return arr; }, subtle: {} },
  btoa: (s) => Buffer.from(s).toString('base64'),
  atob: (s) => Buffer.from(s, 'base64').toString(),
  MutationObserver: class { observe() {} disconnect() {} },
  IntersectionObserver: class { observe() {} disconnect() {} },
  ResizeObserver: class { observe() {} disconnect() {} },
  Map: Map,
  Set: Set,
  WeakMap: WeakMap,
  WeakSet: WeakSet,
  Promise: Promise,
  Proxy: Proxy,
  Reflect: Reflect,
  Symbol: Symbol,
  SharedArrayBuffer: typeof SharedArrayBuffer !== 'undefined' ? SharedArrayBuffer : class {},
  ArrayBuffer: ArrayBuffer,
  Uint8Array: Uint8Array,
  Uint16Array: Uint16Array,
  Uint32Array: Uint32Array,
  Int8Array: Int8Array,
  Int16Array: Int16Array,
  Int32Array: Int32Array,
  Float32Array: Float32Array,
  Float64Array: Float64Array,
  DataView: DataView,
  WebAssembly: { instantiate: async () => ({}) },
  console: { log: () => {}, warn: () => {}, error: () => {}, info: () => {}, debug: () => {} },
  postMessage: () => {},
  matchMedia: (q) => ({ matches: false, media: q, addListener: () => {}, removeListener: () => {}, addEventListener: () => {} }),
  getComputedStyle: () => new Proxy({}, { get: () => '' }),
  requestAnimationFrame: (cb) => { cb(16); return 1; },
  cancelAnimationFrame: () => {},
  self: null,
  top: null,
  parent: null,
  opener: null,
  chrome: { runtime: {}, loadTimes: () => ({}), csi: () => ({}), app: {}, webstore: undefined },
  Notification: class { static permission = 'default'; },
  Atomics: typeof Atomics !== 'undefined' ? Atomics : {},
  queueMicrotask: (fn) => Promise.resolve().then(fn),
  structuredClone: (v) => JSON.parse(JSON.stringify(v)),
};
mockWindow.self = mockWindow;
mockWindow.top = mockWindow;
mockWindow.parent = mockWindow;
mockWindow.window = mockWindow;
mockWindow.globalThis = mockWindow;

// We can't run the full tags.js directly - it's too complex.
// Instead let's use regex to extract all .t("key", ...) calls from the prettified source
const pretty = readFileSync('./tags_590_pretty.js', 'utf8');

// Pattern 1: e.t("key", value) or M.t("key", value) - the collector .t() calls
const tCalls = [...pretty.matchAll(/\.t\("([^"]+)"/g)];
const tKeys = [...new Set(tCalls.map(m => m[1]))].sort();

// Pattern 2: Object property assignments in the signal builder
// These look like n.key = value or n["key"] = value
const propAssign = [...pretty.matchAll(/\["([a-z][a-z0-9_]{1,10})"\]\s*=/g)];
const propKeys = [...new Set(propAssign.map(m => m[1]))].sort();

// Pattern 3: String literals that look like signal keys (2-8 chars, lowercase+underscore+digits)
const allStrings = [...pretty.matchAll(/"([a-z][a-z0-9_]{1,8})"/g)];
const allKeys = [...new Set(allStrings.map(m => m[1]))];

// Our known 5.8.0 keys from the Go builder
const known580 = [
  "log3", "r3n", "glvd", "glrd", "wwlrv", "nddc", "exp8",
  "plu", "plgod", "plg", "plgne", "plgre", "plgof", "plggt",
  "bfr", "hdn", "br_w", "br_h", "br_ih",
  "ars_w", "ars_h", "rs_w", "rs_h", "rs_cd",
  "cg_w", "cg_h", "sg_w", "sg_h", "pr", "so", "trrd",
  "ucdv", "dp0", "hcovdr", "plovdr", "ftsovdr",
  "orf", "dffls", "niet", "nid", "nisd",
  "nt_tcp", "nt_dns", "nt_rd", "nt_irt", "nt_rt", "nt_tls", "nt_ttf",
  "nt_swt", "nt_csd", "nt_nhp", "nt_rdc", "nt_it",
  "nt_prs", "nt_esc", "nt_ttrd", "nt_le", "nt_dcle", "nt_di", "nt_dc",
  "lg", "isb", "idp", "crt", "vnd", "bid", "med",
  "pltod", "npmtm", "wdif",
  "ccsT", "ccsB", "ccsH", "ccsV", "mmt", "wdifpnh",
  "vco", "vcots", "vch", "vchts", "vcw", "vcwts", "vc3", "vc3ts",
  "vcmp", "vcmpts", "vc1", "vc1ts", "vcmk", "vcmkuts", "vcq", "vcqts",
  "cssS", "css0", "css1", "cssH",
  "pro_t", "prso", "wbst", "psn", "edp", "wsdc",
  "ccsr", "nuad", "bcda", "idn", "capi", "svde",
  "bchk", "tz", "ihdn", "cdhf", "eva", "cokys", "ecpc", "wop",
  "pf", "hc", "br_oh", "br_ow", "ua", "wbd", "ts_mtp", "mob", "lgs", "dvm",
  "ckwa",
  "aco", "acots", "acmp", "acmpts", "acmpu", "acmputs", "acw", "acwts",
  "acma", "acmats", "acaa", "acaats", "ac3", "ac3ts", "acf", "acfts",
  "acmp4", "acmp4ts", "acmp3", "acmp3ts", "acwm", "acwmts",
  "acqt", "ac_NA",
  "ocpt", "sivd", "mq", "mq2",
  "awe", "phe", "dat", "nm", "geb", "sqt", "spwn", "emt",
  "nhi", "k_lyts", "k_lytk",
  "bci", "bcl", "bct", "bdt",
  "stqe", "stqu", "isf", "isf2",
  "pw", "pcb", "arc", "fai", "gai", "bbs3", "dt",
  "fph", "sgb", "sgd", "sgc", "jset", "bpc",
];

console.log("=== .t() CALLS IN 5.9.0 ===");
console.log(tKeys.join('\n'));
console.log(`\nTotal .t() keys: ${tKeys.length}`);

console.log("\n=== NEW .t() KEYS (not in 5.8.0 Go builder) ===");
const knownSet = new Set(known580);
const newKeys = tKeys.filter(k => !knownSet.has(k));
console.log(newKeys.join('\n'));
console.log(`\nNew keys count: ${newKeys.length}`);

console.log("\n=== REMOVED KEYS (in 5.8.0 but not in .t() calls) ===");
const tKeySet = new Set(tKeys);
const removedKeys = known580.filter(k => !tKeySet.has(k));
console.log(removedKeys.join('\n'));
console.log(`\nRemoved count: ${removedKeys.length}`);
