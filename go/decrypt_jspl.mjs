// Fast DataDome jspl decryptor — optimized: step by 8ms, first-byte filter
const seedO = 1789537805, seedE = 9959949970, encryptSeed = 1809053797;
const ivXorConst = 11027890091, defaultV = 741130091;

function toInt32(n) { n = Number(n) & 0xFFFFFFFF; return n >= 0x80000000 ? n - 0x100000000 : n; }
function xorshift32(n) { n = toInt32(n); n = toInt32(n ^ toInt32(n << 13)); n = toInt32(n ^ (n >>> 17)); return toInt32(n ^ toInt32(n << 5)); }
function hashL(s) { if (!s) return seedO; let t = 0; for (let i = 0; i < s.length; i++) t = toInt32(toInt32(t << 5) - t + s.charCodeAt(i)); return t === 0 ? seedO : t; }
function float64ToInt32(f) { if (!isFinite(f) || f === 0) return 0; return toInt32(Number(BigInt(Math.trunc(f)) & 0xFFFFFFFFn)); }
function wDecode(c) { if (c >= 96) return c - 59; if (c >= 65) return c - 53; if (c >= 48) return c - 46; if (c === 95) return 1; return 0; }

function computeF(ts) {
  let tsShifted = toInt32(toInt32(ts >> 3) ^ ivXorConst);
  let inner = xorshift32(tsShifted);
  return xorshift32(float64ToInt32(inner * seedE));
}

function firstByteCheck(jsplBytes, nKey, tKey, f) {
  // Decode first 4 base64 chars
  let aIV = toInt32(f);
  let combined = (wDecode(jsplBytes[0]) << 18) | (wDecode(jsplBytes[1]) << 12) | (wDecode(jsplBytes[2]) << 6) | wDecode(jsplBytes[3]);
  aIV = toInt32(aIV - 1); let c0 = (combined >> 16 & 255) ^ (255 & aIV);

  // XOR with first tPrng byte
  // tPrng: seed=tKey, iv=f, xor=false → first next() returns high byte of seed after init
  let tC = toInt32(tKey), tE = -1;
  tE++; // e=0
  let tRaw = toInt32(tC >> 16); // shift=16
  let d0 = c0 ^ (255 & tRaw);

  // XOR with first sPrng byte
  // sPrng: seed=nKey, iv=f, xor=true → first next() returns (high byte of seed) ^ (iv-1)
  let sC = toInt32(nKey), sI = toInt32(f);
  sI = toInt32(sI - 1);
  let sRaw = toInt32(sC >> 16);
  let plain0 = d0 ^ (255 & (sRaw ^ sI));

  return plain0 === 123; // '{'
}

function fullDecrypt(jsplBytes, nKey, tKey, f) {
  let aIV = toInt32(f), c = [];
  for (let pos = 0; pos + 3 < jsplBytes.length; pos += 4) {
    let combined = (wDecode(jsplBytes[pos]) << 18) | (wDecode(jsplBytes[pos+1]) << 12) | (wDecode(jsplBytes[pos+2]) << 6) | wDecode(jsplBytes[pos+3]);
    aIV = toInt32(aIV - 1); c.push((combined >> 16 & 255) ^ (255 & aIV));
    aIV = toInt32(aIV - 1); c.push((combined >> 8 & 255) ^ (255 & aIV));
    aIV = toInt32(aIV - 1); c.push((combined & 255) ^ (255 & aIV));
  }
  let rem = jsplBytes.length % 4;
  if (rem >= 2) {
    let vals = []; for (let i = jsplBytes.length - rem; i < jsplBytes.length; i++) vals.push(wDecode(jsplBytes[i]));
    while (vals.length < 4) vals.push(0);
    let combined = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
    aIV = toInt32(aIV - 1); c.push((combined >> 16 & 255) ^ (255 & aIV));
    if (rem >= 3) { aIV = toInt32(aIV - 1); c.push((combined >> 8 & 255) ^ (255 & aIV)); }
  }
  if (rem === 2) c = c.slice(0, c.length - 2);
  else if (rem === 3) c = c.slice(0, c.length - 1);
  c.pop();

  // tPrng
  let tC = toInt32(tKey), tE = -1, tI = toInt32(f);
  function tNext() {
    tE++; if (tE > 2) { tC = xorshift32(tC); tE = 0; }
    return 255 & toInt32(tC >> (16 - 8 * tE));
  }
  let d = c.map(b => b ^ tNext());

  // sPrng
  let sC = toInt32(nKey), sE = -1, sI = toInt32(f);
  function sNext() {
    sE++; if (sE > 2) { sC = xorshift32(sC); sE = 0; }
    sI = toInt32(sI - 1);
    return 255 & (toInt32(sC >> (16 - 8 * sE)) ^ sI);
  }
  let chars = d.map(b => b ^ sNext());
  let str = String.fromCharCode(...chars) + '}';
  try { return JSON.parse(str); } catch { return null; }
}

// Parse payload
const raw = process.argv[2] || `jspl=hZDrF_PopQUrM5WBBzK7dCBofLkbQOlvgiwWGyGURaU7rkwbsMn6Q2X9WsDhvwdJ8-jAWHFxDZUo1RdUtJyHnNhZH9DH61lCauqLhkkonFmSkOZ8rrtxFridK1DYgTb339gnU_eEXFAYrtt8D9BTIsry50WjEDH04RHPSy381h9EfF7yKMyYUzeJsh2q4o70RvLrtORrVVDACu3uD_GvLRku0CeH3OLqTFJqOe1O5GHu-CgvsUXrcCjvMctOYxyawUOgbiEhlbGB0qn7rRFgumhySIOHcElFne1pE9uAj4TZE6rU02lKlRyMbGWPpffjs6c0nhpW8OO4gSw3eNMD1qpx_1p-fB9q4blyv_OPvzLPgYrbWXNTGjsqCkYC4SPv33vxnzHkik-l6x72mWEvJb3fdB5kYTR5Nu6bDUUnKGSUWOwX5RfTob6rPVjsASS4G7MvqbuaplwlHkSvtKKs8zQQsDc0961_wII2Khe9RQMrKjBEg9_9O1qOANo8UHkWIx2ucx8wzS85yj8sbyRIDcylGJfa6Xx0cDN_AiJPglCocLhEtX1LBIeFKPQ2NUqYX0qeSgYTyNin8uircU2k1EUehcFkao8JwAfuzFsD9RPqyeFGog9KpnUjkf8XIkszvBO8efvL7nzNvrx_aB1mIRd_LEpSrjTOc2f9FZmfWj98a1LWA7025TwFCVxLjIwrKXAfOx1bkEHXlvNMnB8UKSQZDaQhcDu8yyUA4MReCRm9iUxpTX1SGLyu85bSNQPxHNl_5oJqfrrMa5JMt2uRFFBGGsG0XokURnLGDd6Ij01iR61SBtPcMUJRiqiRCkHiJpa8bVG7e7V8QqXx0N9Bj2aiyACikzTNA8CYicvYs26nXzn5DHwuuwAIxvpj6t4iyPLSZhBT4ac3vVmBTxdKSvSZDGmRHQgwCbRic6VP_pvAPWtZHkb2nDgOpvwNcp0do5AEx2uikS5wKkb3fKWIKlsSyiHgaMs2XjtoN4U2YW5SDpgTjwOyB2Qerx6Wk3u5IhpEoRK5OOSxADZnmqJTAsD8CxtAlV_IP9LbXlFEZr4VYspplCFcuBm56Z-61xFlMynRh1z2xRna0pSwV51x7wqpYCNIQIwIwAx22fajsPCYQoee1pMyUyOots_Ct4CQFTwyUYR0BZulZ01MFL9bPo4DNEm5IyVnBHkQLpUYXtyIl-267hV1ohNTOJMAV7_fu-AMe9E7Y9MitHwsI528G1gMaQqjlJwznT5BFk7gVrCLeZByY5zPPEuSDPemaN5DNoqeZQTdmLU0tO5w5-FwqmqKywbTrTJXHd2j09cqKc5xUq7e7nrdUbw8rctqeviWSxG8UtjpXX9drWeaPv4nOfAofUb_zbBEb1Jrxspx0xJCoqzN8eksFThO9qlja5rMtPCOuWFEdxi2MX-QM_KWqtZ6FCM1z8Q7_AkdBVbc-7sy4tggNGECPtzeNo3lhwLrEJ4pBUcgY0NjB23XQ1udfkVuJiq3YCwc-vNnc7fCGyHeIo-7sVi6-QCTA87oqlimF2ksusPZf7NQs4yhYnmUZ0lbRv4IkpKiokKROZCCxPQvoqvqZOdSHjKJCWcw-qvXUr1P4Qdj-VszYf4tTke5YsMUmn3WeqTV_QrQQCoj7zgSXbtYLCDGs1QoZCsEtPJbmKcig4COglYFaH_IRVRXTUX4EoaWAh0XDid5DoQU5LNXaFCJJUqlnb3BGVnbhLUEzxrxwzDhyoMYpBT9j16bdN4SKZHxptHq3f-BuxBn4dyaSmO0iArNr2YIvPfXgaIZsUfNdDvnF3RrqE3gDtVcfYQm1tMlFS4WvOLH72QIkXTworjCx3axPuBStlBu8KaMkGvWNwDiBXsZ0iStb-vAPopGMHPuoxCpj0X5sD8CEtvluxRfCmo51d1CjlAUZzei7hYK9t5UMvm16ExQ8h68n32E62JRXlSPaO0VOIJXqLbZrqV4TY_Y7Fl6ad7T4Tz2nlcis0BI7it5ucvaBciYjwiWc760hPBvB0C-ZGlRyyWuK7G98oDyAHHMqui-UXZyg2YCHYMDmiUupeN2CuwBeFqBx5p4OcvOD0mqfxDgmg5IJ-xK2tKzYoePbl4B-6rTe5cd5c6_Zs3KkVTmkp_hx_5pkfPU8vHlqQtteOZ8DLRfXBnY8a_9yEmRPD0ErDO_3njKGGYUjHzE4Q2I-FGFWceKJ-S5lHtRRREIwCgAa9rSWEnXKNS9Cym_tr3OdJieGZ4lDhd6JewKOPfaHqv5rgH-0GHDW7WJvm_lIXvIChSES0SaLbHiNVUOss2DnG5fpT8sPKNsw7__-8B-TQFjFNyWmbYyhB5U7grOKGoE3gaeSrFVJDlIkYoiyyovXLjkhlvWhY3MdDC-bIEcToy0kuGMydfPFa6pxkQaXxY624qMnxrgS-Ixx0nSoA6AZR0-bOn2oUUUY1r14uVKwWm6XOq60CX4SUhFq22gEglMLiX1RlD7dEef4v15tAvi0thh_zkD9-2e0u9ZtnOl6QihrCkoGbG6BIMholMIv7Y8zldx4DEGAO0q4YQ5kF4Q0aCu95Kp0AUEOuUqOPEx6SqqVkKZPDzSd4CrvAIsbjBCphgc-L2eMW8xepXCVkQuNKnuSk0HPDKr3t7xR_1OU9CSGOQYYe1iMS4AYjOgQ8EX9GowwkuRamDnMZIteIwygZykf3cT2jrTETMdB6y--0ORZc1E5_JLC-7UmGWMcjRKs3sD51f18DQyQIUc7ziSZKhli8l6dzy5aUz6rMI5DsyeQ0nc9oDtLuTkkum30Ep5HB5pJJreEK0v-bPOjk3M8lfFyp7o_S367PoRtTWuRWOVXPxK9Mkbqb3Ntt4iqiHWj-sj7yiDOGq0SYF6na1Zukdc4SywdLsoPsjNep6fTuVXDnItZUqWL6ewcvbM53zhq4xTptVp_bxSzGzzCyd3sCbcYz2hWmu7elrdOhsJL5tzBGJqdituhdLet-iArEwmGTz1SczjbGZDBEkobjLqC68iyQHJzzSN9IL6s1jQDYKlkYtZf5eWahYyGPHrVkR48KxaXk8OVxLoLycCpWQKSmBQBXNUeG7s7TTr_3Q39aQZu1YaVaR0kqbnwQ5AD-l5QkQQz2OGeyFsJgJeD4h6aItfa1wwIxEMAQ7zYt1uAUgaK-h5kdoQZKvf1efcT9HsQpcTkmHLg4i1Y2mTKItW-iTRCZGSo45LNi4N3gfQmM8-WmXKTiMoLuX9HrMjaX1h8a1rHJ_vlRKi5qGY4vWUos5XpLSK2axWJ_Jz5UQKGUr3BldLrLCaAOIg8cVHcDkiEMrWgKUylC6H8XOaf2Ie6BGTb6s10mCGOkMPCIEWrQcjBOP7iJttJ-rcpITUGYuA5VUjchBUpvIUOc7v_p2RYZD0DRawL7hqoaOFAnV2pb_w-X_0tk6l_ka4gJ2RGBCYg5zPMiXEz_sFWVlE2cV5uMsjVqKGepR70plDQIvKRcmflJ-dtV5MLPcEdXMWxdq6HfR2GSPBjxYzH7ZtyGTfKSUC5AgZ8ACU7-Lm27Ij_GwjwyQRyzHOc3M4ZwWcv49Dd7L3H95yraYMWpQCuwTNM3lL_fiTtm34vP6dO59T83EUXnlLCA1qGGzelTRw6nyAf-eE2FKV8DDJfLHogMsao6WvSqMRXUCi7WKK-5HvCTblpLloA6Ypvj9FP_uifChsXYa3hJqMdTBRe2Y8732DNj-jPE1sWcM5l8qSGj85BRng0t3NvT0SYg7ORlsZvbSK91CXvcBmQSPJuCEgAvI5RC0Aam1NdauKvydtJjmiW4YTyYiuKVaFH7NBo2M82vJhRcuyu5GZrcZz5DYS2U2QhG7QmEsUVyKAJCXApF9WgS4ynQ2rOCl4dlkR8QhbOrVZg09weInEoe_aZJgAFQzPkbxMfELNMiwH2yjdQ0lW89R1omcy1FjYPgOV0awFm6OEcsqO79BsZPt417TPWb-WHH59rcSz5OLbFdJvzNgMWhK6DMqLBqtVzhDzfYS0SRvoMd6dQz13vo7L_Jbxu9w8oH68q_PdCo01lFvKmT60HxyhDX3JPCuMPpeF0GbFLvf2sZjYhJ5bYNJY27O4_xtRIApzz5BCldtYZ1RSQ2pRHykFLSPhPrP-P36N1swpD1spGqs45Qp1q5YabeJGqP5jLhEGAaKBDvVM_qZmmENRZzaUkGGor6uFwIigzqWwPt7Hvv6ck6VNSkZ3vWNF25DvP0UXT1IGCsNpU6ioPBvTGcRyKCrGENG2xVKdZO-veLqgJ3StY1QM0n1uUfEg51ToDXJxgv6vBpXcPZWBGMj7T1huuiHJTpqGkIya_IUszETSDc3P7ZW8AZkJ52SemWh_FWf0SlVg300qB9usGQH94GQae2iNijIuv7v3QyLRkfv1tjOaDaGeJBtu6rtzKY5t08V7Bm4z8NIcGpbpNDchMpX5EyGTB_p2O1jNxt_HKNz1NeaKVEiXIIKV6N3q6vdYB9LjDOG1oljwJnf0FspL0CF3673avcrvLKskbx9ohXsVIHDotKXxXlmambjpO5S2bmf84eH9Ix_NPOg5ZGhgyspGlj4dd51FXyQiL5uvYwoDHhqV_1YeFqbEXd-xFPXgXXzNSbiZvySF4StbeeOspHr4T58teMWrLRa_lWg6ULZJEWNs9oIo47ECNwisks-lSRu1dC7eBSFdMbkQurv1UMmJspZvSGHcDjcalj5Xz8FmlGaCHsuo5E76b8T4_zv84B1J7oGZG0V6mIq8AIPl0ylFwYaJRcgDfHovQzpQk09XXiEPJNRX4Gd-kgiKPz_4vNac1pz2k4tn2t503cRyrmFu7CeaOti7E7HsAlUAisk5bkRS6e1BjrTbpdJBDVw1eymFh-5Y5wTXKYGdtgVrNKVcRNIbhALw7NatOb3BW3MEQ4yeOISOU96J2kR7CcCHSwVyNg6MoMoBwZJdsncLiH1oVTOWgVNqa-xZtX7F36b6roFPyr43KRuDswGhyBuHIgQGGaBxniextiliD0gCgm1vSfM1do_P_t5dtySuuXuqtNZhtWDwErfyF4momNQspg87A-BaEPMdJgPCFBhjNlbbd_DfhGiWlhF5JM4rnIcimDyJFk8fIjNKI_Hm1hujdJuCOul4OT9r9KyKU_F2jtMZxNYXkSNBETqOKQPtANw_BrYwpRWiKfmVPaOgWIbl_WuPjgni7ajQ6w_5p7FId-zpGPInk78Gy1w4-_LKcARJ5uT-iZq4`;

const params = new URLSearchParams(raw);
const jspl = params.get('jspl');
const cid = params.get('cid');
const ddk = params.get('ddk');
const jsplBytes = [...jspl].map(c => c.charCodeAt(0));

const nKey = toInt32(toInt32(seedE) ^ hashL(ddk) ^ defaultV);
const tKey = toInt32(encryptSeed ^ hashL(cid));

console.log(`CID: ${cid?.slice(0,40)}...`);
console.log(`DDK: ${ddk}`);
console.log(`jspl: ${jspl.length} chars`);

const now = Date.now();
let found = false;
let checked = 0;
const start = performance.now();

// Scan 48h window, step by 8ms (ts>>3 resolution)
for (let off = 0; off < 48 * 3600 * 1000; off += 8) {
  const ts = now - off;
  const f = computeF(ts);
  checked++;

  if (firstByteCheck(jsplBytes, nKey, tKey, f)) {
    // Candidate — try full decrypt with exact ms within this 8ms window
    for (let fine = 0; fine < 8; fine++) {
      const exactTs = ts - fine;
      const exactF = computeF(exactTs);
      const obj = fullDecrypt(jsplBytes, nKey, tKey, exactF);
      if (obj) {
        const elapsed = ((performance.now() - start) / 1000).toFixed(1);
        console.log(`\nDECRYPTED in ${elapsed}s (checked ${checked} candidates)`);
        console.log(`Timestamp: ${exactTs} (${((now - exactTs)/1000/3600).toFixed(2)}h ago)\n`);

        const keys = Object.keys(obj);
        console.log(`Total signal keys: ${keys.length}\n`);

        const go580 = new Set([
          "log3","r3n","glvd","glrd","wwlrv","nddc","exp8",
          "plu","plgod","plg","plgne","plgre","plgof","plggt",
          "bfr","hdn","br_w","br_h","br_ih",
          "ars_w","ars_h","rs_w","rs_h","rs_cd",
          "cg_w","cg_h","sg_w","sg_h","pr","so","trrd",
          "ucdv","dp0","hcovdr","plovdr","ftsovdr",
          "orf","dffls","niet","nid","nisd",
          "nt_tcp","nt_dns","nt_rd","nt_irt","nt_rt","nt_tls","nt_ttf",
          "nt_swt","nt_csd","nt_nhp","nt_rdc","nt_it",
          "nt_prs","nt_esc","nt_ttrd","nt_le","nt_dcle","nt_di","nt_dc",
          "lg","isb","idp","crt","vnd","bid","med",
          "pltod","npmtm","wdif",
          "ccsT","ccsB","ccsH","ccsV","mmt","wdifpnh",
          "vco","vcots","vch","vchts","vcw","vcwts","vc3","vc3ts",
          "vcmp","vcmpts","vc1","vc1ts","vcmk","vcmkuts","vcq","vcqts",
          "cssS","css0","css1","cssH",
          "pro_t","prso","wbst","psn","edp","wsdc",
          "ccsr","nuad","bcda","idn","capi","svde",
          "bchk","tz","ihdn","cdhf","eva","cokys","ecpc","wop",
          "pf","hc","br_oh","br_ow","ua","wbd","ts_mtp","mob","lgs","dvm",
          "ckwa",
          "aco","acots","acmp","acmpts","acmpu","acmputs","acw","acwts",
          "acma","acmats","acaa","acaats","ac3","ac3ts","acf","acfts",
          "acmp4","acmp4ts","acmp3","acmp3ts","acwm","acwmts",
          "acqt","ac_NA",
          "ocpt","sivd","mq","mq2",
          "awe","phe","dat","nm","geb","sqt","spwn","emt",
          "nhi","k_lyts","k_lytk",
          "bci","bcl","bct","bdt",
          "stqe","stqu","isf","isf2",
          "pw","pcb","arc","fai","gai","bbs3","dt",
          "fph","sgb","sgd","sgc","jset","bpc",
        ]);

        console.log('=== ALL SIGNALS (+ = new in 5.9.0) ===');
        for (const k of keys) {
          let v = obj[k];
          let vs = typeof v === 'string' && v.length > 100 ? v.slice(0,100)+'...' : JSON.stringify(v);
          let marker = go580.has(k) ? '  ' : '+ ';
          console.log(`${marker}${k} = ${vs}`);
        }

        const liveKeys = new Set(keys);
        console.log('\n=== NEW IN 5.9.0 ===');
        for (const k of keys) {
          if (!go580.has(k)) console.log(`  + ${k} = ${JSON.stringify(obj[k])}`);
        }

        console.log('\n=== REMOVED (in Go 5.8.0 but not in live 5.9.0) ===');
        for (const k of go580) {
          if (!liveKeys.has(k)) console.log(`  - ${k}`);
        }

        const fs = await import('fs');
        fs.writeFileSync('live_590_signals.json', JSON.stringify(obj, null, 2));
        console.log('\nSaved to live_590_signals.json');
        found = true;
        break;
      }
    }
    if (found) break;
  }

  if (checked % 1000000 === 0) {
    const elapsed = ((performance.now() - start) / 1000).toFixed(0);
    console.log(`  scanned ${(off/1000/3600).toFixed(1)}h back (${checked} checks, ${elapsed}s elapsed)`);
  }
}

if (!found) console.log('FAILED — not in 48h window');
