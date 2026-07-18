/*
 * Timing side-channel measurement for the fixed-length-nonce countermeasure
 * (lib/models/Priv.js `fixed_length_scalar`). NOT part of `npm test` - it is
 * a slow, informational probe for review. Run it with:
 *
 *     npm run analysis:timing
 *
 * Question it answers (the one Minerva / TPM-FAIL rely on): does the SECRET
 * nonce's bit length correlate with the work / time of the scalar
 * multiplication, and does that correlation disappear after padding?
 *
 * Method. The whole fix is one function: pad the scalar with the group order
 * to a constant bit length. "Before" = multiply by the raw nonce; "after" =
 * multiply by the padded nonce. Both are built here in a single process, so
 * no second git checkout is needed - we compare the two code paths directly,
 * without cross-run noise.
 *
 *  - Nonces are drawn from the REAL distribution (uniform in [1, order), like
 *    curve.rand). The x-axis is the leading-zero count (orderBits - bitLength)
 *    - exactly the quantity the lattice attacks exploit - which for natural
 *    nonces is decoupled from the value's magnitude / Hamming weight.
 *  - Work is counted deterministically (every point op routes through
 *    Point.add; add(this) is a doubling, add(other) is a wNAF addition), which
 *    is noise-free. Wall-clock time is reported too, as corroboration.
 *
 * Expected: doublings track the leading-zero count before the fix and become
 * constant after it; the total-work correlation with the leading-zero count
 * collapses to ~0.
 */
import { test } from "vitest";
import asn1 from "asn1.js";
import { std_curve } from "../lib/curve.js";
import Point from "../lib/point.js";
import Field from "../lib/field.js";

const bn = asn1.bignum;

// add(this) === doubling (count set by bit length); add(other) === wNAF
// addition (count set by the non-zero digit pattern / Hamming weight).
let dbl = 0;
let addn = 0;
const origAdd = Point.prototype.add;
Point.prototype.add = function (o) {
  if (o === this) dbl++;
  else addn++;
  return origAdd.call(this, o);
};
function counts(point, scalar) {
  dbl = 0;
  addn = 0;
  point.mul(scalar);
  return { dbl, total: dbl + addn };
}

function medianMulMs(point, scalar, reps, rounds) {
  const s = [];
  for (let r = 0; r < rounds; r++) {
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < reps; i++) point.mul(scalar);
    s.push(Number(process.hrtime.bigint() - t0) / reps / 1e6);
  }
  s.sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

// deterministic PRNG so the run is reproducible
let seed = 0x9e3779b9;
function xorshift() {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return seed >>> 0;
}

function padded(bigK, bigMod, curve) {
  let k = bigK.add(bigMod);
  if (k.bitLength() === bigMod.bitLength()) k = k.add(bigMod);
  return new Field(k.toArray(), "buf8", curve);
}

function pearson(xs, ys) {
  const n = xs.length;
  const mx = xs.reduce((a, b) => a + b, 0) / n;
  const my = ys.reduce((a, b) => a + b, 0) / n;
  let sxy = 0;
  let sxx = 0;
  let syy = 0;
  for (let i = 0; i < n; i++) {
    const dx = xs[i] - mx;
    const dy = ys[i] - my;
    sxy += dx * dy;
    sxx += dx * dx;
    syy += dy * dy;
  }
  return sxx === 0 || syy === 0 ? Number.NaN : sxy / Math.sqrt(sxx * syy);
}
const mean = a => a.reduce((x, y) => x + y, 0) / a.length;
const std = a => {
  const m = mean(a);
  return Math.sqrt(mean(a.map(x => (x - m) * (x - m))));
};

// This probe runs for over a minute in one tight computation; yield to the
// event loop periodically so vitest's worker heartbeat (onTaskUpdate) does
// not time out and flag a spurious unhandled error.
const breathe = () => new Promise(resolve => setImmediate(resolve));

test("secret nonce leading-zeros vs scalar-mul work: before(raw) vs after(padded)", async () => {
  const curve = std_curve("DSTU_PB_257");
  const base = curve.base;
  const bigOrder = new bn.BN(curve.order.buf8(), 8);
  const orderBits = curve.order.bitLength();

  function naturalNonce() {
    for (;;) {
      const buf = Buffer.alloc(Math.ceil(orderBits / 8));
      for (let i = 0; i < buf.length; i++) buf[i] = xorshift() & 0xff;
      const v = new bn.BN(buf).maskn(orderBits);
      if (!v.isZero() && v.lt(bigOrder)) return v;
    }
  }

  for (let i = 0; i < 400; i++) base.mul(padded(naturalNonce(), bigOrder, curve)); // warm up

  const N = 6000;
  const lz = [];
  const dblRaw = [];
  const dblPad = [];
  const totRaw = [];
  const totPad = [];
  for (let i = 0; i < N; i++) {
    const k = naturalNonce();
    lz.push(orderBits - k.bitLength());
    const cr = counts(base, new Field(k.toArray(), "buf8", curve));
    const cp = counts(base, padded(k, bigOrder, curve));
    dblRaw.push(cr.dbl);
    totRaw.push(cr.total);
    dblPad.push(cp.dbl);
    totPad.push(cp.total);
    if (i % 200 === 0) await breathe();
  }

  // wall-clock grouped by leading-zero count (median per group)
  const groups = {};
  for (let i = 0; i < N; i++) {
    const z = lz[i];
    if (!groups[z]) groups[z] = [];
    groups[z].push(i);
  }
  const gz = Object.keys(groups)
    .map(Number)
    .sort((a, b) => a - b)
    .filter(z => groups[z].length >= 100);
  const tRaw = [];
  const tPad = [];
  for (const z of gz) {
    let k;
    do {
      k = naturalNonce();
    } while (orderBits - k.bitLength() !== z);
    tRaw.push(medianMulMs(base, new Field(k.toArray(), "buf8", curve), 40, 7));
    tPad.push(medianMulMs(base, padded(k, bigOrder, curve), 40, 7));
    await breathe();
  }

  const fmtR = r => (Number.isNaN(r) ? "n/a (constant -> no dependence)" : r.toFixed(4));
  const line = (label, ys) =>
    "  " +
    label.padEnd(16) +
    " r(leading-zeros)=" +
    fmtR(pearson(lz, ys)) +
    "   [std=" +
    std(ys).toFixed(2) +
    ", range " +
    Math.min(...ys) +
    ".." +
    Math.max(...ys) +
    "]";
  const out = [
    "",
    "=== leading-zeros of NATURAL nonce vs scalar-mul work (DSTU_PB_257) ===",
    "N=" + N + "  leading-zeros observed " + Math.min(...lz) + ".." + Math.max(...lz),
    "",
    "DOUBLINGS  (the bit-length / Minerva channel the padding targets):",
    line("before (raw)", dblRaw),
    line("after (padded)", dblPad),
    "",
    "TOTAL point ops (doublings + additions ~ time):",
    line("before (raw)", totRaw),
    line("after (padded)", totPad),
    "",
    "wall-clock (corroboration only - the padded effect is <1% and sits below",
    "pure-JS timing noise, so the deterministic counts above are authoritative):",
    "  r(leading-zeros, time):  before=" +
      fmtR(pearson(gz, tRaw)) +
      "  after=" +
      fmtR(pearson(gz, tPad)),
    "  median mul ms by leading-zeros:",
    ...gz.map(
      (z, i) =>
        "  lz=" +
        z +
        " (n=" +
        groups[z].length +
        ")  raw=" +
        tRaw[i].toFixed(3) +
        "  padded=" +
        tPad[i].toFixed(3)
    ),
    ""
  ].join("\n");
  // eslint-disable-next-line no-console
  console.log(out);
}, 300000);
