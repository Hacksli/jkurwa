import { bench, describe, vi } from "vitest";
import { std_curve } from "../lib/curve.js";

// Performance benchmarks for the private/public key operations.
// Run with `npm run bench` (separate from the normal `npm test` run).
//
// The signing path pads the secret nonce to a fixed bit length as a
// timing-side-channel countermeasure (see lib/models/Priv.js); these
// benchmarks make its cost visible and guard against regressions.
//
// Override the test suite's fixed 32-byte RNG stub (test/setup.js) with a
// full-length generator: otherwise curves that need more than 32 bytes of
// randomness (e.g. DSTU_PB_431) would be benchmarked with a truncated,
// unrealistically short nonce and report a misleading cost.
vi.mock("node:crypto", () => {
  let s = 0x12345678;
  const rng = n => {
    const b = Buffer.alloc(n);
    for (let i = 0; i < n; i++) {
      s = (s * 1103515245 + 12345) & 0x7fffffff;
      b[i] = (s >>> 8) & 0xff;
    }
    return b;
  };
  return { default: { rng } };
});

const hash = Buffer.alloc(32, 7);

function fixture(name) {
  const curve = std_curve(name);
  const priv = curve.keygen();
  const pub = priv.pub();
  const shortSig = priv.sign(hash, "short");
  return { curve, priv, pub, shortSig };
}

for (const name of ["DSTU_PB_257", "DSTU_PB_431"]) {
  const f = fixture(name);
  describe(name, () => {
    bench("sign", () => {
      f.priv.sign(hash, "short");
    });
    bench("verify", () => {
      f.pub.verify(hash, f.shortSig, "short");
    });
    bench("pub (public key from private)", () => {
      f.priv.pub();
    });
    bench("derive (ECDH shared key)", () => {
      f.priv.derive(f.pub);
    });
  });
}
