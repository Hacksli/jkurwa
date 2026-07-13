import { describe, it, expect } from "vitest";
import gost89 from "gost89";
import * as jk from "../lib/index.js";
import { loadAsset } from "./utils.js";

describe("CZO CAdES-T", () => {
  const gostHash = gost89.compat.algos().hash;
  const p7s = loadAsset("test-t-gost.p7s");

  function makeBox() {
    return new jk.Box({
      algo: { hash: gostHash, hashes: { Gost34311: gostHash, Dstu4145le: gostHash } }
    });
  }

  it("unwraps with CA verification", async () => {
    const box = makeBox();
    box.loadCAs(loadAsset("CZO-CA-LIST.p7s"));

    const { content, pipe } = await box.unwrap(p7s);
    expect(content.toString()).toBe("Test\r\n");
    expect(pipe[0].signed).toBe(true);
    expect(pipe[0].cert.verified).toBe(true);
  });
});
