import { describe, it, expect } from "vitest";
import gost89 from "gost89";
import * as jk from "../lib/index.js";
import { loadAsset } from "./utils.js";

describe("CZO CAdES-BES GOST", () => {
  const gostHash = gost89.compat.algos().hash;
  const box = new jk.Box({
    algo: { hash: gostHash, hashes: { Gost34311: gostHash } }
  });
  const p7s = loadAsset("test-gost-czo.p7s");

  it("unwraps and verifies signature", async () => {
    const { content, pipe } = await box.unwrap(p7s);
    expect(content.toString()).toBe("Test\r\n");
    expect(pipe[0].signed).toBe(true);
    expect(pipe[0].cert.subject.commonName).toBe("ТЕСТ Тестовий Тест Тестович");
  });

  it("unwraps with CA verification", async () => {
    const caBox = new jk.Box({
      algo: { hash: gostHash, hashes: { Gost34311: gostHash, Dstu4145le: gostHash } }
    });
    caBox.loadCAs(loadAsset("CZO-CA-LIST.p7s"));

    const { pipe } = await caBox.unwrap(p7s);
    expect(pipe[0].signed).toBe(true);
    expect(pipe[0].cert.verified).toBe(true);
  });
});
