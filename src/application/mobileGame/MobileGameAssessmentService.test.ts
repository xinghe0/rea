import { expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ZipWriter, Uint8ArrayWriter, Uint8ArrayReader } from "@zip.js/zip.js";
import { MobileGameAssessmentService } from "./MobileGameAssessmentService.js";
import { MobileGameToolService } from "./MobileGameToolService.js";

it("preserves partial stage outcomes and input identity, and refuses case overwrite", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-game-workflow-"));
  try {
    const writer = new ZipWriter(new Uint8ArrayWriter());
    await writer.add(
      "assets/settings.json",
      new Uint8ArrayReader(Buffer.from('{"api_key":"test-source-value"}')),
    );
    const apk = join(root, "fixture.apk");
    await writeFile(apk, await writer.close());
    const service = new MobileGameToolService(
      new MobileGameAssessmentService(),
    );
    const input = { apk, game: "fixture", case_root: root };
    const result = await service.execute("assess_mobile_game", input);
    expect(result.ok).toBe(true);
    if (!result.ok) throw result.error;
    expect(result.value.subject?.local_path).toBe(apk);
    const check = JSON.parse(
      await readFile(join(root, "fixture/analysis/check.json"), "utf8"),
    );
    expect(check.status).toBe("partial");
    expect(check.checks).toContainEqual({
      stage: "baseline.signature",
      status: "not-configured",
    });
    expect(check.checks).toContainEqual({
      stage: "traffic",
      status: "not-selected",
    });
    const before = await readFile(
      join(root, "fixture/analysis/scope.json"),
      "utf8",
    );
    expect((await service.execute("assess_mobile_game", input)).ok).toBe(false);
    expect(
      await readFile(join(root, "fixture/analysis/scope.json"), "utf8"),
    ).toBe(before);
    const controller = new AbortController();
    controller.abort(new Error("cancelled"));
    const cancelled = await service.execute(
      "assess_mobile_game",
      { ...input, game: "cancelled" },
      { signal: controller.signal },
    );
    expect(cancelled.ok).toBe(false);
    if (!cancelled.ok)
      expect(cancelled.error._tag).toBe("AnalysisCancelledError");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
