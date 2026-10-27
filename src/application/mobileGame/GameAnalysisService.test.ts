import { expect, it } from "vitest";
import {
  mkdtemp,
  mkdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { GameAnalysisService } from "./GameAnalysisService.js";
import { GameResourceProvider } from "../../mobileGame/GameResourceProvider.js";
import { MobileGameToolService } from "./MobileGameToolService.js";
import { MobileGameAssessmentService } from "./MobileGameAssessmentService.js";
import { ZipWriter, Uint8ArrayWriter, Uint8ArrayReader } from "@zip.js/zip.js";

it("converts colliding names losslessly, records limits and refuses overwrite", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-game-convert-"));
  const service = new GameAnalysisService(new GameResourceProvider());
  try {
    const input = join(root, "input");
    await mkdir(input);
    for (const name of ["a", "b"]) {
      await mkdir(join(input, name));
      await writeFile(join(input, name, "table.bin"), '{"value":false}');
    }
    await writeFile(join(input, "oversize.bin"), Buffer.alloc(256));
    await symlink(join(input, "a/table.bin"), join(input, "linked.bin"));
    const output = join(root, "output");
    const result = await service.execute("convert_game_resources", {
      output_directory: output,
      options: { roots: [input], max_file_bytes: 100 },
    });
    expect(result.ok).toBe(true);
    const manifest = JSON.parse(
      await readFile(join(output, "manifest.json"), "utf8"),
    );
    expect(
      manifest.files.filter(
        (file: { status: string }) => file.status === "completed",
      ),
    ).toHaveLength(2);
    expect(
      manifest.files.filter(
        (file: { status: string }) => file.status === "limited",
      ),
    ).toHaveLength(1);
    expect(
      manifest.files.filter(
        (file: { status: string }) => file.status === "not-read",
      ),
    ).toHaveLength(1);
    for (const file of manifest.files.filter(
      (file: { status: string }) => file.status === "completed",
    )) {
      expect(await readFile(file.artifact, "utf8")).toBe('{"value":false}');
      const converted = JSON.parse(
        await readFile(file.conversions[0].path, "utf8"),
      );
      expect(converted.interpretations[0].values).toEqual([{ value: false }]);
    }
    expect(
      (
        await service.execute("convert_game_resources", {
          output_directory: output,
          options: { roots: [input] },
        })
      ).ok,
    ).toBe(false);
    expect(
      (
        await service.execute("convert_game_resources", {
          output_directory: join(input, "nested"),
          options: { roots: [input] },
        })
      ).ok,
    ).toBe(false);
  } finally {
    await service.close();
    await rm(root, { recursive: true, force: true });
  }
});
it("decodes protobuf using shared offsets and retains malformed partial fields", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-game-wire-"));
  const service = new GameAnalysisService(new GameResourceProvider());
  try {
    const path = join(root, "message.bin");
    await writeFile(path, Buffer.from([8, 150, 1, 18, 5, 65]));
    const result = await service.execute("decode_game_protocol", { path });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.subject?.local_path).toBe(path);
      expect(result.value.normalized_result).toMatchObject({
        fields: [{ number: 1, value: "150", offset: 0 }],
        error: { offset: 3 },
      });
    }
  } finally {
    await service.close();
    await rm(root, { recursive: true, force: true });
  }
});
it("checks saved evidence and generates a report without replacing analyst edits", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-game-case-"));
  const service = new GameAnalysisService(new GameResourceProvider());
  try {
    const writer = new ZipWriter(new Uint8ArrayWriter());
    await writer.add(
      "assets/config.json",
      new Uint8ArrayReader(Buffer.from("{}")),
    );
    const apk = join(root, "game.apk");
    await writeFile(apk, await writer.close());
    const assessed = await new MobileGameToolService(
      new MobileGameAssessmentService(),
    ).execute("assess_mobile_game", { apk, game: "game", case_root: root });
    expect(assessed.ok).toBe(true);
    const directory = join(root, "game/analysis");
    await writeFile(join(directory, "report.md"), "analyst-owned report");
    expect(
      (
        await service.execute("inspect_game_case", {
          case_directory: directory,
        })
      ).ok,
    ).toBe(true);
    expect(
      (await service.execute("report_game_case", { case_directory: directory }))
        .ok,
    ).toBe(true);
    expect(await readFile(join(directory, "report.md"), "utf8")).toBe(
      "analyst-owned report",
    );
    expect(
      await readFile(join(directory, "report.generated.md"), "utf8"),
    ).toContain("后端强校验");
    expect(
      (await service.execute("report_game_case", { case_directory: directory }))
        .ok,
    ).toBe(false);
  } finally {
    await service.close();
    await rm(root, { recursive: true, force: true });
  }
});
