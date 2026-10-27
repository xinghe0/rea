import { writeFile, readFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { mcpTest } from "../../support/mcp/mcpFixture.js";

mcpTest(
  "advertises game tools and returns shared wire/resource Evidence through MCP",
  async ({ mcp }) => {
    const session = createTestBinarySession(() => {
      throw new Error("No deep target provider should start");
    });
    const client = await mcp.connect(
      createServer({ kind: "session", session }),
    );
    try {
      const names = (await client.listTools()).tools.map((tool) => tool.name);
      for (const name of [
        "assess_mobile_game",
        "convert_game_resources",
        "inspect_game_case",
        "report_game_case",
        "decode_game_protocol",
        "inspect_scrcpy_client",
        "observe_scrcpy_device",
        "control_scrcpy_device",
      ])
        expect(names).toContain(name);
      const root = await createTestTempDirectory("rea-game-mcp-");
      const path = join(root, "wire.bin");
      await writeFile(path, Buffer.from([8, 1]));
      const response = await client.callTool({
        name: "decode_game_protocol",
        arguments: { path },
      });
      expect(response.isError, JSON.stringify(response.content)).not.toBe(true);
      const evidence = toolContract("decode_game_protocol").outputSchema.parse(
        response.structuredContent,
      );
      expect(evidence.subject?.local_path).toBe(path);
      expect(evidence.normalized_result).toMatchObject({
        fields: [{ number: 1, value: "1" }],
      });
      const input = join(root, "input");
      await mkdir(input);
      await writeFile(join(input, "config.bin"), '{"enabled":false}');
      const converted = await client.callTool({
        name: "convert_game_resources",
        arguments: {
          output_directory: join(root, "out"),
          options: { roots: [input] },
        },
      });
      expect(converted.isError, JSON.stringify(converted.content)).not.toBe(
        true,
      );
      toolContract("convert_game_resources").outputSchema.parse(
        converted.structuredContent,
      );
      expect(
        JSON.parse(await readFile(join(root, "out/manifest.json"), "utf8"))
          .files[0].conversions[0].status,
      ).toBe("completed");
      const refused = await client.callTool({
        name: "control_scrcpy_device",
        arguments: {
          serial: "test-only",
          action: { kind: "shell_exec", command: "id" },
        },
      });
      expect(refused.isError).toBe(true);
    } finally {
      await session.close();
    }
  },
);
