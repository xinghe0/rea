import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import {
  mcpToolResultSchema,
  mcpTextBlocks,
  parseMcpJsonOrText,
} from "../providers/McpToolResult.js";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import type { ScrcpyConfiguration } from "./ScrcpyConfiguration.js";

export interface ScrcpyMcpConnection {
  connect(signal?: AbortSignal): Promise<readonly string[]>;
  call(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
    signal?: AbortSignal,
  ): Promise<JsonValue>;
  close(): Promise<void>;
}

export const createScrcpyMcpConnection = (
  configuration: ScrcpyConfiguration,
): ScrcpyMcpConnection => {
  let client = new Client({ name: "rea-scrcpy-provider", version: "1" });
  const makeTransport = () =>
    new StdioClientTransport({
      command: configuration.command,
      args: configuration.args,
      ...(configuration.serverPath === undefined
        ? {}
        : { env: { SCRCPY_SERVER_PATH: configuration.serverPath } }),
    });
  let transport = makeTransport();
  let connected = false;
  return {
    async connect(signal) {
      if (signal?.aborted === true) throw signal.reason;
      if (!connected) {
        await client.connect(transport, {
          ...(signal === undefined ? {} : { signal }),
          timeout: configuration.timeoutMs,
        });
        connected = true;
      }
      const names: string[] = [];
      const cursors = new Set<string>();
      let cursor: string | undefined;
      do {
        const listed = await client.listTools(
          cursor === undefined ? {} : { cursor },
          {
            ...(signal === undefined ? {} : { signal }),
            timeout: configuration.timeoutMs,
          },
        );
        names.push(...listed.tools.map((tool) => tool.name));
        cursor = listed.nextCursor;
        if (cursor !== undefined) {
          if (cursors.has(cursor))
            throw new AnalysisProtocolError(
              "scrcpy catalog repeated a pagination cursor",
            );
          cursors.add(cursor);
        }
      } while (cursor !== undefined);
      return names;
    },
    async call(name, args, signal) {
      if (signal?.aborted === true) throw signal.reason;
      if (!connected)
        await client
          .connect(transport, {
            ...(signal === undefined ? {} : { signal }),
            timeout: configuration.timeoutMs,
          })
          .then(() => {
            connected = true;
          });
      const result = await client.callTool(
        { name, arguments: args },
        {
          ...(signal === undefined ? {} : { signal }),
          timeout: configuration.timeoutMs,
        },
      );
      const envelope = mcpToolResultSchema.parse(result);
      if (envelope.isError === true)
        throw new AnalysisProtocolError("scrcpy MCP refused the operation", {
          diagnostics: {
            upstream_tool: name,
            upstream_response: jsonValueSchema.parse(result),
          },
        });
      for (const text of mcpTextBlocks(envelope.content)) {
        const payload = parseMcpJsonOrText(text);
        if (
          typeof payload === "object" &&
          payload !== null &&
          !Array.isArray(payload) &&
          (payload.error === true || payload.status === "error")
        )
          throw new AnalysisProtocolError(
            "scrcpy MCP returned a failure envelope",
            {
              diagnostics: { upstream_tool: name, upstream_response: payload },
            },
          );
      }
      return jsonValueSchema.parse(result);
    },
    async close() {
      await transport.close();
      connected = false;
      client = new Client({ name: "rea-scrcpy-provider", version: "1" });
      transport = makeTransport();
    },
  };
};
