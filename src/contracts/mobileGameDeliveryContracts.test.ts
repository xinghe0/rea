import { Ajv2020 } from "ajv/dist/2020.js";
import { Ajv } from "ajv";
import { expect, it } from "vitest";
import { toolContract } from "./toolContracts.js";
import {
  toolInputSchemaWithMetadata,
  toolOutputSchemaWithMetadata,
} from "./toolSchemaMetadata.js";

it.each(["draft-2020-12", "draft-07"] as const)(
  "advertises valid mobile contracts after SDK conversion in %s",
  (target) => {
    const ajv =
      target === "draft-2020-12"
        ? new Ajv2020({ strict: false, validateFormats: false })
        : new Ajv({ strict: false, validateFormats: false });
    for (const name of [
      "assess_mobile_game",
      "convert_game_resources",
      "inspect_game_case",
      "report_game_case",
      "decode_game_protocol",
      "inspect_scrcpy_client",
      "observe_scrcpy_device",
      "control_scrcpy_device",
    ] as const) {
      const contract = toolContract(name);
      const schema = toolInputSchemaWithMetadata(contract)[
        "~standard"
      ].jsonSchema.input({ target });
      expect(ajv.validateSchema(schema), name).toBe(true);
      const validate = ajv.compile(schema);
      for (const example of contract.examples)
        expect(
          validate(example.input),
          `${name}: ${JSON.stringify(validate.errors)}`,
        ).toBe(true);
      const output = toolOutputSchemaWithMetadata(contract)[
        "~standard"
      ].jsonSchema.output({ target });
      expect(ajv.validateSchema(output), name).toBe(true);
    }
  },
);
