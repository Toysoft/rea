import { describe, expect, it } from "vitest";

import { createCli } from "../../../src/cli.js";
import { createCliInventory } from "../../../scripts/lib/catalog-cli.mjs";
import { TOOL_CONTRACTS } from "../../../src/contracts/toolContracts.js";
import {
  CLI_COMMAND_TOOL_ALIASES,
  MCP_ONLY_TOOL_REASONS,
} from "../../../src/contracts/toolCliReachability.js";
import { CLI_COMMAND_NAMES } from "../../../src/cliCommandNames.js";

describe("CLI canonical tool coverage", () => {
  it("reaches every MCP tool through a registered CLI command or declares why it is MCP-only", () => {
    const registeredCli = createCliInventory(createCli());
    const registeredCommandNames = new Set([
      ...registeredCli.primary,
      ...registeredCli.aliases.map(({ name }) => name),
    ]);
    for (const command of CLI_COMMAND_NAMES)
      expect(registeredCommandNames.has(command), command).toBe(true);
    for (const { name, cliReachability } of TOOL_CONTRACTS)
      if ("commands" in cliReachability)
        for (const command of cliReachability.commands)
          expect(
            registeredCommandNames.has(command),
            `${name}: ${command}`,
          ).toBe(true);
      else expect(cliReachability.mcpOnlyReason.trim(), name).not.toBe("");
  });

  it("declares CLI aliases and MCP-only reasons only for public tools", () => {
    const names = new Set<string>(TOOL_CONTRACTS.map(({ name }) => name));
    expect(
      [
        ...Object.values(CLI_COMMAND_TOOL_ALIASES).flat(),
        ...Object.keys(MCP_ONLY_TOOL_REASONS),
      ].filter((name) => !names.has(name)),
    ).toEqual([]);
  });
});
