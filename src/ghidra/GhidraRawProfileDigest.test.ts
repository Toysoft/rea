import { describe, expect, it } from "vitest";

import { parseConfig } from "../config/parseConfig.js";
import {
  createAnalysisProfile,
  type AnalysisProfileCommitment,
} from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { silentLogger } from "../logger.js";
import { ghidraProfileInstallationHost as host } from "./GhidraInstallation.fixture.js";
import { GhidraProvider } from "./GhidraProvider.js";

const configFor = (environment: NodeJS.ProcessEnv) => {
  const parsed = parseConfig({ GHIDRA_INSTALL_DIR: "/ghidra", ...environment });
  if (!parsed.ok) throw parsed.error;
  return parsed.value;
};

const raw = (architecture: "6502" | "x86", entryPoint: string): BinaryTarget =>
  ({
    path: "/tmp/raw.bin",
    sha256: "a".repeat(64),
    kind: "executable",
    format: "raw-binary",
    architecture,
    availableArchitectures: [architecture],
    entryPoint,
    entryPointSource: entryPoint,
  }) as unknown as BinaryTarget;

const resolveProfile = async (
  environment: NodeJS.ProcessEnv,
  target: BinaryTarget,
): Promise<AnalysisProfileCommitment> => {
  const ghidra = new GhidraProvider(
    configFor(environment),
    silentLogger,
    {},
    host,
  );
  const resolved = await ghidra.resolveAnalysisProfile(target);
  if (!resolved.ok) throw resolved.error;
  const { profile } = resolved.value;
  if (profile === null) throw new Error("Ghidra committed no raw profile");
  return profile;
};

/**
 * Snapshots with earlier results stay reusable unless the digest changes, so
 * bumping any committed `-v<N>` policy revision must change it.
 */
const expectDigestCommitsEachRevision = ({
  provider,
  parameters,
  digest,
}: AnalysisProfileCommitment): void => {
  expect(createAnalysisProfile(provider, parameters).digest).toBe(digest);
  const revisions = Object.entries(parameters).flatMap(([key, value]) =>
    typeof value === "string" && /-v\d+$/u.test(value) ? [{ key, value }] : [],
  );
  expect(revisions).not.toHaveLength(0);
  for (const { key, value } of revisions) {
    const bumped = value.replace(
      /-v(\d+)$/u,
      (_revision, number: string) => `-v${Number(number) + 1}`,
    );
    expect(
      createAnalysisProfile(provider, { ...parameters, [key]: bumped }).digest,
      key,
    ).not.toBe(digest);
  }
};

describe("raw-binary analysis profile digest", () => {
  it("commits the 6502 raw profile to the current shared policy", async () => {
    const target = raw("6502", "0x8001");
    const profile = await resolveProfile({}, target);
    expect((await resolveProfile({}, target)).digest).toBe(profile.digest);
    expectDigestCommitsEachRevision(profile);
    expect(profile.parameters).toMatchObject({
      target_format: "raw-binary",
      loader: "BinaryLoader",
      language_id: "6502:LE:16:default",
      language_selection: "caller-supplied-v1",
      load_image_evidence: "independent-raw-mapping-context-v4",
      load_image_observations:
        "source-mappings-entry-context-relocation-symbol-v3",
      instruction_status: "unlisted-and-containing-code-data-v3",
      inventory_search_projection: "provider-inventory-facts-v1",
      value_flow_effect_scope: "pcode-load-store-explicit-v1",
      native_value_flow_projection: "accepted-runtime-budgets-v1",
      byte_search_boundary: "contiguous-eligible-initialized-blocks-v1",
      byte_search_coverage: "separate-loaded-overlays-v1",
      data_type_observations: "bit-field-base-and-lookup-v1",
      instruction_references:
        "exact-address-incoming-without-synthetic-entry-v3",
      analyzer_preset: "ghidra-default",
    });
  });

  it("commits disabled analyzers to the raw digest and its analysis options", async () => {
    const environment = {
      REA_GHIDRA_DISABLED_ANALYZERS: "Aggressive Instruction Finder",
    };
    const target = raw("x86", "0x1000");
    const profile = await resolveProfile(environment, target);
    expect((await resolveProfile(environment, target)).digest).toBe(
      profile.digest,
    );
    expect((await resolveProfile({}, target)).digest).not.toBe(profile.digest);
    expectDigestCommitsEachRevision(profile);
    expect(profile.parameters).toMatchObject({
      inventory_search_projection: "provider-inventory-facts-v1",
      value_flow_effect_scope: "pcode-load-store-explicit-v1",
      native_value_flow_projection: "accepted-runtime-budgets-v1",
      byte_search_coverage: "separate-loaded-overlays-v1",
      analysis_options: {
        disabled_analyzers: ["Aggressive Instruction Finder"],
      },
    });
  });
});
