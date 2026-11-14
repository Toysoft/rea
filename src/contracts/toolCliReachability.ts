import { CLI_COMMAND_NAMES, type CLI_COMMANDS } from "../cliCommandNames.js";

type CliCommandName = (typeof CLI_COMMANDS)[keyof typeof CLI_COMMANDS];

/** One-shot CLI commands that reach a public tool, or why only MCP serves it. */
export type ToolCliReachability =
  | { readonly commands: readonly [CliCommandName, ...CliCommandName[]] }
  | { readonly mcpOnlyReason: string };

/** Canonical MCP operations reached by CLI commands with different names. */
export const CLI_COMMAND_TOOL_ALIASES: Readonly<
  Partial<Record<CliCommandName, readonly string[]>>
> = {
  "environment-build": ["export_environment_bundle"],
  guidance: ["search_guidance", "read_guidance_section"],
  analyze: ["binary_overview"],
  inspect: ["binary_overview"],
  decompile: ["procedure_pseudo_code"],
  function: ["analyze_function"],
  instructions: ["read_function_instructions"],
  trace: ["trace_feature"],
  search: ["search_strings", "search_procedures"],
  "capture-process": ["capture_process_scenario"],
  compare: ["compare_bundles"],
  "list-objdump-architectures": ["inspect_with_objdump"],
  "debug-with-gdb": ["gdb_console"],
  "debug-with-rizin": ["rizin_debug_command"],
};

const SERVER_SETTINGS =
  "Runtime settings belong to the long-lived MCP server; CLI calls use launch/per-call controls.";
const RESOURCE_ROOT =
  "MCP session control selects a resource root; CLI resource commands take paths directly.";
const ACTIVE_TARGET =
  "Uses or manages the active target the MCP session holds between calls; CLI analysis commands open their own target per call.";
const INVESTIGATION_RESET =
  "Investigation reset acts on the long-lived MCP server's retained history.";
const RETAINED_EVIDENCE =
  "Works with Evidence and Unknowns the MCP session retains between calls; CLI Evidence commands take bundle files and retain nothing.";
const LIVE_SESSION =
  "Controls a debugger or instrumentation session the MCP server keeps between calls; CLI debugger and Frida commands run one ephemeral session per call.";
const BUILD_COMPUTER =
  "Build computers are held by the long-lived MCP server between actions.";

/** MCP operations without a dedicated CLI command or command alias. */
export const MCP_ONLY_TOOL_REASONS: Readonly<Record<string, string>> = {
  inspect_analysis_settings: SERVER_SETTINGS,
  update_analysis_settings: SERVER_SETTINGS,
  open_bundle_resources: RESOURCE_ROOT,
  address_name: ACTIVE_TARGET,
  comment: ACTIVE_TARGET,
  current_address: ACTIVE_TARGET,
  current_procedure: ACTIVE_TARGET,
  current_document: ACTIVE_TARGET,
  goto_address: ACTIVE_TARGET,
  inline_comment: ACTIVE_TARGET,
  list_bookmarks: ACTIVE_TARGET,
  list_documents: ACTIVE_TARGET,
  list_names: ACTIVE_TARGET,
  list_procedures: ACTIVE_TARGET,
  list_segments: ACTIVE_TARGET,
  list_strings: ACTIVE_TARGET,
  next_address: ACTIVE_TARGET,
  prev_address: ACTIVE_TARGET,
  procedure_address: ACTIVE_TARGET,
  procedure_assembly: ACTIVE_TARGET,
  procedure_callees: ACTIVE_TARGET,
  procedure_callers: ACTIVE_TARGET,
  procedure_info: ACTIVE_TARGET,
  resolve_containing_procedure: ACTIVE_TARGET,
  set_address_name: ACTIVE_TARGET,
  set_addresses_names: ACTIVE_TARGET,
  set_bookmark: ACTIVE_TARGET,
  set_comment: ACTIVE_TARGET,
  set_inline_comment: ACTIVE_TARGET,
  unset_bookmark: ACTIVE_TARGET,
  get_objc_classes: ACTIVE_TARGET,
  get_objc_protocols: ACTIVE_TARGET,
  batch_decompile: ACTIVE_TARGET,
  get_call_graph: ACTIVE_TARGET,
  analyze_swift_types: ACTIVE_TARGET,
  find_xrefs_to_name: ACTIVE_TARGET,
  trace_call_path: ACTIVE_TARGET,
  open_binary: ACTIVE_TARGET,
  close_binary: ACTIVE_TARGET,
  binary_session: ACTIVE_TARGET,
  get_navigation_context: ACTIVE_TARGET,
  inspect_address_context: ACTIVE_TARGET,
  reset_investigation: INVESTIGATION_RESET,
  export_evidence_bundle: RETAINED_EVIDENCE,
  import_evidence_bundle: RETAINED_EVIDENCE,
  compare_functions: RETAINED_EVIDENCE,
  find_changed_behavior: RETAINED_EVIDENCE,
  build_call_path: RETAINED_EVIDENCE,
  correlate_static_and_runtime: RETAINED_EVIDENCE,
  verify_reconstruction: RETAINED_EVIDENCE,
  list_unknowns: RETAINED_EVIDENCE,
  record_unknown: RETAINED_EVIDENCE,
  update_unknown: RETAINED_EVIDENCE,
  verify_unknown_resolution: RETAINED_EVIDENCE,
  get_evidence_bundle: RETAINED_EVIDENCE,
  start_gdb_session: LIVE_SESSION,
  gdb_session_status: LIVE_SESSION,
  close_gdb_session: LIVE_SESSION,
  start_rizin_debug_session: LIVE_SESSION,
  rizin_debug_session_status: LIVE_SESSION,
  close_rizin_debug_session: LIVE_SESSION,
  start_frida_session: LIVE_SESSION,
  load_frida_script: LIVE_SESSION,
  resume_frida_session: LIVE_SESSION,
  unload_frida_script: LIVE_SESSION,
  frida_session_status: LIVE_SESSION,
  close_frida_session: LIVE_SESSION,
  start_build_computer: BUILD_COMPUTER,
  act_on_build_computer: BUILD_COMPUTER,
  close_build_computer: BUILD_COMPUTER,
  start_build_capture: BUILD_COMPUTER,
  mark_build_checkpoint: BUILD_COMPUTER,
  stop_build_capture: BUILD_COMPUTER,
  export_build_environment: BUILD_COMPUTER,
  check_build_task: BUILD_COMPUTER,
  measure_build_task: BUILD_COMPUTER,
  record_build_consent: BUILD_COMPUTER,
};

/**
 * Resolve how the CLI reaches one public tool: its kebab-case command, an
 * aliased command, or a declared MCP-only reason. An undeclared tool fails
 * closed, like an unaudited effect.
 */
export const toolCliReachability = (name: string): ToolCliReachability => {
  const reason = MCP_ONLY_TOOL_REASONS[name];
  const [command, ...commands] = CLI_COMMAND_NAMES.filter(
    (candidate) =>
      candidate === name.replaceAll("_", "-") ||
      CLI_COMMAND_TOOL_ALIASES[candidate]?.includes(name) === true,
  );
  if (command === undefined) {
    if (reason === undefined)
      throw new Error(`Missing CLI reachability for ${name}`);
    return { mcpOnlyReason: reason };
  }
  if (reason !== undefined)
    throw new Error(`${name} has a CLI command and an MCP-only reason`);
  return { commands: [command, ...commands] };
};
