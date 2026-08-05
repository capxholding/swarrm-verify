/* tslint:disable */
/* eslint-disable */

/**
 * Verify a bundle passed as a JSON string. Returns "VERIFIED" /
 * "NOT VERIFIED" / "ERROR: <reason>". For the file-drop static page.
 */
export function verify_bundle_json(json: string): string;

/**
 * Verify certificate bytes (bare core or view envelope) and return the JSON
 * result dict `{parse_ok, layers, certificate_id, core_present,
 * cross_checks_ok, vector, mark, errors}` — same shape as Python's
 * `verify_certificate`. Total on hostile input: never panics. With the
 * `wasm` feature this same symbol is the wasm export for the static page.
 */
export function verify_certificate_cbor(bytes: Uint8Array): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly verify_certificate_cbor: (a: number, b: number) => [number, number];
    readonly verify_bundle_json: (a: number, b: number) => [number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
