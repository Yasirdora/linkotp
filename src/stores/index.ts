/**
 * Bundled {@link TokenStore} implementations.
 *
 * Neither is required: the interface is six methods, and anything satisfying
 * it works. Run `checkStoreConformance` from `linkotp/testing` against a
 * custom one before trusting it.
 */

export { createMemoryStore } from "./memory.ts";
export type { MemoryStore } from "./memory.ts";

export { createSqlStore, schemaFor } from "./sql.ts";
export type { SqlDialect, SqlDriver, SqlStoreOptions } from "./sql.ts";
