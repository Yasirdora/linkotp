/**
 * Minimal ambient declarations for the Node built-ins used by the test suite.
 *
 * otplink has zero runtime dependencies and exactly one devDependency
 * (`typescript`). Pulling in `@types/node` purely so the tests can import
 * `node:test` would double that count for no benefit to consumers, so the
 * handful of signatures we actually use are declared here instead.
 *
 * `src/` imports no Node built-ins at all — it targets Web Standard APIs
 * (`crypto`, `Request`, `Response`, `TextEncoder`) so the library runs
 * unchanged on Node, Bun, Deno, Cloudflare Workers, and Vercel Edge. These
 * declarations therefore never leak into the published type surface.
 */

declare module "node:test" {
    type TestFn = () => void | Promise<void>;
    interface TestOptions {
        /** A string reason marks the test skipped and is reported as such. */
        skip?: boolean | string;
        todo?: boolean | string;
        concurrency?: number | boolean;
        timeout?: number;
    }
    export function test(name: string, fn: TestFn): Promise<void>;
    export function test(name: string, options: TestOptions, fn: TestFn): Promise<void>;
    export function describe(name: string, fn: () => void): void;
    export function it(name: string, fn: TestFn): void;
    export function it(name: string, options: TestOptions, fn: TestFn): void;
    export function before(fn: TestFn): void;
    export function after(fn: TestFn): void;
    export function beforeEach(fn: TestFn): void;
    export function afterEach(fn: TestFn): void;
}

declare module "node:assert/strict" {
    interface AssertStrict {
        (value: unknown, message?: string): asserts value;
        equal(actual: unknown, expected: unknown, message?: string): void;
        notEqual(actual: unknown, expected: unknown, message?: string): void;
        deepEqual(actual: unknown, expected: unknown, message?: string): void;
        ok(value: unknown, message?: string): asserts value;
        match(value: string, pattern: RegExp, message?: string): void;
        fail(message?: string): never;
        throws(fn: () => unknown, expected?: unknown, message?: string): void;
        doesNotThrow(fn: () => unknown, message?: string): void;
        rejects(
            fn: (() => Promise<unknown>) | Promise<unknown>,
            expected?: unknown,
            message?: string,
        ): Promise<void>;
    }
    const assert: AssertStrict;
    export default assert;
}

declare module "node:sqlite" {
    interface StatementSync {
        all(...params: unknown[]): Record<string, unknown>[];
        run(...params: unknown[]): { changes: number; lastInsertRowid: number };
        get(...params: unknown[]): Record<string, unknown> | undefined;
    }
    export class DatabaseSync {
        constructor(path: string);
        exec(sql: string): void;
        prepare(sql: string): StatementSync;
        close(): void;
    }
}

declare module "node:fs" {
    export function existsSync(path: string): boolean;
}

declare module "node:path" {
    export function resolve(...parts: string[]): string;
    export function dirname(path: string): string;
    export function join(...parts: string[]): string;
}

declare module "node:url" {
    export function fileURLToPath(url: string | URL): string;
}

declare module "node:module" {
    export function createRequire(path: string | URL): (id: string) => unknown;
}

/*
 * Used only by examples/minimal-server.ts, which converts between Node's
 * stream-based server and the Fetch API. Nothing in src/ imports these.
 */

declare module "node:http" {
    export interface IncomingMessage extends AsyncIterable<Uint8Array> {
        url?: string | undefined;
        method?: string | undefined;
        headers: Record<string, string | string[] | undefined>;
    }
    export interface ServerResponse {
        setHeader(name: string, value: string | readonly string[]): void;
        writeHead(status: number, headers?: Record<string, string>): ServerResponse;
        end(chunk?: unknown): void;
    }
    export interface Server {
        listen(port: number, callback?: () => void): Server;
    }
    export function createServer(
        handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>,
    ): Server;
}

declare module "node:stream" {
    export class Readable {
        static fromWeb(stream: unknown): { pipe(destination: unknown): void };
    }
}
