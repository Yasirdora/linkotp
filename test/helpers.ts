/** Shared fixtures. Not a test file, so the runner's glob skips it. */

import { createOtpLink, type OtpLink } from "../src/core.ts";
import type { OtpLinkOptions } from "../src/config.ts";
import { createMemoryStore, type MemoryStore } from "../src/stores/memory.ts";
import type { MailerMessage } from "../src/types.ts";

export const SECRET = "test-secret-that-is-at-least-32-characters-long";
export const BASE_URL = "https://example.com";
export const NOW = 1_700_000_000_000;

export interface Harness {
    auth: OtpLink;
    store: MemoryStore;
    sent: MailerMessage[];
    /** Advances the fake clock. */
    advance(ms: number): void;
    /** The code from the most recent message, recovered from its plain-text part. */
    lastCode(): string;
    /** The token from the most recent message, recovered from its link. */
    lastToken(): string;
}

export function harness(overrides: Partial<OtpLinkOptions> = {}): Harness {
    const store = createMemoryStore();
    const sent: MailerMessage[] = [];
    let now = NOW;

    const auth = createOtpLink({
        secret: SECRET,
        baseUrl: BASE_URL,
        store,
        mailer: async (message) => {
            sent.push(message);
        },
        clock: () => now,
        // Tests must not wait half a second per start; the equalization
        // behaviour itself is covered explicitly in core.test.ts.
        minimumStartDurationMs: 0,
        ...overrides,
    });

    return {
        auth,
        store,
        sent,
        advance: (ms) => {
            now += ms;
        },
        lastCode() {
            const message = sent.at(-1);
            if (!message) throw new Error("no message was sent");
            const match = /\n {4}([A-Z0-9 ]+)\n/.exec(message.text);
            if (!match) throw new Error("no code found in the message body");
            return match[1]!.replace(/ /g, "");
        },
        lastToken() {
            const message = sent.at(-1);
            if (!message) throw new Error("no message was sent");
            const match = /token=([A-Za-z0-9]+)/.exec(message.text);
            if (!match) throw new Error("no token found in the message body");
            return match[1]!;
        },
    };
}

/** Asserts that `fn` throws an OtpLinkError carrying `code`. */
export async function expectError(fn: () => Promise<unknown>, code: string): Promise<void> {
    try {
        await fn();
    } catch (error) {
        const actual = (error as { code?: string }).code;
        if (actual !== code) {
            throw new Error(`expected error code ${code}, got ${actual ?? String(error)}`);
        }
        return;
    }
    throw new Error(`expected the call to throw ${code}, but it resolved`);
}
