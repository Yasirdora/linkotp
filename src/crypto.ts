/**
 * Cryptographic primitives.
 *
 * Built exclusively on Web Crypto (`globalThis.crypto`), which is present in
 * Node 18+, Bun, Deno, Cloudflare Workers, Vercel Edge, and browsers. No Node
 * built-ins, no polyfills, no dependencies.
 */

import { LinkOtpError } from "./errors.ts";

/** Resolves Web Crypto, failing loudly rather than silently degrading. */
function webCrypto(): Crypto {
    const subtle = globalThis.crypto?.subtle;
    if (!globalThis.crypto?.getRandomValues || !subtle) {
        throw new LinkOtpError(
            "configuration_error",
            "Web Crypto is unavailable. linkotp requires globalThis.crypto with " +
                "getRandomValues and subtle — Node 18+, Bun, Deno, Cloudflare " +
                "Workers, Vercel Edge, or a browser. On Node 16 and below, no " +
                "supported polyfill exists; upgrade the runtime.",
        );
    }
    return globalThis.crypto;
}

/**
 * Cryptographically secure random string over an arbitrary alphabet.
 *
 * Uses rejection sampling rather than `byte % alphabet.length`. A naive
 * modulo biases the leading `256 % alphabet.length` characters: for a
 * 62-character alphabet, bytes 0..7 map to two source values while 8..61 map
 * to one, making the first eight characters ~1.25x more likely than the rest.
 * That is a real, measurable reduction in effective entropy. Bytes at or
 * above the largest clean multiple of the alphabet size are discarded and
 * redrawn instead, which costs a negligible number of extra random bytes and
 * yields a provably uniform distribution.
 */
export function randomString(length: number, alphabet: string): string {
    if (!Number.isInteger(length) || length <= 0) {
        throw new LinkOtpError("configuration_error", "length must be a positive integer");
    }
    if (alphabet.length < 2 || alphabet.length > 256) {
        throw new LinkOtpError(
            "configuration_error",
            "alphabet must contain between 2 and 256 characters",
        );
    }
    if (new Set(alphabet).size !== alphabet.length) {
        throw new LinkOtpError(
            "configuration_error",
            "alphabet must not contain duplicate characters — duplicates skew the " +
                "output distribution and overstate the entropy of generated secrets",
        );
    }

    const crypto = webCrypto();
    const ceiling = 256 - (256 % alphabet.length);
    const out: string[] = [];

    while (out.length < length) {
        const bytes = crypto.getRandomValues(new Uint8Array(length - out.length));
        for (const byte of bytes) {
            if (byte < ceiling) {
                out.push(alphabet[byte % alphabet.length]!);
                if (out.length === length) break;
            }
        }
    }

    return out.join("");
}

/** Shannon entropy, in bits, of a secret drawn uniformly from `alphabet`. */
export function entropyBits(length: number, alphabetSize: number): number {
    return length * Math.log2(alphabetSize);
}

/** Opaque, collision-resistant identifier for a challenge row. */
export function randomId(): string {
    return randomString(24, "abcdefghijklmnopqrstuvwxyz0123456789");
}

/** Namespace separating the three digest keyspaces. See {@link createHasher}. */
export type DigestDomain = "code" | "token" | "binding";

export interface Hasher {
    (domain: DigestDomain, value: string): Promise<string>;
}

/**
 * Builds a keyed-digest function bound to one application secret.
 *
 * ## Why HMAC and not a bare hash
 *
 * One of the two secrets we persist is a six-character code — roughly 30 bits.
 * A plain SHA-256 of that falls to an offline dictionary attack the instant
 * the table leaks: the entire keyspace is about 10^9 digests, minutes of GPU
 * time. Keying the digest with a secret held outside the database means a
 * database compromise alone yields nothing, because the attacker also needs
 * the application secret from the environment. This is the same reasoning
 * behind peppering a password hash, and it is why linkotp requires a secret
 * rather than treating one as optional.
 *
 * ## Why a domain separator
 *
 * The digest input is prefixed with a versioned domain tag so a digest
 * computed over a code can never collide with, or be replayed as, a digest
 * over a link token or a binding value — even though all three share one key.
 * The `v1` marker lets a future release change the construction without
 * silently validating legacy digests.
 *
 * The derived HMAC key is cached for the lifetime of the returned function,
 * so the per-call cost is one `subtle.sign` rather than an `importKey` too.
 */
export function createHasher(secret: string): Hasher {
    const encoder = new TextEncoder();
    const crypto = webCrypto();

    // Imported once, lazily, and shared by every call. Held as a promise so
    // concurrent first-calls await the same import rather than racing.
    let keyPromise: Promise<CryptoKey> | undefined;
    const key = (): Promise<CryptoKey> => {
        keyPromise ??= crypto.subtle.importKey(
            "raw",
            encoder.encode(secret),
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"],
        );
        return keyPromise;
    };

    return async (domain, value) => {
        const signature = await crypto.subtle.sign(
            "HMAC",
            await key(),
            encoder.encode(`linkotp:v1:${domain}:${value}`),
        );
        return toHex(new Uint8Array(signature));
    };
}

const HEX = "0123456789abcdef";

function toHex(bytes: Uint8Array): string {
    let out = "";
    for (const byte of bytes) {
        out += HEX[byte >> 4]! + HEX[byte & 0x0f]!;
    }
    return out;
}

/**
 * Content-constant-time comparison of two hex digests.
 *
 * Both operands are always SHA-256 digests of identical, publicly known
 * length, so the early length check leaks nothing an attacker does not
 * already know. The comparison itself accumulates differences across every
 * character rather than returning at the first mismatch, so the runtime does
 * not reveal how many leading characters were correct.
 *
 * This matters for the device-binding check, where one operand is derived
 * from an attacker-supplied cookie. It is deliberately *not* used for code
 * and token lookup: those are resolved by an indexed database predicate,
 * whose timing characteristics we do not control and which is safe here
 * precisely because the stored values are high-entropy keyed digests.
 */
export function timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let mismatch = 0;
    for (let i = 0; i < a.length; i++) {
        mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return mismatch === 0;
}
