/**
 * In-memory sliding-window rate limiter.
 *
 * Suitable for a single process: a CLI, a test suite, a container that does
 * not scale horizontally. It is explicitly *not* suitable behind a load
 * balancer, because each instance keeps its own counters and the effective
 * limit multiplies by the instance count. Serverless platforms that recycle
 * isolates per request will find it does nothing at all.
 *
 * For anything distributed, implement `RateLimiter` over Redis, Cloudflare's
 * rate limiting binding, a Durable Object, or your gateway. The interface is
 * one method.
 */

import type { RateLimiter, RateLimitVerdict } from "./types.ts";

export interface MemoryRateLimiterOptions {
    /** Requests permitted per window. */
    readonly limit: number;
    /** Window length in seconds. */
    readonly windowSeconds: number;
    /**
     * Cap on distinct keys held at once. Once reached, the least recently
     * touched keys are evicted. This bounds memory against an attacker who
     * rotates keys to grow the map without bound.
     * @default 10000
     */
    readonly maxKeys?: number;
}

/**
 * Sliding window over per-key timestamps.
 *
 * A fixed window lets a caller send `limit` requests at the very end of one
 * window and `limit` more at the start of the next, briefly doubling the
 * intended rate. Retaining timestamps and expiring them individually costs
 * more memory but enforces the limit the configuration actually promises.
 */
export function createMemoryRateLimiter(options: MemoryRateLimiterOptions): RateLimiter {
    const { limit, windowSeconds } = options;
    const maxKeys = options.maxKeys ?? 10_000;

    if (!Number.isInteger(limit) || limit < 1) {
        throw new RangeError("limit must be a positive integer");
    }
    if (!Number.isFinite(windowSeconds) || windowSeconds <= 0) {
        throw new RangeError("windowSeconds must be positive");
    }

    const windowMs = windowSeconds * 1000;
    // Map preserves insertion order, which gives LRU eviction for free as
    // long as touched keys are re-inserted at the tail.
    const hits = new Map<string, number[]>();

    return {
        async check(key: string, now: number): Promise<RateLimitVerdict> {
            const cutoff = now - windowMs;
            const previous = hits.get(key);
            const live = previous ? previous.filter((t) => t > cutoff) : [];

            if (live.length >= limit) {
                const oldest = live[0]!;
                hits.delete(key);
                hits.set(key, live);
                return {
                    allowed: false,
                    retryAfter: Math.max(1, Math.ceil((oldest + windowMs - now) / 1000)),
                };
            }

            live.push(now);
            hits.delete(key);
            hits.set(key, live);

            if (hits.size > maxKeys) {
                const oldestKey = hits.keys().next().value;
                if (oldestKey !== undefined) hits.delete(oldestKey);
            }

            return { allowed: true };
        },
    };
}
