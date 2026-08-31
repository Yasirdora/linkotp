/**
 * In-memory store.
 *
 * For tests, local development, and single-process deployments where losing
 * pending challenges on restart is acceptable (the user simply requests a new
 * code). Not for anything horizontally scaled: a challenge issued by one
 * instance is invisible to every other.
 */

import type {
    Challenge,
    ConsumeQuery,
    FailedAttemptOutcome,
    Purpose,
    TokenStore,
} from "../types.ts";

export interface MemoryStore extends TokenStore {
    /** Live row count, including consumed rows not yet swept. */
    size(): number;
    /** Drops everything. Test helper. */
    clear(): void;
}

/**
 * Atomicity note.
 *
 * JavaScript runs one job to completion before starting the next, so any
 * sequence of statements containing no `await` is atomic with respect to
 * other tasks. The mutating methods below are declared `async` to satisfy the
 * interface but contain no internal suspension points, which is what makes
 * the compare-and-set genuinely indivisible. Introducing an `await` between
 * the guard check and the write would reopen exactly the race the interface
 * forbids, so it must not be done casually.
 */
export function createMemoryStore(): MemoryStore {
    const byId = new Map<string, Challenge>();
    const idByToken = new Map<string, string>();

    const isLive = (challenge: Challenge, now: number): boolean =>
        challenge.consumedAt === null &&
        challenge.expiresAt > now &&
        challenge.attempts < challenge.maxAttempts;

    return {
        async insert(challenge: Challenge): Promise<void> {
            if (byId.has(challenge.id)) {
                throw new Error(`linkotp: duplicate challenge id ${challenge.id}`);
            }
            if (idByToken.has(challenge.tokenHash)) {
                throw new Error("linkotp: duplicate token hash");
            }
            byId.set(challenge.id, challenge);
            idByToken.set(challenge.tokenHash, challenge.id);
        },

        async consume(query: ConsumeQuery): Promise<Challenge | null> {
            let target: Challenge | undefined;

            if (query.by === "token") {
                const id = idByToken.get(query.tokenHash);
                target = id === undefined ? undefined : byId.get(id);
            } else {
                for (const candidate of byId.values()) {
                    if (
                        candidate.email === query.email &&
                        candidate.purpose === query.purpose &&
                        candidate.codeHash === query.codeHash
                    ) {
                        target = candidate;
                        break;
                    }
                }
            }

            if (!target || !isLive(target, query.now)) return null;

            const consumed: Challenge = Object.freeze({ ...target, consumedAt: query.now });
            byId.set(consumed.id, consumed);
            return consumed;
        },

        async registerFailedAttempt(query: {
            email: string;
            purpose: Purpose;
            now: number;
        }): Promise<FailedAttemptOutcome> {
            let found = false;
            let remaining = 0;

            for (const candidate of byId.values()) {
                // `found` deliberately ignores the attempt budget: a challenge
                // whose budget is spent still exists, and saying so is what
                // lets the caller distinguish exhaustion from absence.
                if (
                    candidate.email !== query.email ||
                    candidate.purpose !== query.purpose ||
                    candidate.consumedAt !== null ||
                    candidate.expiresAt <= query.now
                ) {
                    continue;
                }
                found = true;

                const canIncrement = candidate.attempts < candidate.maxAttempts;
                const updated: Challenge = canIncrement
                    ? Object.freeze({ ...candidate, attempts: candidate.attempts + 1 })
                    : candidate;
                if (canIncrement) byId.set(updated.id, updated);

                remaining = Math.max(remaining, updated.maxAttempts - updated.attempts);
            }

            return { found, remaining: Math.max(0, remaining) };
        },

        async delete(id: string): Promise<void> {
            const existing = byId.get(id);
            if (!existing) return;
            byId.delete(id);
            idByToken.delete(existing.tokenHash);
        },

        async countIssuedSince(query: {
            email: string;
            purpose: Purpose;
            since: number;
        }): Promise<number> {
            let count = 0;
            for (const candidate of byId.values()) {
                if (
                    candidate.email === query.email &&
                    candidate.purpose === query.purpose &&
                    candidate.createdAt >= query.since
                ) {
                    count++;
                }
            }
            return count;
        },

        async deleteExpired(now: number): Promise<number> {
            let removed = 0;
            for (const [id, candidate] of byId) {
                if (candidate.expiresAt <= now) {
                    byId.delete(id);
                    idByToken.delete(candidate.tokenHash);
                    removed++;
                }
            }
            return removed;
        },

        size: () => byId.size,

        clear: () => {
            byId.clear();
            idByToken.clear();
        },
    };
}
