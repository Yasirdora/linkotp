/**
 * Request validators, built on the Standard Schema interface.
 *
 * Better Auth's endpoint layer types `body` and `query` as `StandardSchemaV1`
 * — the vendor-neutral interface, not Zod specifically. Zod is simply what
 * Better Auth's own plugins happen to pass. Implementing the interface
 * directly means the plugin gets real 400-level validation, OpenAPI
 * generation, and client-side type inference without linkotp taking on a
 * validation dependency it has spent its whole existence avoiding.
 *
 * The interface is small enough to implement correctly in one file: a
 * `~standard` property carrying a `validate` function that returns either
 * `{ value }` or `{ issues }`.
 *
 * @see https://standardschema.dev
 */

/** Structural mirror of `StandardSchemaV1`, declared rather than imported. */
export interface StandardSchema<Output> {
    readonly "~standard": {
        readonly version: 1;
        readonly vendor: string;
        readonly validate: (value: unknown) => StandardResult<Output>;
        readonly types?: { readonly input: Output; readonly output: Output } | undefined;
    };
}

export type StandardResult<Output> =
    | { readonly value: Output; readonly issues?: undefined }
    | { readonly issues: ReadonlyArray<{ readonly message: string; readonly path?: string[] }> };

/**
 * One property of an object schema.
 *
 * `Optional` is a *literal* type parameter rather than only a runtime field,
 * and that is load-bearing. {@link Infer} decides whether a key is required
 * by asking whether `optional` extends `true`, and a plain `boolean` extends
 * neither `true` nor `false` — so carrying optionality only as a value would
 * silently sort every field into the required bucket. The visible symptom is
 * a caller being told to supply `callbackURL`, `name` and `metadata` on a
 * request that needs none of them.
 */
export interface Field<T = unknown, Optional extends boolean = boolean> {
    readonly optional: Optional;
    /** Describes the field for OpenAPI output. */
    readonly description: string;
    parse(value: unknown): { ok: true; value: T } | { ok: false; message: string };
}

interface StringFieldOptions {
    readonly description: string;
    /**
     * Upper bound on accepted length.
     *
     * Not cosmetic. Every string here is fed to an HMAC, and an unbounded
     * body would let a caller spend server CPU hashing megabytes before any
     * rate limiter has a verdict. The bounds are generous multiples of the
     * real values.
     */
    readonly maxLength: number;
    /** @default 1 */
    readonly minLength?: number;
}

export function string(options: StringFieldOptions): Field<string, false> {
    const min = options.minLength ?? 1;
    return {
        optional: false,
        description: options.description,
        parse(value) {
            if (typeof value !== "string") return { ok: false, message: "must be a string" };
            // Trimmed before measuring so a field of spaces is empty, not
            // "long enough". The protocol normalizes again downstream; this
            // is only about rejecting obvious junk early.
            const trimmed = value.trim();
            if (trimmed.length < min) return { ok: false, message: "is required" };
            if (trimmed.length > options.maxLength) {
                return { ok: false, message: `must be at most ${options.maxLength} characters` };
            }
            return { ok: true, value: trimmed };
        },
    };
}

/** A JSON object passed through verbatim, for caller metadata. */
export function record(description: string): Field<Record<string, unknown>, false> {
    return {
        optional: false,
        description,
        parse(value) {
            if (typeof value !== "object" || value === null || Array.isArray(value)) {
                return { ok: false, message: "must be an object" };
            }
            return { ok: true, value: value as Record<string, unknown> };
        },
    };
}

export function optional<T>(field: Field<T, boolean>): Field<T, true> {
    return { ...field, optional: true };
}

type Shape = Record<string, Field<unknown, boolean>>;

/** Required keys stay required; `optional()` keys become optional properties. */
type Infer<S extends Shape> = {
    [K in keyof S as S[K]["optional"] extends true ? never : K]: S[K] extends Field<
        infer T,
        boolean
    >
        ? T
        : never;
} & {
    [K in keyof S as S[K]["optional"] extends true ? K : never]?: S[K] extends Field<
        infer T,
        boolean
    >
        ? T
        : never;
};

export function object<S extends Shape>(shape: S): StandardSchema<Infer<S>> {
    return {
        "~standard": {
            version: 1,
            vendor: "linkotp",
            validate(input: unknown): StandardResult<Infer<S>> {
                if (typeof input !== "object" || input === null || Array.isArray(input)) {
                    return { issues: [{ message: "expected an object body" }] };
                }

                const source = input as Record<string, unknown>;
                const output: Record<string, unknown> = {};
                const issues: { message: string; path: string[] }[] = [];

                for (const [key, field] of Object.entries(shape)) {
                    const raw = source[key];

                    if (raw === undefined || raw === null || raw === "") {
                        // An absent optional field is omitted entirely rather
                        // than set to undefined, which keeps the result clean
                        // under `exactOptionalPropertyTypes`.
                        if (!field.optional) issues.push({ message: "is required", path: [key] });
                        continue;
                    }

                    const parsed = field.parse(raw);
                    if (parsed.ok) output[key] = parsed.value;
                    else issues.push({ message: parsed.message, path: [key] });
                }

                if (issues.length > 0) return { issues };
                return { value: output as Infer<S> };
            },
        },
    };
}
