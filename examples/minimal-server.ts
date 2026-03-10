/**
 * A complete, runnable sign-in flow in one file.
 *
 *     node examples/minimal-server.ts
 *     open http://localhost:3000
 *
 * Needs nothing installed. The store is in memory, the mailer prints to the
 * console, and the HTTP layer is Node's own. Everything else is exactly what
 * you would run in production.
 *
 * Worth trying once it is up: copy the verification URL from the console and
 * `curl` it. You will get the confirmation page and the challenge will still
 * work afterwards, which is the behaviour that keeps mail scanners from
 * burning your users' links.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { Readable } from "node:stream";

import { createOtpLink } from "../src/index.ts";
import { createHandler } from "../src/http/index.ts";
import { createMemoryStore } from "../src/stores/index.ts";

const PORT = 3000;
const ORIGIN = `http://localhost:${PORT}`;

// ---------------------------------------------------------------- auth setup

const auth = createOtpLink({
    secret: "example-only-secret-at-least-32-characters-long",
    baseUrl: ORIGIN,
    store: createMemoryStore(),
    email: { product: "Example" },
    mailer: async (message) => {
        console.log("\n" + "-".repeat(66));
        console.log(`To:      ${message.to}`);
        console.log(`Subject: ${message.subject}`);
        console.log("-".repeat(66));
        console.log(message.text);
        console.log("-".repeat(66) + "\n");
    },
});

// A real deployment issues a signed session cookie here. This one is a stub,
// to keep the example about otplink rather than about session management.
const handler = createHandler(auth, {
    product: "Example",
    async onVerified(identity) {
        console.log(`Verified ${identity.email} via the ${identity.via}`);
        return {
            headers: {
                "Set-Cookie": `example_session=${encodeURIComponent(identity.email)}; Path=/; HttpOnly; SameSite=Lax`,
            },
            redirectTo: "/",
        };
    },
});

// ------------------------------------------------------------- the sign-in UI

const PAGE = `<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>otplink example</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.6 system-ui, sans-serif; max-width: 22rem; margin: 15vh auto; padding: 0 1rem; }
  form { display: grid; gap: .6rem; margin-block: 1.4rem; }
  input, button { font: inherit; padding: .6rem .7rem; border-radius: .5rem; border: 1px solid #8884; }
  button { background: #111; color: #fff; border: 0; cursor: pointer; }
  #out { min-height: 1.4rem; color: #888; font-size: .9rem; }
  .who { padding: .7rem; border: 1px solid #8884; border-radius: .5rem; }
</style>
<h1>Sign in</h1>
<div id="who"></div>
<form id="start"><input name="email" type="email" placeholder="you@example.com" required><button>Email me a code</button></form>
<form id="verify" hidden><input name="code" placeholder="6-character code" required autocomplete="one-time-code"><button>Verify</button></form>
<p id="out"></p>
<script>
  const out = document.getElementById("out");
  const session = document.cookie.split("; ").find((c) => c.startsWith("example_session="));
  if (session) {
    document.getElementById("who").innerHTML =
      '<p class="who">Signed in as <b>' + decodeURIComponent(session.split("=")[1]) + '</b></p>';
  }
  let email = "";

  document.getElementById("start").onsubmit = async (e) => {
    e.preventDefault();
    email = e.target.email.value;
    const r = await fetch("/api/auth/start", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    const body = await r.json();
    out.textContent = r.ok ? "Check the server console for the code and link." : body.message;
    if (r.ok) document.getElementById("verify").hidden = false;
  };

  document.getElementById("verify").onsubmit = async (e) => {
    e.preventDefault();
    const r = await fetch("/api/auth/verify", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, code: e.target.code.value }),
    });
    const body = await r.json();
    if (r.ok) location.href = body.redirectTo;
    else out.textContent = body.message;
  };
</script>`;

// --------------------------------------------------- node:http <-> Fetch glue

/**
 * Express and Node's own server predate the Fetch API, so the conversion
 * happens once at the boundary. Every modern runtime skips this entirely.
 */
async function toRequest(req: IncomingMessage): Promise<Request> {
    // Every body this handler accepts is text (JSON or form-encoded), so
    // decoding as a string keeps the glue readable. A real adapter that must
    // also carry file uploads would stream the bytes instead.
    let body = "";
    if (req.method !== "GET" && req.method !== "HEAD") {
        const decoder = new TextDecoder();
        for await (const chunk of req) body += decoder.decode(chunk, { stream: true });
        body += decoder.decode();
    }

    return new Request(new URL(req.url ?? "/", ORIGIN), {
        headers: req.headers as Record<string, string>,
        ...(req.method ? { method: req.method } : {}),
        ...(body.length > 0 ? { body } : {}),
    });
}

async function send(response: Response, res: ServerResponse): Promise<void> {
    for (const [key, value] of response.headers) {
        if (key === "set-cookie") continue;
        res.setHeader(key, value);
    }
    const cookies = response.headers.getSetCookie();
    if (cookies.length > 0) res.setHeader("Set-Cookie", cookies);

    res.writeHead(response.status);
    if (response.body) await Readable.fromWeb(response.body).pipe(res);
    else res.end();
}

// ---------------------------------------------------------------------- serve

createServer(async (req, res) => {
    try {
        const url = new URL(req.url ?? "/", ORIGIN);

        if (url.pathname === "/") {
            res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
            res.end(PAGE);
            return;
        }

        await send(await handler(await toRequest(req)), res);
    } catch (error) {
        console.error(error);
        res.writeHead(500).end("Internal error");
    }
}).listen(PORT, () => {
    console.log(`\notplink example running at ${ORIGIN}\n`);
});
