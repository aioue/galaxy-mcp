/**
 * One native keyring operation, run in its own short-lived process so the CLI can kill it.
 *
 * Why a process: `new AsyncEntry()` connects to the D-Bus session bus synchronously, and on a
 * bus that accepts the connection and never answers it blocks its thread forever
 * (https://github.com/Brooooooklyn/keyring-node/issues/156). A timer in the same process
 * cannot fire, and a `worker_thread` cannot be torn down either: the process cannot exit while
 * the native thread is blocked. A child process can be SIGKILLed whatever it is doing.
 *
 * Protocol: stdin is one JSON request, stdout is one JSON reply, and the process exits.
 *   request: { op: "get" | "set" | "delete", service, account, secret? }
 *   reply:   { ok: true, value?: string | null | boolean }
 *          | { ok: false, kind: "unavailable" | "not-found" | "failed", message }
 * The secret travels only over these pipes, never argv, env or a file, and no reply or error
 * message echoes it. Standalone on purpose: it imports nothing from the CLI, so it builds as a
 * second tsup entry and also runs as source under Node's type stripping.
 */
export {};

interface KeyringRequest {
  op: "get" | "set" | "delete";
  service: string;
  account: string;
  secret?: string;
}

type Reply =
  | { ok: true; value: string | boolean | null }
  | { ok: false; kind: "unavailable" | "not-found" | "failed"; message: string };

async function run(req: KeyringRequest): Promise<Reply> {
  let AsyncEntry: typeof import("@napi-rs/keyring").AsyncEntry;
  try {
    ({ AsyncEntry } = await import("@napi-rs/keyring"));
  } catch (e) {
    return { ok: false, kind: "unavailable", message: `the native keyring module could not be loaded: ${describe(e)}` };
  }
  let entry: InstanceType<typeof AsyncEntry>;
  try {
    // Pinned to Secret Service: see keyring-store.ts for why keyutils is never used.
    entry = new AsyncEntry(req.service, req.account, { linux: { store: "secret-service" } });
  } catch (e) {
    return { ok: false, kind: "unavailable", message: describe(e) };
  }
  try {
    if (req.op === "get") return { ok: true, value: (await entry.getPassword()) ?? null };
    if (req.op === "set") {
      if (typeof req.secret !== "string") return { ok: false, kind: "failed", message: "set without a secret" };
      await entry.setPassword(req.secret);
      return { ok: true, value: true };
    }
    return { ok: true, value: await entry.deletePassword() };
  } catch (e) {
    return { ok: false, kind: "failed", message: describe(e) };
  }
}

function describe(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

let reply: Reply;
try {
  const req = JSON.parse(await readStdin()) as KeyringRequest;
  if (!req || !["get", "set", "delete"].includes(req.op) || typeof req.service !== "string" || typeof req.account !== "string") {
    reply = { ok: false, kind: "failed", message: "bad request" };
  } else {
    reply = await run(req);
  }
} catch {
  reply = { ok: false, kind: "failed", message: "bad request" };
}
process.stdout.write(JSON.stringify(reply), () => process.exit(0));
