/**
 * Keyring calls that outlived their timeout.
 *
 * Investigated against @napi-rs/keyring 2.1.2 (Linux, Secret Service), with a fake D-Bus
 * endpoint that accepts connections and then says nothing:
 *
 * - Methods of `AsyncEntry` run on libuv's thread pool (napi-rs `AsyncTask`), and a queued or
 *   running pool request keeps the event loop, and so the process, alive until it returns.
 *   `KeyringStore`'s 5 s timeout stops us *waiting*; it cannot cancel the native call (the
 *   `AbortSignal` the binding takes only helps before the work has started). A call that never
 *   returns would leave the CLI hanging after it has printed everything. That is what this
 *   module handles: once the work is done, flush stdout and stderr and exit.
 * - Not handled, and worse: `new AsyncEntry(...)` itself connects to the bus and authenticates
 *   synchronously on the main thread. Against a bus that accepts the connection and never
 *   completes authentication, the constructor blocks the whole process: no timer, signal
 *   handler or timeout can run. (Ctrl-C and SIGTERM still kill it, as no JS handler is
 *   installed.) The only way round that is not to load the keyring: `GXY_NO_KEYRING=1`.
 *
 * Not a blanket `process.exit()`: that can cut off stdout when it is a pipe. We only exit when a
 * call really is stuck, and only after the streams have drained.
 */
let outstanding = 0;

/** Remember a native call as outstanding until it settles. */
export function trackWedged(work: Promise<unknown>): void {
  outstanding++;
  const done = () => {
    outstanding--;
  };
  work.then(done, done);
}

/** True while a keyring call that timed out has still not returned. */
export function keyringWedged(): boolean {
  return outstanding > 0;
}

interface Drainable {
  write(chunk: string, cb?: (err?: Error | null) => void): unknown;
}

/**
 * If a keyring call is still stuck, exit once both streams have drained, keeping whatever exit
 * code was set. Does nothing otherwise, so a normal run ends by the event loop emptying.
 */
export function exitIfKeyringWedged(
  streams: Drainable[] = [process.stdout, process.stderr],
  exit: () => void = () => process.exit(),
): boolean {
  if (!keyringWedged()) return false;
  let pending = streams.length;
  const one = () => {
    if (--pending === 0) exit();
  };
  if (pending === 0) exit();
  // An empty write calls back once everything written before it has been flushed.
  for (const s of streams) s.write("", one);
  return true;
}
