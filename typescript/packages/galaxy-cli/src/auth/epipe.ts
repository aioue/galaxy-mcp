/**
 * Exit quietly when the reader of our output goes away.
 *
 * `gxy auth token | head -c1` closes the pipe after one byte; the next write then fails with
 * EPIPE, which Node raises as an `error` event, and with no listener that is an uncaught
 * exception: a stack trace on stderr, in a command whose arguments and output are secrets.
 * The reader leaving is not our failure, so the process ends without a word, when it is
 * stdout (the output is what they wanted, and `| head` is normal). A closed stderr is different:
 * the work is still going (a login, a revoke), and ending with 0 would report success for
 * something that has not finished. So stderr just goes quiet and the run carries on, and its
 * exit code still says how it went.
 */
const seen = new WeakSet<object>();

export function exitQuietlyOnEpipe(
  streams: { stdout: NodeJS.WritableStream; stderr: NodeJS.WritableStream } = process,
  exit: (code: number) => void = (code) => process.exit(code),
): void {
  const watch = (stream: NodeJS.WritableStream, onEpipe: () => void) => {
    if (seen.has(stream)) return;
    seen.add(stream);
    stream.on("error", (e: NodeJS.ErrnoException) => {
      if (e.code === "EPIPE") onEpipe();
      else throw e;
    });
  };
  watch(streams.stdout, () => exit(0));
  watch(streams.stderr, () => {
    // Later writes would only raise the same error again.
    streams.stderr.write = (() => true) as typeof streams.stderr.write;
  });
}
