/**
 * Exit quietly when the reader of our output goes away.
 *
 * `gxy auth token | head -c1` closes the pipe after one byte; the next write then fails with
 * EPIPE, which Node raises as an `error` event, and with no listener that is an uncaught
 * exception: a stack trace on stderr, in a command whose arguments and output are secrets.
 * The reader leaving is not our failure, so the process ends without a word.
 */
const seen = new WeakSet<object>();

export function exitQuietlyOnEpipe(
  streams: NodeJS.WritableStream[] = [process.stdout, process.stderr],
  exit: (code: number) => void = (code) => process.exit(code),
): void {
  for (const stream of streams) {
    if (seen.has(stream)) continue;
    seen.add(stream);
    stream.on("error", (e: NodeJS.ErrnoException) => {
      if (e.code === "EPIPE") exit(0);
      else throw e;
    });
  }
}
