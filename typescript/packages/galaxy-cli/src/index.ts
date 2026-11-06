import { exitIfKeyringWedged } from "./auth/wedge";
import { buildProgram } from "./program";

await buildProgram().parseAsync(process.argv);
// Normally the event loop just empties. A keyring call that timed out cannot be cancelled and
// would hold the process open, so in that one case exit once the output has drained.
exitIfKeyringWedged();
