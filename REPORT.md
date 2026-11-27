# gxy auth desktop test report (galaxy-mcp #216 to #225)

Real desktops, not CI: GNOME and KDE in QEMU guests on an AWS Linux host, and Windows Server 2025. The stack is branches 03 to 10 of `gxy-auth`, built from the fork. Each branch was run on Node 22.19.0 (the `engines` floor) and 26.13.1 (upstream CI's pair). The server is the in-repo fake Galaxy with fake tokens, so no real Galaxy and no real key is involved. Nothing here is posted upstream except through the PR comments that link to this file.

Open PRs: #221 (07 os-keyring), #223 (08 device-flow-client), #224 (09 device-login), #225 (10 lint). 03 to 06 (#216 to #220) are merged.

## Environment

|                     | Windows                                                                                                                                                                                                                                                                                                                                    | Linux                                                                            |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------- |
| Run                 | `20261127T023453Z`, started 02:34Z (harness `96c0249e`)                                                                                                                                                                                                                                                                                    | `20261127T030042Z`, 03:00 to 07:02Z (harness `59812a0b`)                         |
| Host                | AWS m8i-flex.xlarge, eu-west-2                                                                                                                                                                                                                                                                                                             | AWS m8i-flex.2xlarge, KVM host, Ubuntu 26.04, 8 GiB per guest                    |
| Guest OS            | Windows Server 2025 Datacenter 10.0.26100, PowerShell 5.1 and 7.6.10 (`ps51`, `pwsh`), Edge 157                                                                                                                                                                                                                                            | Ubuntu 26.04.1 LTS, kernel 7.0.0-43, Wayland                                     |
| Desktop and keyring | Windows Credential Manager                                                                                                                                                                                                                                                                                                                 | GNOME Shell 50.1 and gnome-keyring 50.0; Plasma 6.6.7 and kwalletd 0.1 (KWallet) |
| Passes              | one per shell, plus long-path, no-LongPaths and real-Edge variants                                                                                                                                                                                                                                                                         | greeter, session and autologin start states                                      |
| Final heads         | 07 `8e020d1`, 08 `8cac5a2`, 09 `d156ebc`, 10 `2345827` (pushed fast-forward; GitHub CI green on Node 22.19.0 and 26 for all four)                                                                                                                                                                                                          | same                                                                             |
| Tested commits      | 03 `7a31e43`, 04 `4a13eb3`, 05 `b1c20d1`, 06 `5c16cc7`, 07 `da99d9b`, 08 `f73c88d`, 09 `8152f13`, 10 `d083c2e` (first runs). Later runs: Windows `20261127T095855Z` on 07 to 10 (CLI code final for Windows), Linux `20261127T105122Z` and `20261127T120008Z`, final Linux `20261127T131249Z` on the final heads (16/16 clean, suites 8/8) | same                                                                             |

## Matrix

|         | 03  | 04  | 05  | 06  | 07  | 08  | 09  | 10  |
| ------- | --- | --- | --- | --- | --- | --- | --- | --- |
| GNOME   | ✅  | ✅  | ✅  | ✅  | ⚠️  | ⚠️  | ⚠️  | ⚠️  |
| KDE     | ✅  | ✅  | ✅  | ✅  | ⚠️  | ⚠️  | ⚠️  | ⚠️  |
| Windows | ⚠️  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  |

✅ all applicable cases pass · ⚠️ passes, with cases not covered · ❌ at least one failure.
Linux 07 to 10 are from the later runs, where the slow cases (L3a, L5a, L7a, L9d) ran on Node 22 only, hence the ⚠️. Every failure in them is fixed (findings below). Final Linux run on the final heads: `20261127T131249Z`, all 16 combos clean (finding 8).

Final heads, all pushed fast-forward (no force-push): 07 8e020d1 (#221), 08 8cac5a2 (#223), 09 d156ebc (#224), 10 2345827 (#225). GitHub CI is green on Node 22.19.0 and 26 for all four.

A cell is the worst result over both Node versions (and, on Windows, both shells and the extra variants). Cases whose feature lands in a later branch are n/a: the case table's `since` marks them, and the first run predates that, so the verdicts recorded as FAIL on earlier branches are shown as n/a.

Totals per branch (cases x node, merged): see the per-platform tables. D1 to D12 are n/a on 03 to 08 because device login lands in 09; the keyring cases (L, W1 to W4a, W8) are n/a on 03 to 06.

## Verdict changes from the raw run

The harness recorded FAIL for these; after triage they are shown differently here. The raw `summary.json` files are unchanged in the release.

| Case                                                       | Raw             | Shown as           | Why                                                                                    |
| ---------------------------------------------------------- | --------------- | ------------------ | -------------------------------------------------------------------------------------- |
| D1 to D12 on 07, 08                                        | FAIL            | n/a                | device login lands in 09                                                               |
| L4b, L1 to L10 and W1 to W8 on earlier branches            | FAIL            | n/a                | the feature lands in 07 (L4b's wording too)                                            |
| KDE L5a on 07 to 10                                        | FAIL            | record-only (pass) | wrong expectation: the real Ctrl-C goes to the modal wallet dialog, as on GNOME        |
| GNOME L9d on 07 to 10                                      | FAIL (exit 124) | not covered        | harness bug: the terminal window had no keyboard focus; the runner clicks it first now |
| KDE L2a on 10 (Node 22)                                    | FAIL            | not covered        | harness check re-searched the wallet too soon; the harness retries now                 |
| Windows W7, W7-lp0, W7-lp1 on 03                           | FAIL            | not covered        | harness limitation: the fake server has no issueToken                                  |
| KDE L1 (08, Node 22), L2a (08, Node 26), L4a (09, Node 26) | FAIL            | FAIL, fixed        | ksecretd handshake errors; see finding 1                                               |

## Findings

### 1. KDE and GNOME: intermittent Secret Service errors (real, fixed)

Cases: L1 logout (08, Node 22), L2a (08, Node 26), L4a (09, Node 26). Later runs found KDE L9a (07, Node 26) and GNOME L2a (07, Node 26) with the variants above, now fixed.

The CLI reports ksecretd session-handshake errors: `Client public key size is invalid` (L4a) and `Crypto error: Unpad Error` (L2a); in L1 the logout reports it could not confirm the secret is gone. This is a known upstream bug: dbus-secret-service 4.1.0 (used by @napi-rs/keyring 2.1.2) sends its DH public key without the leading zero bytes, so about 1 key in 256 comes out short and KWallet rejects it. secret-service-rs fixed it in [v6.0.0](https://github.com/open-source-cooperative/secret-service-rs/commit/8726596d), but dbus-secret-service 4.2.0 still has it, so bumping won't help. I've added a narrow retry-once for that error and for "Crypto error: Unpad Error" (I haven't proven the Unpad one is the same flake).

Minimal repro (not deterministic): on KDE with the wallet unlocked, loop `gxy auth login --host <fake server> --with-token` then `gxy auth logout` a few hundred times and watch for a keyring read error with exit 77, or a "may remain" note on logout. Harness: run the L1, L2a and L4a cases repeatedly.

Fixes, all on 07 (PR #221) and merged up into 08, 09 and 10, pushed fast-forward: [43b5fa4](https://github.com/aioue/galaxy-mcp/commit/43b5fa4) retries a keyring call once on the handshake flake ("Client public key size is invalid", "Unpad Error", "Can't find session") and cleans up a half-written item; [2d3f969](https://github.com/aioue/galaxy-mcp/commit/2d3f969) extends that retry to the same flake when the helper reports it as "unavailable" (missed at first: the login fell back to plain text on KDE); [8e020d1](https://github.com/aioue/galaxy-mcp/commit/8e020d1) reads a write back after a lost D-Bus reply ("Did not receive a reply"): dbus-secret-service gives each call 2 s, and a busy gnome-keyring stores the item but answers late, so it was misreported as failed (GNOME L2a on Node 26, run 120008Z). Also in the first fix: the "keyring may be locked" wording and "keep the record when logout finds nothing to delete".

Evidence: `transcripts/kde/08-device-flow-client-node22.19.0/L1.log`, `transcripts/kde/08-device-flow-client-node26.13.1/L2a.log`, `transcripts/kde/09-device-login-node26.13.1/L4a.log`.

### 2. Windows: "readable only by you" is not true outside the profile (real, wording fixed)

Cases: W6, recorded rather than failed; I checked 07 to 10 and all four show it. After a file-store login with `GXY_CONFIG_DIR=C:\gxy-shared\cfg`, `icacls` shows `BUILTIN\Users:(I)(RX)` on the directory and on `hosts.yml`, and the file holds a plaintext token. Under the user's profile the ACL is owner, SYSTEM and Administrators only, so the wording holds there.

Minimal repro: `$env:GXY_NO_KEYRING=1; $env:GXY_CONFIG_DIR="C:\gxy-shared\cfg"; gxy auth login --host <host> --with-token`, then `icacls C:\gxy-shared\cfg` and `icacls` on the `hosts.yml` under it. Compare with a directory under the profile.

Fix: the `fileAccessPhrase` wording commit makes the message true outside the profile. It's in PR #221 (merged up). The final Windows run is on it and W6 still records the same ACLs. Locking the ACLs down with `icacls` is a follow-up.

Evidence: `transcripts/windows/07-os-keyring-node22.19.0-pwsh/W6.log` (the same flag on 08, 09 and 10).

### 3. KDE L5a: expectation was wrong (not a gxy bug)

The case sends a real Ctrl-C by QMP while the unlock prompt is up. The keypress goes to the modal wallet dialog, so gxy sees no signal and exits 0, as on GNOME. It is record-only now. The pty and signal variants (L5a2, L5b, L5c) pass. Evidence: `screenshots/kde/07-os-keyring-node22.19.0/L5a-after-ctrl-c.png`.

### 4. GNOME L9d: not covered (harness bug)

The real-keypress, no-echo login in a terminal window was killed at 124 and stored nothing on every combination, because the window had no keyboard focus (the cursor is hollow in the screenshot). The runner clicks the window first now. The same flow through the pty (L9a to L9c) passes. Evidence: `screenshots/gnome/09-device-login-node22.19.0/L9d-after.png`.

### 5. KDE L2a on 10: not covered (harness)

The check searched the wallet before the entry was visible. The CLI was fine. The harness retries now. Same family: KDE L3b (10, Node 22, run 120008Z) re-read the wallet too soon at the end of the case, and KDE L5b (07, Node 22, run 105122Z) failed an unlock-to-inspect once after a left-over wallet dialog. Both are runner fixes, polling and retrying. Evidence: `transcripts/kde/10-lint-node22.19.0/L2a.log`.

### 6. Windows 03 W7: not covered (harness limitation)

The fake server has no issueToken, so the long-path login cannot finish on 03. It passes from 04 on. Evidence: `transcripts/windows/03-login-with-token-node22.19.0-pwsh/W7.log`.

### 7. Windows: final run, and the suites

Run `20261127T095855Z` on 07 to 10: 416 PASS, 0 FAIL. No Windows rerun after 2d3f969 and 8e020d1: both only fire on Secret Service error text, which Credential Manager never produces. The two 09 device-login Ctrl-C e2e tests failed on Windows because `child.kill("SIGINT")` ends the process outright there; [bc9af5a](https://github.com/aioue/galaxy-mcp/commit/bc9af5a) skips them on Windows. [44fed1a](https://github.com/aioue/galaxy-mcp/commit/44fed1a) on 10 is formatting only. The galaxy-cli suites fail 32 tests on Windows already on merged 06 (POSIX assumptions: file modes, / paths, sh, symlinks, getuid); none are new in these PRs, and upstream CI is Linux-only. Reported, not claimed fixed. Upstream [galaxy-mcp #249](https://github.com/galaxyproject/galaxy-mcp/pull/249) is a test-only PR for this: with it the galaxy-cli and galaxy-ops suites pass on Windows (on main, 30 + 2 tests fail there).

### 8. Linux: later runs

Runs `20261127T105122Z` and `20261127T120008Z` each had 14 of 16 platform, branch and Node combos clean, and every failure was fixed (the CLI ones in finding 1, plus runner fixes). Suites were 8/8 and 7/8; the one miss was an upstream galaxy-mcp timing test (`test/lax-arguments.test.ts` "is linear in the length of the string", 127 ms against a 65 ms limit under load), which these PRs don't touch. With `--timeouts-once` the slow cases (L3a, L5a, L7a, L9d) run on Node 22 only. Final run `20261127T131249Z` on the final heads (07 `8e020d1`, 08 `8cac5a2`, 09 `d156ebc`, 10 `2345827`), GNOME and KDE, Node 22.19.0 and 26.13.1, with `--timeouts-once`, `--suites` and `--record`:

- 16/16 combos: every applicable case passed, no FAIL or ERROR (the only non-passes are the 4 slow cases NOT_COVERED on Node 26, by design).
- Suites: 8/8 passed (typecheck and tests, all four branches on both Node versions).
- The job's exit 1 in run-gxy's log is a harness poll race after the host powered off (being fixed), not a test failure.

## Windows Server 2025: per-case results

Over all branches: 143 pass / 0 fail / 129 n/a or not covered (case x branch cells, Node versions merged; "22 x / 26 y" where they differ).

| Case                                                                                          | 03  | 04  | 05  | 06  | 07  | 08  | 09  | 10  |
| --------------------------------------------------------------------------------------------- | --- | --- | --- | --- | --- | --- | --- | --- |
| D1 Enter at the open-the-page prompt opens the default browser, which hits the approval page  | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D2 --no-browser: no prompt and no browser hit within 10 s; approval then gives exit 0         | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D3 No --host, at a terminal: the URL prompt shows nothing pre-filled (even with a stored logi | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D4 Approval denied on the approval page                                                       | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D5 Device code expires before approval                                                        | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D6 Galaxy has the device flow switched off (metadata without a device endpoint)               | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D6b Galaxy publishes no OAuth metadata (what Galaxy 26.1 does today)                          | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D7 Metadata endpoint unavailable (503): reads as unreachable, not as 'no device login'        | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D8 hosts.yml holds a login a newer gxy wrote for this Galaxy: refused before any code is requ | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D8b hosts.yml is corrupt: refused, file untouched, no code requested                          | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D9 Usage error: --no-browser with --with-token                                                | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D10 Ctrl-C (real keypress) while waiting for approval                                         | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D12 $BROWSER set to a launcher that fails: falls back to the system opener                    | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| W1 login, token, status, logout through Credential Manager                                    | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| W2a login over an existing login, same user                                                   | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| W2b login over an existing login, different user                                              | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| W3a persistence: the login survives a new process / new logon session of the same user        | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| W3b a blob over 2560 bytes falls back to plaintext                                            | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| W4a GXY_NO_KEYRING=1 over an existing login                                                   | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| W4b GXY_NO_KEYRING=1 with no login                                                            | n/a | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  |
| W5a Ctrl-C at the no-echo prompt, in its own console (ConsoleInject)                          | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  |
| W5b Ctrl-C during the device wait (ConsoleInject)                                             | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| W5c the signal path: AttachConsole + GenerateConsoleCtrlEvent (CtrlEvent)                     | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  |
| W5d Stop-Process at the prompt                                                                | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  |
| W5e SendKeys ^c to the focused conhost (cross-check), with a screenshot                       | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  |
| W5f no keyring-child process left                                                             | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  |
| W6 ACLs under the profile and under C:\gxy-shared\cfg (icacls)                                | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  |
| W7 paths with spaces; over 260 characters with LongPathsEnabled 0 and 1 (set by SYSTEM)       | ⚠️  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  |
| W7-lp0 paths with spaces; over 260 characters with LongPathsEnabled 0 and 1 (set by SYSTEM)   | ⚠️  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  |
| W7-lp1 paths with spaces; over 260 characters with LongPathsEnabled 0 and 1 (set by SYSTEM)   | ⚠️  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  |
| W8 no-echo prompt: no echo, backspace, 2>file gives 64                                        | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| W9 PS 5.1 pipe: CRLF and $OutputEncoding; the stored token compared byte for byte             | n/a | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  |
| W10 default browser: the stub records the URL; a real Edge case too (device D1)               | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| W10-edge default browser: the stub records the URL; a real Edge case too (device D1)          | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |

## GNOME: per-case results

Over all branches: 132 pass / 0 fail / 180 n/a or not covered (case x branch cells, Node versions merged; "22 x / 26 y" where they differ).

| Case                                                                                           | 03  | 04  | 05  | 06  | 07  | 08  | 09  | 10  |
| ---------------------------------------------------------------------------------------------- | --- | --- | --- | --- | --- | --- | --- | --- |
| D1 Enter at the open-the-page prompt opens the default browser, which hits the approval page   | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D2 --no-browser: no prompt and no browser hit within 10 s; approval then gives exit 0          | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D3 No --host, at a terminal: the URL prompt shows nothing pre-filled (even with a stored logi  | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D4 Approval denied on the approval page                                                        | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D5 Device code expires before approval                                                         | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D6 Galaxy has the device flow switched off (metadata without a device endpoint)                | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D6b Galaxy publishes no OAuth metadata (what Galaxy 26.1 does today)                           | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D7 Metadata endpoint unavailable (503): reads as unreachable, not as 'no device login'         | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D8 hosts.yml holds a login a newer gxy wrote for this Galaxy: refused before any code is requ  | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D8b hosts.yml is corrupt: refused, file untouched, no code requested                           | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D9 Usage error: --no-browser with --with-token                                                 | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D10 Ctrl-C (real keypress) while waiting for approval                                          | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D11 SIGTERM while waiting for approval                                                         | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D12 $BROWSER set to a launcher that fails: falls back to the system opener                     | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| L1 login, token, status, logout through the keyring; hosts: {} after logout (nit 5)            | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L2a login over an existing keyring login, same user                                            | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L2b login over an existing keyring login, different user (keyring account changes)             | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L3a locked keyring, tty on stderr, nobody answers the dialog (the 60 s wait)                   | n/a | n/a | n/a | n/a | ⚠️  | ⚠️  | ⚠️  | ⚠️  |
| L3b locked keyring, password typed into the real dialog at 5 s                                 | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L3c locked keyring, stderr not a tty, nobody answers (the 5 s wait)                            | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L3d locked after login: token, status, logout (non-interactive)                                | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L3e login over a keyring login while locked (non-interactive)                                  | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L3f locked, Escape on the dialog (record)                                                      | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L3g B1: login over an existing keyring login, dialog cancelled                                 | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L4a GXY_NO_KEYRING=1 over an existing keyring login                                            | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L4b GXY_NO_KEYRING=1 with no keyring login: login and logout work on the file                  | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L5a REAL keypress Ctrl-C (QMP) while the unlock prompt is up                                   | n/a | n/a | n/a | n/a | ⚠️  | ⚠️  | ⚠️  | ⚠️  |
| L5a2 Ctrl-C at the pty (as an SSH user), tmux send-keys                                        | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L5b signal during the prompt: kill -INT to gxy's pid alone                                     | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L5c signal during the prompt: kill -TERM to gxy's pid alone                                    | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L6 PAM unlock at login: the keyring is unlocked by typing the password at the greeter          | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L7a locked; gxy from a second login session (systemd-run --machine=tester@ --pty) while the GU | n/a | n/a | n/a | n/a | ⚠️  | ⚠️  | ⚠️  | ⚠️  |
| L7b the same with no GUI session (logged out)                                                  | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L8 x64 and the prebuilt keyring .node path                                                     | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L9a no-echo key prompt: typed key with a backspace (Mac 7a)                                    | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L9b no-echo prompt: stdin a terminal, stderr redirected to a file: refuses with 64 (Mac 7b)    | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  |
| L9c no-echo prompt: Ctrl-C at the key prompt gives 130 (Mac 7c)                                | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  |
| L9d no-echo prompt in a real terminal window: typed with real keypresses (extra, the 'real-key | n/a | n/a | n/a | n/a | ⚠️  | ⚠️  | ⚠️  | ⚠️  |
| L10 auto-login (keyring locked from the start), then the first write                           | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |

## KDE: per-case results

Over all branches: 132 pass / 3 fail / 177 n/a or not covered (case x branch cells, Node versions merged; "22 x / 26 y" where they differ).

| Case                                                                                           | 03  | 04  | 05  | 06  | 07  | 08  | 09  | 10  |
| ---------------------------------------------------------------------------------------------- | --- | --- | --- | --- | --- | --- | --- | --- |
| D1 Enter at the open-the-page prompt opens the default browser, which hits the approval page   | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D2 --no-browser: no prompt and no browser hit within 10 s; approval then gives exit 0          | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D3 No --host, at a terminal: the URL prompt shows nothing pre-filled (even with a stored logi  | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D4 Approval denied on the approval page                                                        | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D5 Device code expires before approval                                                         | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D6 Galaxy has the device flow switched off (metadata without a device endpoint)                | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D6b Galaxy publishes no OAuth metadata (what Galaxy 26.1 does today)                           | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D7 Metadata endpoint unavailable (503): reads as unreachable, not as 'no device login'         | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D8 hosts.yml holds a login a newer gxy wrote for this Galaxy: refused before any code is requ  | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D8b hosts.yml is corrupt: refused, file untouched, no code requested                           | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D9 Usage error: --no-browser with --with-token                                                 | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D10 Ctrl-C (real keypress) while waiting for approval                                          | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D11 SIGTERM while waiting for approval                                                         | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| D12 $BROWSER set to a launcher that fails: falls back to the system opener                     | n/a | n/a | n/a | n/a | n/a | n/a | ✅  | ✅  |
| L1 login, token, status, logout through the keyring; hosts: {} after logout (nit 5)            | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L2a login over an existing keyring login, same user                                            | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L2b login over an existing keyring login, different user (keyring account changes)             | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L3a locked keyring, tty on stderr, nobody answers the dialog (the 60 s wait)                   | n/a | n/a | n/a | n/a | ⚠️  | ⚠️  | ⚠️  | ⚠️  |
| L3b locked keyring, password typed into the real dialog at 5 s                                 | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L3c locked keyring, stderr not a tty, nobody answers (the 5 s wait)                            | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L3d locked after login: token, status, logout (non-interactive)                                | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L3e login over a keyring login while locked (non-interactive)                                  | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L3f locked, Escape on the dialog (record)                                                      | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L3g B1: login over an existing keyring login, dialog cancelled                                 | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L4a GXY_NO_KEYRING=1 over an existing keyring login                                            | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L4b GXY_NO_KEYRING=1 with no keyring login: login and logout work on the file                  | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L5a REAL keypress Ctrl-C (QMP) while the unlock prompt is up                                   | n/a | n/a | n/a | n/a | ⚠️  | ⚠️  | ⚠️  | ⚠️  |
| L5a2 Ctrl-C at the pty (as an SSH user), tmux send-keys                                        | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L5b signal during the prompt: kill -INT to gxy's pid alone                                     | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L5c signal during the prompt: kill -TERM to gxy's pid alone                                    | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L6 PAM unlock at login: the keyring is unlocked by typing the password at the greeter          | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L7a locked; gxy from a second login session (systemd-run --machine=tester@ --pty) while the GU | n/a | n/a | n/a | n/a | ⚠️  | ⚠️  | ⚠️  | ⚠️  |
| L7b the same with no GUI session (logged out)                                                  | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L8 x64 and the prebuilt keyring .node path                                                     | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L9a no-echo key prompt: typed key with a backspace (Mac 7a)                                    | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |
| L9b no-echo prompt: stdin a terminal, stderr redirected to a file: refuses with 64 (Mac 7b)    | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  |
| L9c no-echo prompt: Ctrl-C at the key prompt gives 130 (Mac 7c)                                | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  | ✅  |
| L9d no-echo prompt in a real terminal window: typed with real keypresses (extra, the 'real-key | n/a | n/a | n/a | n/a | ⚠️  | ⚠️  | ⚠️  | ⚠️  |
| L10 auto-login (keyring locked from the start), then the first write                           | n/a | n/a | n/a | n/a | ✅  | ✅  | ✅  | ✅  |

## Resource use and right-sizing

Generated by `harness/report/make-report.py` from the run's metrics (`phases.json`, host samples, CloudWatch). One run each, so treat the recommendations as indicative. Note the GNOME guest's qemu resident set (8.1 GiB) touched its 8.0 GiB allowance: it is an upper bound that includes qemu's own overhead, and the cases passed, but it is the number to watch if guests are ever shrunk.

### Cost and time in brief

The whole matrix took 4h on a m8i-flex.2xlarge (18.5% CPU at p95, 11.7 GiB RAM at peak) plus 1h13m on Windows, about $2.40 all in.

### Linux host and guests (run `20261127T030042Z`)

### Linux KVM host (m8i-flex.2xlarge)

| Phase                | Duration | CPU avg | CPU p95 | CPU peak | Peak RAM (headroom)        | Bound      | Builder CPU p95 / RSS peak | CloudWatch avg / max      |
| -------------------- | -------- | ------- | ------- | -------- | -------------------------- | ---------- | -------------------------- | ------------------------- |
| up                   | 0:03     | n/a     | n/a     | n/a      | not collected              | too short  | n/a                        | 56.1% / 95.9% (1 x 300s)  |
| doctor               | 0:00     | n/a     | n/a     | n/a      | not collected              | too short  | n/a                        | 56.1% / 95.9% (1 x 300s)  |
| upload               | 0:02     | n/a     | n/a     | n/a      | not collected              | too short  | n/a                        | 56.1% / 95.9% (1 x 300s)  |
| exec                 | 0:06     | n/a     | n/a     | n/a      | not collected              | too short  | n/a                        | 56.1% / 95.9% (1 x 300s)  |
| job (total)          | 4:00:44  | 11.0%   | 18.5%   | 99.8%    | 11.7 / 30.8 GiB (62% free) | wait-bound | 0.0% / 6691 MiB            | 11.4% / 95.9% (47 x 300s) |
| setup and build      | 2:07:08  | 13.2%   | 19.3%   | 99.8%    | 11.7 / 30.8 GiB (62% free) | wait-bound | 0.0% / 6691 MiB            | 13.4% / 95.9% (26 x 300s) |
| cases gnome          | 5:15     | 9.5%    | 11.0%   | 11.3%    | 9.0 / 30.8 GiB (71% free)  | wait-bound | 0.0% / 0.0 MiB             | 8.4% / 12.3% (2 x 300s)   |
| cases kde            | 3:56     | 9.8%    | 12.1%   | 12.1%    | 9.0 / 30.8 GiB (71% free)  | wait-bound | 0.0% / 0.0 MiB             | 9.7% / 11.7% (2 x 300s)   |
| tail (scrub, upload) | 9:55     | 5.5%    | 5.5%    | 5.5%     | 0.9 / 30.8 GiB (97% free)  | too short  | 0.0% / 0.0 MiB             | 10.5% / 11.6% (1 x 300s)  |
| collect              | 0:19     | n/a     | n/a     | n/a      | not collected              | too short  | n/a                        | n/a                       |
| down                 | 0:01     | n/a     | n/a     | n/a      | not collected              | too short  | n/a                        | n/a                       |
| verify               | 0:02     | n/a     | n/a     | n/a      | not collected              | too short  | n/a                        | n/a                       |

Builder CPU is summed over user `builder`'s processes (the suites) as a share of the host's vCPUs; a process that exits between samples is not counted.

### GNOME guest

| Phase       | Duration | CPU avg | CPU p95 | CPU peak | Peak RAM (headroom)      | Bound      |
| ----------- | -------- | ------- | ------- | -------- | ------------------------ | ---------- |
| cases gnome | 5:15     | 13.0%   | 19.4%   | 19.6%    | 8.1 / 8.0 GiB (-1% free) | wait-bound |

Guest CPU is the qemu process's CPU as a share of the vCPUs it was given. Guest RAM is the qemu process's resident set, an upper bound on what the guest used.

### Recommendation (Linux host and GNOME guest)

- **Linux host: down-size.** CPU p95 19.0%, peak RAM 38% of allocated.
  Scale out: no. The critical phase is setup and build (2:07:08) and it is wait-bound: look at caches and downloads.
- **GNOME guest: keep.** CPU p95 19.4%.
- **KDE guest: keep.** CPU p95 16.3%.

### KDE guest

| Phase     | Duration | CPU avg | CPU p95 | CPU peak | Peak RAM (headroom)      | Bound      |
| --------- | -------- | ------- | ------- | -------- | ------------------------ | ---------- |
| cases kde | 3:56     | 15.0%   | 16.3%   | 16.3%    | 8.1 / 8.0 GiB (-1% free) | wait-bound |

Guest CPU is the qemu process's CPU as a share of the vCPUs it was given. Guest RAM is the qemu process's resident set, an upper bound on what the guest used.

### Windows (run `20261127T023453Z`)

#### Windows Server 2025 (m8i-flex.xlarge)

| Phase           | Duration | CPU avg | CPU p95 | CPU peak | Peak RAM (headroom)       | Bound      | Queue p95 | CloudWatch avg / max      |
| --------------- | -------- | ------- | ------- | -------- | ------------------------- | ---------- | --------- | ------------------------- |
| restore         | 1:04     | n/a     | n/a     | n/a      | not collected             | too short  | n/a       | 5.4% / 9.8% (1 x 300s)    |
| up              | 0:03     | n/a     | n/a     | n/a      | not collected             | too short  | n/a       | 5.4% / 9.8% (1 x 300s)    |
| doctor          | 0:48     | 11.5%   | 19.3%   | 19.3%    | 2.1 / 15.6 GiB (86% free) | too short  | 0.0       | 5.4% / 9.8% (1 x 300s)    |
| up              | 0:25     | n/a     | n/a     | n/a      | not collected             | too short  | n/a       | 17.4% / 50.8% (2 x 300s)  |
| doctor          | 0:15     | 3.9%    | 3.9%    | 3.9%     | 1.8 / 15.6 GiB (88% free) | too short  | 0.0       | 29.4% / 50.8% (1 x 300s)  |
| upload          | 0:02     | 4.4%    | 4.4%    | 4.4%     | 1.9 / 15.6 GiB (88% free) | too short  | 0.0       | 29.4% / 50.8% (1 x 300s)  |
| exec            | 0:07     | n/a     | n/a     | n/a      | not collected             | too short  | n/a       | 29.4% / 50.8% (1 x 300s)  |
| job (total)     | 34:37    | 26.1%   | 62.9%   | 82.9%    | 3.9 / 15.6 GiB (75% free) | wait-bound | 2.0       | 26.9% / 50.8% (8 x 300s)  |
| setup and build | 5:58     | 40.2%   | 80.9%   | 82.9%    | 2.8 / 15.6 GiB (82% free) | CPU-bound  | 0.0       | 28.6% / 50.8% (2 x 300s)  |
| cases           | 56:01    | 23.5%   | 51.7%   | 87.5%    | 4.1 / 15.6 GiB (73% free) | wait-bound | 1.0       | 24.7% / 45.0% (12 x 300s) |
| collect         | 0:26     | n/a     | n/a     | n/a      | not collected             | too short  | n/a       | 5.4% / 6.5% (1 x 300s)    |
| down            | 0:14     | n/a     | n/a     | n/a      | not collected             | too short  | n/a       | 5.4% / 6.5% (1 x 300s)    |
| verify          | 0:01     | n/a     | n/a     | n/a      | not collected             | too short  | n/a       | 5.4% / 6.5% (1 x 300s)    |

### Recommendation

- **Windows instance: keep.** CPU p95 59.1%, peak RAM 27% of allocated.
  Scale out: worth trying. Cases run one at a time in this VM; a second instance (or the shells in parallel) would save at most about 28:00.

Rules: a phase of 60 s or more is **CPU-bound** at p95 CPU of 80% or more (host: load above vCPUs; Windows: queue above 2 per vCPU), otherwise **wait-bound**. **Up-size** on a CPU-bound work phase that is 25% or more of the work time, RAM headroom under 10%, or swap growth of 5% of RAM. **Down-size** on p95 CPU under 40% and peak RAM under 50% with nothing CPU-bound. Otherwise **keep**. The full rules are in `harness/metrics/resource_use.py`.

## Harness notes

- Verdicts come from `harness/cases/*cases.json` plus each run's `summary.json`; `harness.tgz` (sha256 in the release) is the exact harness used. Each run was assembled from several passes (Linux: greeter, session and autologin; Windows: one pass per shell and variant), and a case shown here takes the worst result across them.
- Session hygiene (Linux): 0 cases left the session dirty, 0 reverts to a pass snapshot, 0 cases needed a cleanup.
- The raw run predates the `since` field in the case table (device cases since 09; keyring cases since 07). Rows are re-evaluated against it here, so FAILs for features a branch doesn't have show as n/a. L4b was `since: 04` in the table, but `GXY_NO_KEYRING` first appears on 07, so it is `since: 07` now and its 04 to 06 FAILs are n/a.
- Transcripts and screenshots are scrubbed for tokens, API-key and authorization header names and 32-hex strings. Windows transcripts carry the instance's hostname, which is rewritten in the evidence copies (see evidence-release.md).
- Not covered anywhere: macOS and a real Galaxy. The per-case tables below are the first full run, with the cells that failed or were not covered there shown as they came out in the later runs.
- The Linux run's setup and build phase took 2:07 of the 4:01 job. The cases themselves took 5:15 (GNOME) and 3:56 (KDE).
