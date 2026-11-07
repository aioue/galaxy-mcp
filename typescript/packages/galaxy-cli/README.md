# @galaxyproject/galaxy-cli

Galaxy agent operations on the command line. One subcommand per operation --
histories, datasets, tools, workflows, pages, and the IWC catalog -- with table / JSON
output and meaningful exit codes. Built on
[`@galaxyproject/galaxy-ops`](https://www.npmjs.com/package/@galaxyproject/galaxy-ops).

## Install

```bash
npm install -g @galaxyproject/galaxy-cli   # provides the `galaxy-cli` command
# or run without installing:
npx @galaxyproject/galaxy-cli --help
```

Requires Node.js `>=22.19`.

## Usage

Set your [Galaxy](https://galaxyproject.org/) connection, then run a command:

```bash
export GALAXY_URL=https://usegalaxy.org/
export GALAXY_API_KEY=your-api-key

galaxy-cli get_user
galaxy-cli --format json get_histories --name rnaseq
galaxy-cli get_workflow_input_template <workflowId>
galaxy-cli invoke_workflow <workflowId> --inputs @inputs.json --history-name "WF run"
```

Credentials resolve from (first match wins): `--url`/`--api-key` flags, the
`GALAXY_URL`/`GALAXY_API_KEY` environment variables, a `.env` file in the current
directory, or a planemo profile (`--profile <name>`). Output is a table by
default; `--format json` prints the full result envelope for scripting. Exit
codes follow `sysexits.h` conventions (e.g. `77` for auth failures).

Run `galaxy-cli --help`, or `galaxy-cli <command> --help`, for the full list of
commands and their arguments.

## Logging in

`gxy auth` stores a login so you don't have to put an API key in a shell variable or a
command line. `gxy` and `galaxy-cli` are the same program.

```bash
gxy auth login --host https://usegalaxy.org   # device flow: approve a one-time code in your browser
gxy auth status                               # stored logins, checked against Galaxy
gxy get_user                                  # operations use the stored login, no flags
gxy auth logout                               # revoke the token and delete it
```

If the Galaxy has the device flow switched off (`gxy` says it "does not offer device login yet"
and prints the command to use), or you already have a key, pipe it in:
`printf %s "$KEY" | gxy auth login --host <url> --with-token`.

| Command | Does |
| --- | --- |
| `auth login` | device flow, or `--with-token` to read a key from stdin; `--scopes`, `--no-browser`, `--insecure-storage` |
| `auth status` | show stored logins and check each one (`--json`, `--show-token`) |
| `auth token` | print the token on stdout |
| `auth env` | print `GALAXY_URL` and `GALAXY_API_KEY` assignments, for `eval` |
| `auth headers` | print `{"x-api-key": ...}` as JSON, for an MCP `headersHelper` |
| `auth logout` | revoke the token where the server allows it, and delete the stored login |

Tokens live in the system keyring when there is one, otherwise in `hosts.yml` in the config
directory (`$GXY_CONFIG_DIR`, else `~/.config/gxy`), readable only by you. A `GALAXY_API_KEY`
(or `--api-key`) still wins over a stored login.

A token that carries admin rights is only ever stored in the system keyring. With no keyring,
`gxy auth login` refuses and stores nothing, unless you add `--insecure-storage` to put it in
`hosts.yml`.

| Variable | Does |
| --- | --- |
| `GXY_CONFIG_DIR` | Where `hosts.yml` lives (default `~/.config/gxy`; `$XDG_CONFIG_HOME/gxy` when that is set) |
| `GXY_OAUTH_CLIENT_ID` | The OAuth client id presented to the Galaxy during login (default `galaxy-cli`), for a Galaxy that registers clients by name |
| `GXY_NO_KEYRING` | `1` never touches the system keyring: tokens go to `hosts.yml`, with a warning. Use it on a box whose keyring is broken or locked, to skip the wait |

A login counts as expired a minute before its expiry time, so a token that passes `auth token`
has time to do its job. If the keyring cannot be read, `auth logout` still removes the stored
record (it says the token was not revoked and may remain valid until it expires) and `auth status`
reports that host as "token unavailable" and exits 1.

Which Galaxy is meant, for `auth` and for operations alike: `--host`/`--url`, then `GALAXY_URL` in
the environment, then in `.env`, then the `--profile` URL, then the only stored login. A stored
token is only sent to the host it was issued for. `auth login` never takes its host from `.env` or a
profile (a repository must not choose where your key goes): give `--host` or set `GALAXY_URL`.

Troubleshooting: the system keyring is asked through a short-lived helper process that is killed
if it does not answer within 5 seconds, so a dead D-Bus costs at most that wait before the
command reports the keyring as unavailable. `GXY_NO_KEYRING=1` skips the keyring entirely.

### Keeping tokens away from agents

`gxy auth env` puts the token in the environment of every process started from that shell,
and `gxy auth token` prints it where a transcript can keep it. Agents should run
`gxy <operation>` and let it read the stored login, rather than handling tokens themselves.
In Claude Code you can say so in `.claude/settings.json`:

```json
{
  "permissions": {
    "deny": ["Bash(gxy auth token*)", "Bash(gxy auth env*)", "Read(~/.config/gxy/**)"]
  }
}
```

These rules match the command text; they are not a sandbox. A different spelling of the
same command, or a script that runs it, is not caught.

### Galaxy's MCP endpoint

To give Claude Code the stored login for a Galaxy's `/api/mcp` endpoint without putting a key
in the config file:

```json
{
  "mcpServers": {
    "galaxy": {
      "type": "http",
      "url": "https://usegalaxy.org/api/mcp",
      "headersHelper": "gxy auth headers"
    }
  }
}
```

### Certificates and proxies

For a Galaxy with a certificate from a private CA, set `NODE_EXTRA_CA_CERTS=/path/to/ca.pem`.
Node's `fetch` ignores `HTTPS_PROXY` unless `NODE_USE_ENV_PROXY=1` is set (Node 22.21 and
later). Login never offers to switch off certificate checks.

## Documentation

See the [TypeScript workspace README](https://github.com/galaxyproject/galaxy-mcp/tree/main/typescript#readme)
for the full operation list, output formats, and exit-code reference.

## License

[MIT](https://github.com/galaxyproject/galaxy-mcp/blob/main/LICENSE)
