# `ssh-vend-local-signer`



## Overview

`ssh-vend-local-signer` is a privileged stdin/stdout SSH certificate signer.
It is intended to be launched through `sudo` as the `ssh-vend-signer` user.

Usage:

```text
ssh-vend-local-signer [--debug]
```

The helper reads one JSON request from stdin and writes one OpenSSH user
certificate authorized-key line to stdout.

Diagnostics and debug output go to stderr.

## Request JSON

Example:

```json
{
  "public_key": "ssh-ed25519 AAAA...",
  "principal": "ansadmin",
  "signing_key": "default",
  "requested_ttl": "15m",
  "identity": "semaphore-task-123"
}
```

Fields:

- `public_key` — required SSH public key in authorized-key format
- `principal` — required certificate principal
- `signing_key` — required signing key name
- `requested_ttl` — optional, defaults to 3600 seconds
- `identity` — optional certificate key ID

`requested_ttl` may be a Go duration string like `15m` or `1h`, or a plain
number of seconds like `3600`.

## Fixed Layout

For security reasons, paths are fixed:

```text
/etc/ssh-vend-local
  profiles
  keys/
    default
    default.pub
```

Signing key names are resolved under `/etc/ssh-vend-local/keys`.
The caller must not be allowed to choose arbitrary filesystem paths.

## Policy File

The policy file is:

```text
/etc/ssh-vend-local/profiles
```

Format:

```text
uid:allowed_principals:allowed_signing_keys:max_ttl
```

Example:

```text
1000:ansadmin,deploy:default,lab:3600
995:ansadmin:default:900
```

Rules:

- `SUDO_UID` identifies the original caller.
- The effective user must be `ssh-vend-signer`.
- The signer trusts `SUDO_UID` only when it is actually running as
  `ssh-vend-signer`.
- Policy is checked against `SUDO_UID` after that execution-context check.
- Lines beginning with `#` are comments.
- Empty lines are ignored.
- Principals and signing keys are comma-separated lists.
- Matching is exact after trimming whitespace.
- A request is allowed if at least one non-comment, non-empty line matches all
  four fields.
- Malformed lines return an error.
- The requested TTL must not exceed the line’s `max_ttl`.
- Source-address restrictions are not implemented yet.

This is the current `SUDO_UID` spoofing-resistance story:

- `SUDO_UID` identifies the original caller.
- The effective user must be `ssh-vend-signer`.
- Policy is checked against `SUDO_UID` only in that trusted signer context.

## Signing Keys

Each signing key is stored as two files:

```text
/etc/ssh-vend-local/keys/<name>
/etc/ssh-vend-local/keys/<name>.pub
```

The `signing_key` request field is a key name, not a path.

Signing key names are restricted to an allowlist of ASCII letters, digits,
`-`, `_`, and `.`. Names containing other characters or `..` are rejected.

## Certificate Extensions

The signer currently hard-codes certificate extensions to only permit PTY.

Future work: make source-address and certificate extensions policy-driven.

## Example Invocation

```bash
cat <<'JSON' | sudo -n -u ssh-vend-signer /usr/local/libexec/ssh-vend-local-signer
{
  "public_key": "ssh-ed25519 AAAA...",
  "principal": "ansadmin",
  "signing_key": "default",
  "requested_ttl": "15m",
  "identity": "semaphore-task-123"
}
JSON
```

The `-n` option prevents `sudo` from prompting for a password, which is useful
for non-interactive automation.
