# SSH Token Vending Machine

ssh-vend-local is a local SSH certificate vending utility for development, lab automation, and automation-controller
integration.

The project lets an unprivileged process generate a short-lived SSH keypair, ask a tightly-scoped privileged helper to
sign the public key, expose the resulting private key + certificate through a temporary SSH_AUTH_SOCK, and then run
another command using that temporary credential.

The design goal is simple:

**Give automation tools short-lived SSH certificate access without giving those tools direct read access to the SSH CA
private key.**

This is especially useful for tools like Semaphore UI, AWX-style automation runners, development scripts, and lab
systems where storing long-lived SSH private keys in the automation platform is risky.

## Project Status

Project status

This repository is early-stage but already contains the core building blocks:

- ssh-vend-local
    - unprivileged client CLI
    - generates ephemeral SSH keys
    - asks an external signer to sign the ephemeral public key
    - starts an in-process SSH agent containing the certified key
- runs a child command with SSH_AUTH_SOCK pointed at that temporary agent
- ssh-vend-local-signer
    - privileged stdin/stdout signing helper
    - intended to run as the dedicated Unix user ssh-vend-signer
    - reads one JSON signing request from stdin
    - enforces /etc/ssh-vend-local/profiles
    - signs only with keys from /etc/ssh-vend-local/keys
    - writes one OpenSSH user certificate line to stdout

Some CLI commands are scaffolding/TODOs. In particular, init-ca, sign, and doctor currently print placeholder output,
and semaphore-agent currently exists as a stub. The currently meaningful end-to-end path is:

```text
ssh-vend-local exec [flags] -- COMMAND ...
```

with ssh-vend-local-signer installed and reachable through sudo.

## Why use SSH Certificates?

Traditional automation systems often store a private SSH key and reuse it for many jobs. That works, but it creates a
long-lived secret with broad blast radius.

OpenSSH user certificates give us a better pattern:

1. Servers trust an SSH user CA public key.
1. A client generates a temporary keypair.
1. A signer signs the temporary public key into a short-lived user certificate.
1. The client uses the temporary private key + certificate to connect.
1. The credential expires automatically.

The target server does not need the caller’s raw public key in authorized_keys. Instead, sshd validates that the
certificate was signed by a trusted CA and that the certificate principal is allowed for the requested Unix login
account.

## Architecture

```terminaloutput
+----------------------+        sudo         +--------------------------+
| unprivileged caller  | ------------------> | ssh-vend-local-signer    |
|                      |                     | runs as ssh-vend-signer  |
| ssh-vend-local exec  |                     |                          |
+----------+-----------+                     +------------+-------------+
           |                                              |
           | 1. generate ephemeral keypair                |
           | 2. send JSON request on stdin                |
           |                                              |
           |                         3. read policy file  |
           |                         4. read CA key       |
           |                         5. sign certificate  |
           |                                              |
           | <--------------------------------------------+
           | 6. receive OpenSSH cert line on stdout
           |
           | 7. start in-process SSH agent
           | 8. run child command with SSH_AUTH_SOCK
           v
+----------------------+
| ssh / ansible / etc. |
+----------------------+
```

The private CA key is not readable by the ordinary caller. The caller can only request signing through the helper, and
the helper enforces policy based on the original sudo caller UID.

## Binaries

ssh-vend-local

The unprivileged client.

Current command surface:

```bash
ssh-vend-local init-ca
ssh-vend-local sign
ssh-vend-local exec
ssh-vend-local print-server-config
ssh-vend-local doctor
ssh-vend-local semaphore-agent
```

The useful command is `exec`.

## Signer

The signer is a small executable that runs as a user (using sudo) who has direct access to the
certificates. It is run by the agent as:

````
ssh-vend-local-signer [--debug
````

It reads one JSON request from stding:

```json
{
  "public_key": "ssh-ed25519 AAAA...",
  "principal": "ansadmin",
  "signing_key": "default",
  "requested_ttl": "15m",
  "identity": "semaphore-task-123"
}
```

and writes one OpenSSH user certificate line to stadout:

```terminaloutput
ssh-ed25519-cert-v01@openssh.com AAAA...
```

## Security Model

The core security boundary is between:

- the unprivileged caller, such as a developer, Semaphore worker, or automation service account
- the dedicated signer account, ssh-vend-signer
- the root-owned policy and key directories under /etc/ssh-vend-local

The signer enforces these rules:

1. The helper must be running as effective user ssh-vend-signer.
1. SUDO_UID and SUDO_USER must be present.
1. The original caller UID comes from SUDO_UID.
1. The request must match /etc/ssh-vend-local/profiles.
1. The requested signing key must be a key name, not a path.
1. Signing key names are restricted to ASCII letters, digits, hyphen, underscore, and dot.
1. Signing key names containing .. are rejected.
1. Signing keys are resolved only under /etc/ssh-vend-local/keys.
1. The requested TTL must not exceed the policy maximum.

The ordinary caller should not receive direct filesystem read access to the CA private keys.

**Important SUDO rule**

Do not give callers broad access like this:

```
%ssh-vend-callers ALL=(ssh-vend-signer) NOPASSWD: ALL
```

That would be catastrophically dumb. The caller could run arbitrary commands as ssh-vend-signer, including commands that
read private signing keys.

Use a narrow command rule that allows only the signer helper binary.

## NTP and Clock Risk

SSH user certificates are time-bounded credentials. Their security depends on reasonably accurate clocks on both the
signer and the target SSH servers.

`ssh-vend-local-signer` issues certificates with a validity window derived from the signer host's current time and the
requested TTL. The target SSH server then validates that the certificate is currently within that validity window.

This creates an operational security dependency:

- If the signer clock is wrong, it may issue certificates with incorrect validity windows.
- If a target server clock is moved backward, an expired certificate may appear valid again.
- If a target server clock is moved forward, valid certificates may be rejected early.
- If time synchronization is disrupted, short-lived certificates may fail unpredictably.

For development and lab testing this may be acceptable, but production deployments should treat time synchronization as
part of the security boundary.

Recommended mitigations:

- Run reliable time synchronization on signer hosts and target SSH servers.
- Prefer authenticated time synchronization where available, such as NTS-capable NTP or a trusted internal time source.
- Monitor clock synchronization and clock offset.
- Alert when signer or target hosts drift beyond an acceptable threshold.
- Consider refusing to sign certificates when the signer host is not time synchronized.
- Keep certificate TTLs short enough to reduce replay value, but long enough to tolerate small clock skew.

The signer should never treat caller-requested TTL as authority. TTL must always be clamped by
`/etc/ssh-vend-local/profiles`.

## Configuration Filesystem Layout

```terminaloutput
/etc/ssh-vend-local/
├── profiles
├── keys/
│   ├── default
│   └── default.pub
└── certs/
```

* /etc/ssh-vend-local/profiles
    * root-controlled policy file
* /etc/ssh-vend-local/keys/
    * CA private keys and matching public keys
* /etc/ssh-vend-local/certs/
    * optional operational storage for issued certs

The signer does not allow the caller to supply arbitrary key paths.

## Policy File

The policy file is _/etc/ssh-vend-local/profiles_

Format:

```
uid:allowed_principals:allowed_signing_keys:max_ttl
```

Examples:

```
# uid:allowed_principals:allowed_signing_keys:max_ttl
1000:ansadmin,deploy:default,lab:3600
995:ansadmin:default:900
```

This means:

* UID 1000 may request:
    * principals: ansadmin, deploy
    * signing keys: default, lab
    * maximum TTL: 3600 seconds
* UID 995 may request:
    * principals: ansadmin
    * signing keys: default
    * maximum TTL: 900 seconds

Policy Rules:

* blank lines are ignored
* lines beginning with # are ignored
* values are comma-separated
* matching is exact after whitespace trimming
* malformed lines are errors
* a request is allowed only if one policy line matches:
    * caller UID
    * requested principal
    * requested signing key
    * requested TTL less than or equal to max TTL

## Building

This project uses Go and includes a Taskfile.yml.

Requirements:

* Go
* Task, optional but convenient
* OpenSSH client tools
* sudo

Commands:

```terminaloutput
task build
task build:main
task build:signer
task test
task check
task install
```

## Configuring the local signer

This section sets up a local privileged signer using the fixed layout expected by `ssh-vend-local-signer`.

The signer is intended to run through `sudo` as a dedicated user named `ssh-vend-signer`. Normal callers do **not** get
read access to the SSH CA private key. They send a signing request to the helper over stdin, and the helper signs only
if `/etc/ssh-vend-local/profiles` allows the original caller UID to request that exact principal, signing key, and TTL
combination.

Safety notes before you start:

- Use a dedicated non-login signer account.
- Grant `sudo` access only to the signer helper binary, not to a shell or a broader command pattern.
- Keep the policy in `/etc/ssh-vend-local/profiles` as small and explicit as possible.
- Prefer the minimum allowed principals, minimum allowed signing keys, and shortest practical TTLs.
- `SUDO_UID` is trusted only when the helper is actually running as `ssh-vend-signer`.

### 1. Create the signer user

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ssh-vend-signer
```

### 2. Create the configuration directories

```bash
sudo mkdir -p /etc/ssh-vend-local/keys
sudo mkdir -p /etc/ssh-vend-local/certs
```

Expected layout:

```text
/etc/ssh-vend-local
  profiles
  keys/
    default
    default.pub
  certs/
```

### 3. Generate the initial SSH CA signing keypair

Generate a local OpenSSH CA key named `default`:

```bash
sudo ssh-keygen -t ed25519 \
  -f /etc/ssh-vend-local/keys/default \
  -N '' \
  -C 'ssh-vend-local default user CA'
```

This creates:

```text
/etc/ssh-vend-local/keys/default      # private CA signing key
/etc/ssh-vend-local/keys/default.pub  # public CA key
```

The private key is used only by `ssh-vend-local-signer`.

The public key is copied to target SSH servers and trusted using `TrustedUserCAKeys`.

### 4. Set ownership and permissions

```bash
sudo chown root:root /etc/ssh-vend-local
sudo chmod 0755 /etc/ssh-vend-local

sudo chown root:root /etc/ssh-vend-local/keys
sudo chmod 0755 /etc/ssh-vend-local/keys

sudo chown root:root /etc/ssh-vend-local/certs
sudo chmod 0755 /etc/ssh-vend-local/certs

sudo chown ssh-vend-signer:ssh-vend-signer /etc/ssh-vend-local/keys/default
sudo chmod 0600 /etc/ssh-vend-local/keys/default

sudo chown root:root /etc/ssh-vend-local/keys/default.pub
sudo chmod 0644 /etc/ssh-vend-local/keys/default.pub
```

### 5. Create the policy file

Create `/etc/ssh-vend-local/profiles`.

Format:

```text
uid:allowed_principals:allowed_signing_keys:max_ttl
```

Example:

```text
# comments and empty lines are ignored
1000:ansadmin,deploy:default,lab:3600
995:ansadmin:default:900
```

Meaning:

```text
UID 1000 may request:
  principals: ansadmin, deploy
  signing keys: default, lab
  maximum TTL: 3600 seconds

UID 995 may request:
  principals: ansadmin
  signing keys: default
  maximum TTL: 900 seconds
```

Create the file with a minimal example:

```bash
sudo tee /etc/ssh-vend-local/profiles >/dev/null <<'EOF'
# uid:allowed_principals:allowed_signing_keys:max_ttl
1000:ansadmin,deploy:default:3600
EOF
```

Replace `1000` with the real UID of the user that will invoke the signer through `sudo`.

The values in `allowed_principals` and `allowed_signing_keys` are comma-separated exact matches after trimming
whitespace.

`allowed_signing_keys` contains key names such as `default`, not arbitrary filesystem paths.

`max_ttl` is in seconds. If the caller requests a longer TTL, the request is denied.

For safety, avoid broad catch-all entries. Add only the principals and signing keys a caller actually needs.

You can check a user’s UID with:

```bash
id -u chrisp
```

Set ownership and permissions:

```bash
sudo chown root:ssh-vend-signer /etc/ssh-vend-local/profiles
sudo chmod 0640 /etc/ssh-vend-local/profiles
```

Keep `/etc/ssh-vend-local/profiles` root-controlled. Callers should not be able to modify policy.

`/etc/ssh-vend-local/certs` is where issued certificates can be stored for operational convenience.

### 6. Install the signer binary

Build the project, then install the signer helper:

```bash
task build:signer

sudo install -o root -g root -m 0755 \
  ./bin/ssh-vend-local-signer \
  /usr/local/bin/ssh-vend-local-signer
```

### 7. Allow selected users to invoke the signer through sudo

Create a caller group:

```bash
sudo groupadd --system ssh-vend-callers
```

Add users that may request certificates:

```bash
sudo usermod -aG ssh-vend-callers chrisp
```

For SemaphoreUI, the caller might be something like:

```bash
sudo usermod -aG ssh-vend-callers semaphore
```

Create `/etc/sudoers.d/ssh-vend-local`:

```bash
sudo tee /etc/sudoers.d/ssh-vend-local >/dev/null <<'EOF'
# Allow selected users to invoke the SSH certificate signer.
#
# The signer runs as ssh-vend-signer, which can read the private CA signing keys
# under /etc/ssh-vend-local/keys.
#
# The invoking user does not receive direct read access to the signing keys.
#
# ssh-vend-local-signer uses SUDO_UID as the original caller identity, but only
# trusts it when the effective user is ssh-vend-signer. Policy is then checked
# against SUDO_UID.

Cmnd_Alias SSH_VEND_LOCAL_SIGNER = /usr/local/libexec/ssh-vend-local-signer

%ssh-vend-callers ALL=(ssh-vend-signer) NOPASSWD: SSH_VEND_LOCAL_SIGNER
EOF
```

Keep this sudoers rule narrow. Do not allow a wildcard command, shell, or general-purpose `sudo -u ssh-vend-signer`
access.

Validate the sudoers file:

```bash
sudo visudo -cf /etc/sudoers.d/ssh-vend-local
```

### 8. Test the signer manually

Generate a temporary test keypair:

```bash
tmpdir="$(mktemp -d)"
ssh-keygen -t ed25519 -f "$tmpdir/test_key" -N '' -C 'ssh-vend-local test key'
```

Send a signing request to the signer:

```bash
pubkey="$(cat "$tmpdir/test_key.pub")"

cat <<JSON | sudo -n -u ssh-vend-signer /usr/local/bin/ssh-vend-local-signer
{
  "public_key": "$pubkey",
  "principal": "ansadmin",
  "signing_key": "default",
  "requested_ttl": "15m",
  "identity": "manual-test"
}
JSON
```

To store the issued certificate under `/etc/ssh-vend-local/certs`:

```bash
cat <<JSON | sudo -n -u ssh-vend-signer /usr/local/bin/ssh-vend-local-signer \
  | sudo tee /etc/ssh-vend-local/certs/manual-test-cert.pub >/dev/null
{
  "public_key": "$pubkey",
  "principal": "ansadmin",
  "signing_key": "default",
  "requested_ttl": "15m",
  "identity": "manual-test"
}
JSON
```

Make sure the request matches a real policy entry in `/etc/ssh-vend-local/profiles`. In particular:

- `principal` must be explicitly listed for the caller UID
- `signing_key` must be explicitly listed for the caller UID
- `requested_ttl` must be less than or equal to that entry’s `max_ttl`

Expected output is one OpenSSH certificate line beginning with something like:

```text
ssh-ed25519-cert-v01@openssh.com ...
```

Cleanup:

```bash
rm -rf "$tmpdir"
```

### 9. Install the public CA key on a target SSH server

Copy the public CA key to the target server:

```bash
scp /etc/ssh-vend-local/keys/default.pub root@example-server:/etc/ssh/ssh-vend-local-user-ca.pub
```

On the target server, configure sshd to trust the CA:

```bash
sudo tee /etc/ssh/sshd_config.d/50-ssh-vend-local-ca.conf >/dev/null <<'EOF'
TrustedUserCAKeys /etc/ssh/ssh-vend-local-user-ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
EOF
```

Allow the `ansadmin` certificate principal to log in as the desired Unix account.

For example, to allow certs with principal `ansadmin` to log in as Unix user `ansadmin`:

```bash
sudo mkdir -p /etc/ssh/auth_principals
echo 'ansadmin' | sudo tee /etc/ssh/auth_principals/ansadmin >/dev/null
sudo chmod 0644 /etc/ssh/auth_principals/ansadmin
```

Validate and reload sshd:

```bash
sudo sshd -t
sudo systemctl reload sshd || sudo systemctl reload ssh
```

### Security Model Summary

`ssh-vend-local-signer` trusts `SUDO_UID` as the original caller identity only after verifying that the helper is
actually running as `ssh-vend-signer`.

In other words:

```text
SUDO_UID identifies the original caller.
Effective user must be ssh-vend-signer.
Policy is checked against SUDO_UID.
```

The caller may request:

```text
public_key
principal
signing_key
requested_ttl
identity
```

The signer enforces:

```text
caller UID from SUDO_UID
allowed principals from /etc/ssh-vend-local/profiles
allowed signing keys from /etc/ssh-vend-local/profiles
maximum TTL from /etc/ssh-vend-local/profiles
fixed signing key directory /etc/ssh-vend-local/keys
certificate storage directory /etc/ssh-vend-local/certs
```

The caller never receives read access to the private CA signing key.