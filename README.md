## Getting Started

This section sets up a local privileged signer using the fixed layout expected by `ssh-vend-local-signer`.

The signer is intended to run through `sudo` as a dedicated user named `ssh-vend-signer`. Normal callers do **not** get read access to the SSH CA private key. They send a signing request to the helper over stdin, and the helper signs only if `/etc/ssh-vend-local/profiles` allows the original caller UID to request that exact principal, signing key, and TTL combination.

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

The values in `allowed_principals` and `allowed_signing_keys` are comma-separated exact matches after trimming whitespace.

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

Keep this sudoers rule narrow. Do not allow a wildcard command, shell, or general-purpose `sudo -u ssh-vend-signer` access.

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

`ssh-vend-local-signer` trusts `SUDO_UID` as the original caller identity only after verifying that the helper is actually running as `ssh-vend-signer`.

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