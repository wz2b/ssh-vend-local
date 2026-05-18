# ssh-vend-local

`ssh-vend-local` gives automation tools short-lived SSH certificate credentials without giving those tools direct access
to the SSH CA private key.

It is intended for development systems, lab automation, Ansible-style runners, Semaphore UI, AWX-like controllers, and
other systems where storing long-lived SSH private keys is undesirable.

## Current status

This project is early-stage.

The currently meaningful end-to-end path is:

```text
ssh-vend-local exec [flags] -- COMMAND ...
```

Some commands are still scaffolding or TODOs. See the wiki for current status and design notes.

## What it does

At a high level:

1. `ssh-vend-local` generates a temporary SSH keypair.
2. It asks `ssh-vend-local-signer` to sign the public key.
3. The signer validates the request against local policy.
4. The signer returns an OpenSSH user certificate.
5. `ssh-vend-local` starts a temporary SSH agent containing the key and certificate.
6. The requested command runs with `SSH_AUTH_SOCK` pointed at that agent.

The target SSH servers do not run project-specific software. Certificate validation is handled by OpenSSH `sshd`.

## Documentation

The main documentation lives in the project wiki:

- [Home](../../wiki)
- [Project Status](../../wiki/Project-Status)
- [Architecture](../../wiki/Architecture)

## Build

```text
TODO
```

## Install

```text
TODO
```

## Basic usage

```text
ssh-vend-local exec [flags] -- ssh user@example-host
```

or:

```text
ssh-vend-local exec [flags] -- ansible-playbook site.yml
```

## Security note

The goal of this project is to avoid storing long-lived SSH private keys in automation platforms.

The SSH CA private key is readable only by the dedicated signing identity, not by ordinary callers. Callers request
certificates through a narrow helper, and the helper enforces local policy before signing.

## License

This project is licensed under the MIT License.

See [LICENSE.txt](LICENSE.txt) for details.

