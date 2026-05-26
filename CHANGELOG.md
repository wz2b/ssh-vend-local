# Changelog

## Unreleased

- Reorganized reusable command/runtime mechanics out of `cmd/ssh-vend-local` into `internal/sshvend/...` packages:
  - `internal/sshvend/cmdline` for shared CLI helpers
  - `internal/sshvend/agentproto` for AGENT/1 stdin/stdout framing
  - `internal/sshvend/agentruntime` for in-process agent socket runtime build/cleanup
  - `internal/sshvend/signerprocess` for external signer process execution
- Kept command entrypoints and semaphore-agent orchestration in `cmd/ssh-vend-local` with no intended behavior change.
- Continued Semaphore-agent cleanup by removing local adapter glue in `cmd/ssh-vend-local/semaphore.go` and moving Semaphore config-body JSON parsing to `internal/sshvend/semaphoreagent`, with no intended behavior changes.
- Moved command-local utility/config implementation files into internal packages:
  - `cmd/ssh-vend-local/config.go` -> `internal/sshvend/config`
  - `cmd/ssh-vend-local/{util.go,keys.go,cert.go,cmdline.go}` -> `internal/sshvend/util`
  with no intended behavior changes.
