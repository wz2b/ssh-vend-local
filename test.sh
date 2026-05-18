#!/usr/bin/env bash
set -euo pipefail

rm -f ./test_key ./test_key.pub ./test_key-cert.pub

ssh-keygen -t ed25519 \
  -f ./test_key \
  -N '' \
  -C 'ssh-vend-local test key'

pubkey="$(cat ./test_key.pub)"

cat <<JSON | sudo -n -u ssh-vend-signer /usr/local/bin/ssh-vend-local-signer > ./test_key-cert.pub
{
  "public_key": "$pubkey",
  "principal": "ansadmin",
  "signing_key": "default",
  "requested_ttl": "15m",
  "identity": "manual-test"
}
JSON

echo "Certificate written to ./test_key-cert.pub"
ssh-keygen -Lf ./test_key-cert.pub

cat ./test_key-cert.pub

rm test_key test_key.pub test_key-cert.pub
