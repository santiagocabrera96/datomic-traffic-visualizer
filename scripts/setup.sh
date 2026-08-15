#!/usr/bin/env bash
set -euo pipefail

# One-shot setup for the local memcached + DynamoDB Local + Datomic
# transactor stack. Installs everything needed, then writes the transactor
# config. Run once; safe to re-run (each step skips work it's already done).

# --- memcached -------------------------------------------------------------

echo "Installing memcached via Homebrew..."
brew install memcached

# --- Datomic Pro ------------------------------------------------------------

# Update this to the current release listed at
# https://docs.datomic.com/on-prem/on-prem.html if the download 404s.
DATOMIC_VERSION="${DATOMIC_VERSION:-1.0.7075}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST_DIR="${DEST_DIR:-${REPO_ROOT}}"
DATOMIC_HOME="${DATOMIC_HOME:-${DEST_DIR}/datomic-pro-${DATOMIC_VERSION}}"

if [ -d "${DATOMIC_HOME}" ]; then
  echo "Datomic Pro already present at ${DATOMIC_HOME}, skipping download."
else
  ZIP="datomic-pro-${DATOMIC_VERSION}.zip"
  URL="https://datomic-pro-downloads.s3.amazonaws.com/${DATOMIC_VERSION}/${ZIP}"

  echo "Downloading Datomic Pro ${DATOMIC_VERSION}..."
  (cd "${DEST_DIR}" && curl -O "${URL}" && unzip -o "${ZIP}")
  echo "Datomic Pro extracted to ${DATOMIC_HOME}"
fi

# --- tshark ------------------------------------------------------------------

echo "Installing tshark (Wireshark CLI) via Homebrew..."
brew install wireshark

# --- DynamoDB Local ----------------------------------------------------------

# Downloads AWS's official DynamoDB Local distribution (DynamoDBLocal.jar +
# native libs) -- a plain OS-level dependency, run later as its own process
# by src/setup.clj, no Docker involved.
DYNAMODB_LOCAL_DIR="${DYNAMODB_LOCAL_DIR:-${DEST_DIR}/dynamodb-local}"
DOWNLOAD_URL="https://s3.us-west-2.amazonaws.com/dynamodb-local/dynamodb_local_latest.tar.gz"

if [ -f "${DYNAMODB_LOCAL_DIR}/DynamoDBLocal.jar" ]; then
  echo "DynamoDB Local already installed at ${DYNAMODB_LOCAL_DIR}, skipping download."
else
  echo "Downloading DynamoDB Local to ${DYNAMODB_LOCAL_DIR}..."
  mkdir -p "${DYNAMODB_LOCAL_DIR}"
  curl -sSL "${DOWNLOAD_URL}" | tar -xz -C "${DYNAMODB_LOCAL_DIR}"
fi

# --- transactor config --------------------------------------------------------

# Writes a transactor config (protocol=ddb-local) -- storage backend for the
# transactor is DynamoDB Local (started above), a process implementing the
# real DynamoDB HTTP API, reachable over the network, and something tshark
# can observe.
DYNAMODB_PORT="${DYNAMODB_PORT:-8000}"
CONFIG="${DATOMIC_HOME}/config/transactor-ddb.properties"

cat > "${CONFIG}" <<EOF
protocol=ddb-local
host=127.0.0.1
port=4336
aws-dynamodb-table=datomic
aws-dynamodb-override-endpoint=localhost:${DYNAMODB_PORT}
storage-idle-expiration-msec=2000
# Disable SSL between peers and the transactor (default is true).
encrypt-channel=false
memory-index-threshold=32m
memory-index-max=256m
object-cache-max=128m
# Route the transactor's storage-object cache through the memcached
# instance started by demo.clj / src/setup.clj's start-all! (\`clj -M demo.clj\`).
memcached=localhost:11211
EOF

echo "Wrote ${CONFIG}"
echo
echo "Done. Capture traffic first: scripts/capture.sh"
echo "Next: clj -M demo.clj"
