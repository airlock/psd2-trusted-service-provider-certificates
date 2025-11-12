#!/usr/bin/env bash
set -euo pipefail

# Wrapper to run all certificate collection and processing steps.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

WEB_CERTS_FILE="eu_web.pem"
POOL_CERTS_FILE="eu_all.pem"
OUTPUT_CHAIN_FILE="eu_chain.pem"
MERGED_FILE="eu_web_and_chain.pem"

# Download and extract website authentication certificates (web bundle)
./get_web_certs.py "$WEB_CERTS_FILE" 2>>error.log

# Download all national TSLs and extract every available certificate (pool)
./download_all_certs.py "$POOL_CERTS_FILE" 2>>error.log

# Add some predownloaded certificates that cannot be found via public API
cat eu_chain_missing.pem >> "$POOL_CERTS_FILE"

# Build certificate chains from web and pool bundles
./download_chain.py "$WEB_CERTS_FILE" "$POOL_CERTS_FILE" "$OUTPUT_CHAIN_FILE" 2>>error.log

# Show incomplete chains only
INCOMPLETE_CHAINS=$(./show_chains.py "$WEB_CERTS_FILE" "$OUTPUT_CHAIN_FILE" 2>>error.log | awk '/INCOMPLETE CHAINS:/ {flag=1; next} flag')
if [[ -n "$INCOMPLETE_CHAINS" ]]; then
    echo "Incomplete certificate chains detected:"
    echo "$INCOMPLETE_CHAINS"
fi

# Remove incomplete or invalid web certificates
#./delete_partial.py "$WEB_CERTS_FILE" "$OUTPUT_CHAIN_FILE" 2>>error.log

# Merge cleaned web certificates and valid chains into final EU bundle
./merge.py "$WEB_CERTS_FILE" "$OUTPUT_CHAIN_FILE" -o "$MERGED_FILE" 2>>error.log

