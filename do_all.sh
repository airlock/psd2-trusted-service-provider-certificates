#!/usr/bin/env bash
set -euo pipefail

# Wrapper to run all certificate collection and processing steps.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# EU web authentication CAs -> Airlock field "CAs for client certificate selection"
SELECTION_CA_CERTS_FILE="eu_selection_ca_certs.pem"
# Additionally collected chain CAs -> Airlock field "CAs for chain validation and OCSP server validation"
VALIDATION_CA_CERTS_FILE="eu_validation_ca_certs.pem"
# Combined single-file bundle (selection + validation)
FULL_CHAINS_FILE="eu_full_chains.pem"
# Intermediate working files
POOL_CERTS_FILE="eu_all.pem"
OUTPUT_CHAIN_FILE="eu_chain.pem"

# Start with a fresh error log for this run
: > error.log

# Download and extract website authentication certificates (web bundle)
echo "Downloading the EU web authentication CA certificates..."
./get_web_certs.py "$SELECTION_CA_CERTS_FILE" >>error.log 2>&1

# Download all national TSLs and extract every available certificate (pool)
echo "Downloading the certificates of all national trusted lists..."
./download_all_certs.py "$POOL_CERTS_FILE" >>error.log 2>&1

# Add some predownloaded certificates that cannot be found via public API
cat eu_chain_missing.pem >> "$POOL_CERTS_FILE"

# Build certificate chains from web and pool bundles
echo "Building the certificate chains..."
./download_chain.py "$SELECTION_CA_CERTS_FILE" "$POOL_CERTS_FILE" "$OUTPUT_CHAIN_FILE" >>error.log 2>&1

# Show incomplete chains only
INCOMPLETE_CHAINS=$(./show_chains.py "$SELECTION_CA_CERTS_FILE" "$OUTPUT_CHAIN_FILE" 2>>error.log | awk '/INCOMPLETE CHAINS:/ {flag=1; next} flag')
if [[ -n "$INCOMPLETE_CHAINS" ]]; then
    echo "Incomplete certificate chains detected:"
    echo "$INCOMPLETE_CHAINS"
fi

# Remove incomplete or invalid web certificates
#./delete_partial.py "$SELECTION_CA_CERTS_FILE" "$OUTPUT_CHAIN_FILE" 2>>error.log

# Extract the certificates that were collected in addition to the EU web
# certificates to complete the chains (Airlock field "CAs for chain
# validation"; the EU web certificates go into "selection", see README)
python3 diff_certs.py "$SELECTION_CA_CERTS_FILE" "$OUTPUT_CHAIN_FILE" > "$VALIDATION_CA_CERTS_FILE" 2>>error.log

# Merge cleaned web certificates and valid chains into final EU bundle
./merge.py "$SELECTION_CA_CERTS_FILE" "$OUTPUT_CHAIN_FILE" -o "$FULL_CHAINS_FILE" >>error.log 2>&1

if grep -q "WARNING: giving up" error.log; then
    echo "Some downloads failed permanently, see error.log for details."
fi

count_certs() { grep -c "BEGIN CERTIFICATE" "$1"; }

# Size of the DN list built from the unique subject DNs (RFC 8446, certificate_authorities)
dn_list_size() {
    python3 - "$1" 2>/dev/null <<'EOF'
import re, sys
from cryptography import x509
data = open(sys.argv[1], "rb").read()
blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.DOTALL)
dns = {x509.load_pem_x509_certificate(b + b"\n").subject.public_bytes() for b in blocks}
print(2 + sum(2 + len(dn) for dn in dns))
EOF
}

echo
echo "Generated files:"
echo "  $SELECTION_CA_CERTS_FILE ($(count_certs "$SELECTION_CA_CERTS_FILE") certificates) -> CAs for client certificate selection"
echo "    (Distinguished Names: $(dn_list_size "$SELECTION_CA_CERTS_FILE") bytes)"
echo "  $VALIDATION_CA_CERTS_FILE ($(count_certs "$VALIDATION_CA_CERTS_FILE") certificates) -> CAs for chain validation"
echo "  $FULL_CHAINS_FILE ($(count_certs "$FULL_CHAINS_FILE") certificates) -> combined bundle"

