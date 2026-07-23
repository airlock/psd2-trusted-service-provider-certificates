# file: diff_certs.py
import sys
import re
import hashlib

def read_pem_blocks(path: str) -> list[bytes]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = f.read()
    pattern = re.compile(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
        re.DOTALL
    )
    matches = pattern.findall(data)
    return [f"-----BEGIN CERTIFICATE-----{m}-----END CERTIFICATE-----\n".encode("ascii") for m in matches]

def canonical_hash(pem: bytes) -> str:
    text = pem.decode("ascii", errors="ignore")
    body = re.search(
        r"-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE-----",
        text,
        re.DOTALL
    )
    if not body:
        return ""
    clean = re.sub(r"\s+", "", body.group(1)).encode("ascii")
    return hashlib.sha1(clean).hexdigest()

def main():
    if len(sys.argv) != 3:
        print("Usage: python diff_certs.py <base.pem> <compare.pem>")
        sys.exit(1)
    base_path, compare_path = sys.argv[1], sys.argv[2]
    base_hashes = {canonical_hash(p) for p in read_pem_blocks(base_path)}
    compare_certs = read_pem_blocks(compare_path)
    diff = [pem for pem in compare_certs if canonical_hash(pem) not in base_hashes]
    for pem in diff:
        sys.stdout.write(pem.decode("ascii") + "\n")

if __name__ == "__main__":
    main()

