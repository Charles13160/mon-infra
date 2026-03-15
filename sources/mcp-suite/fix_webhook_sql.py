import sys
p = "/srv/mcp-suite/internal/api/handlers/license.go"
with open(p) as f: c = f.read()

a  = '"UPDATE revocations SET webhook_attempts=$1 WHERE license_key=$2 ORDER BY revoked_at DESC LIMIT 1"'
b  = '"UPDATE revocations SET webhook_attempts=$1 WHERE id=(SELECT id FROM revocations WHERE license_key=$2 ORDER BY revoked_at DESC LIMIT 1)"'
c2 = '"UPDATE revocations SET webhook_pushed_at=$1, webhook_attempts=$2 WHERE license_key=$3 ORDER BY revoked_at DESC LIMIT 1"'
d2 = '"UPDATE revocations SET webhook_pushed_at=$1, webhook_attempts=$2 WHERE id=(SELECT id FROM revocations WHERE license_key=$3 ORDER BY revoked_at DESC LIMIT 1)"'

if a not in c:  print("ERR: pattern1 not found"); sys.exit(1)
if c2 not in c: print("ERR: pattern2 not found"); sys.exit(1)
c = c.replace(a, b).replace(c2, d2)
with open(p, "w") as f: f.write(c)
print("PATCH_OK")
