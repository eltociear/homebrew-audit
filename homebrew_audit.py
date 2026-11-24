#!/usr/bin/env python3
"""homebrew-audit - security-scan Homebrew formulae, casks & taps before you install them.

`brew audit` checks style and conventions. It does not ask whether a formula or cask does
something dangerous at install time. This scanner does: pipe-to-shell, quarantine stripping,
Gatekeeper/SIP disabling, credential & keychain access, exfiltration to non-GitHub hosts,
decoded-then-executed payloads, launchd persistence, shell-rc tampering, sudoers/TCC writes,
TLS bypass, unverified plaintext downloads, and install-time fetches that skip the checksum.

It is Ruby-aware: every line is classified by the stanza it lives in (`def install`,
`postflight`, `uninstall`, `zap`, `test do`, `livecheck`, `caveats`) so that a `test do` fixture
string, a `zap trash:` path under ~/Library/LaunchAgents, or a `launchctl` *unload* in
`uninstall` is reported as context, never as risk. Deterministic, no LLM, zero dependencies.

Usage:
  python3 homebrew_audit.py <file.rb|dir> [...]          # local formulae / casks / tap checkouts
  python3 homebrew_audit.py --tap owner/homebrew-xxx     # fetch + scan a whole tap (one tarball)
  python3 homebrew_audit.py --formula wget               # homebrew-core formula (or owner/tap/name)
  python3 homebrew_audit.py --cask iterm2                # homebrew-cask cask
  python3 homebrew_audit.py --installed                  # everything installed on this machine
  python3 homebrew_audit.py owner/tap | name | path      # auto-detect
  add --json for machine-readable output, --all to also list SAFE targets, --verbose for INFO
  exit code 2 if any target is HIGH or CRITICAL (CI-friendly)

As a tap: `brew tap eltociear/audit` then `brew secaudit [name|owner/tap|path]`.
MIT licensed. https://github.com/eltociear/homebrew-audit
"""
import glob
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import urllib.request

UA = {"User-Agent": "homebrew-audit (github.com/eltociear/homebrew-audit)"}

# Where a line lives decides whether a match is risk or context.
#   hook    : def install / post_install / preflight / postflight / installer script
#   top     : stanza-level DSL (url, sha256, depends_on, ...) and anything unclassified
#   remove  : uninstall / uninstall_* / zap  (deleting launchd plists here is cleanup)
#   test    : test do  (fixture strings; never risk)
#   livecheck
#   caveats : text shown to the user (advice, not execution -> capped at MEDIUM)
SCORED = {"hook", "top"}
EVERYWHERE = {"hook", "top", "remove", "caveats"}

PATTERNS = {
    "critical": [
        {
            "id": "pipe_to_shell",
            "name": "Pipe-to-Shell",
            "desc": "Fetches a remote script and executes it directly",
            "ctx": EVERYWHERE,
            "regexes": [
                r"(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:/bin/|/usr/bin/(?:env\s+)?)?(?:sh|bash|zsh|ruby|python[0-9.]*|perl|osascript)\b",
                r"\b(?:sh|bash|zsh)\s+-c\s+[\"']?\$\((?:curl|wget)\b",
                r"\b(?:sh|bash|zsh|ruby|python[0-9.]*)\s+<\(\s*(?:curl|wget)\b",
            ],
        },
        {
            "id": "decoded_exec",
            "name": "Decoded-then-Executed Payload",
            "desc": "Decodes an embedded blob (base64 / hex) and runs it",
            "ctx": EVERYWHERE,
            "regexes": [
                r"(?:eval|instance_eval|class_eval|system|exec|spawn|IO\.popen|Kernel\.\w+)\s*\(?\s*(?:Base64\.(?:decode64|strict_decode64|urlsafe_decode64)|\[?[\"'][^\"']{20,}[\"']\]?\.unpack1?\(\s*[\"'](?:m|H\*))",
                r"base64\s+(?:-d|-D|--decode)\b[^\n]*\|\s*(?:sh|bash|zsh|ruby|python[0-9.]*|perl)\b",
                r"Base64\.(?:strict_)?decode64\([^)]*\)[^\n]*\|\s*(?:sh|bash)\b",
            ],
        },
        {
            "id": "remote_eval",
            "name": "Remote Code Eval",
            "desc": "Evaluates Ruby fetched from the network at install time",
            "ctx": EVERYWHERE,
            "regexes": [
                r"\b(?:eval|instance_eval|class_eval|load)\s*\(?\s*(?:URI\.open|URI\.parse\([^)]*\)\.open|Net::HTTP\.get|open\(\s*[\"']https?://|Utils\.(?:safe_popen_read|popen_read)\(\s*[\"']curl|`curl)",
                r"\bload\s*\(?\s*[\"']https?://",
            ],
        },
        {
            "id": "quarantine_strip",
            "name": "Quarantine Stripping",
            "desc": "Removes com.apple.quarantine so Gatekeeper never checks the app",
            "ctx": EVERYWHERE,
            "regexes": [
                r"xattr\b[^\n]*?\s[\"']?-[a-z]*[dc][a-z]*[\"']?[,\s][^\n]*com\.apple\.quarantine",
                r"xattr\b[^\n]*com\.apple\.quarantine[^\n]*[\"']?-[a-z]*d[a-z]*\b",
                r"\bxattr\b\s*[\"']?,?\s*(?:args:\s*\[)?\s*[\"']?-(?:c|cr|rc|crs|rcs)[\"']?(?:[,\s]|$)",
                r"defaults\s+write\s+com\.apple\.LaunchServices\s+LSQuarantine",
            ],
        },
        {
            "id": "gatekeeper_disable",
            "name": "Gatekeeper / SIP Disable",
            "desc": "Turns off macOS code-signing or integrity protection",
            "ctx": EVERYWHERE,
            "regexes": [
                r"spctl[\"',\s\[\]]*(?:args:)?[\"',\s\[\]]*--(?:master-disable|global-disable|disable)\b",
                r"\bcsrutil[\"',\s\[\]]*(?:args:)?[\"',\s\[\]]*disable\b",
                r"defaults\s+write\s+\S*(?:GKAutoRearm|com\.apple\.security\.GKAutoRearm)",
                r"spctl[\"',\s\[\]]*(?:args:)?[\"',\s\[\]]*--add\b",
            ],
        },
        {
            "id": "credential_exfil",
            "name": "Credential Exfiltration",
            "desc": "Reads a credential and sends it to a non-GitHub host (window match)",
            "ctx": EVERYWHERE,
            "regexes": [],  # computed in scan(): credential term + send primitive + foreign host
        },
        {
            "id": "privileged_tamper",
            "name": "Sudoers / TCC / SSH-Key Tampering",
            "desc": "Writes sudoers rules, the TCC privacy DB, or authorized_keys",
            "ctx": SCORED,
            "regexes": [
                r"\bNOPASSWD\s*:",
                r"(?:>>?|tee\s+(?:-a\s+)?|write|cp|mv|install)\s*[\"(]?\s*/(?:private/)?etc/sudoers",
                r"TCC\.db\b",
                r"(?:>>?|tee\s+-a|write|append|cp|mv)[^\n]*authorized_keys",
            ],
        },
    ],
    "high": [
        {
            "id": "credential_access",
            "name": "Credential / Keychain Access",
            "desc": "Reads SSH keys, cloud credentials, tokens files, or the macOS Keychain",
            "ctx": SCORED,
            "regexes": [
                r"(?:cat|read|File\.read|IO\.read|open|cp|scp|tar|zip|base64|curl)\b[^\n]*(?:\.ssh/(?:id_[a-z0-9]+|identity)\b|\.aws/credentials\b|\.(?:netrc|npmrc|pypirc)\b|\.docker/config\.json|\.kube/config\b|\.config/gh/hosts\.yml)",
                r"\bsecurity\b[\"']?\s*,?\s*[\"']?(?:find-generic-password|find-internet-password|dump-keychain|export)\b",
                r"Library/(?:Application Support/(?:Google/Chrome|BraveSoftware|Firefox)|Cookies)/[^\n]*(?:Login Data|Cookies|key4\.db)",
            ],
        },
        {
            "id": "launchd_persistence",
            "name": "launchd Persistence",
            "desc": "Installs or loads a LaunchAgent/LaunchDaemon from an install hook",
            "ctx": {"hook"},
            "regexes": [
                r"(?:cp|mv|ln|install|write|copy|FileUtils\.\w+|tee|>)[^\n]*Library/Launch(?:Agents|Daemons)",
                r"Library/Launch(?:Agents|Daemons)[^\n]*\.(?:write|install|atomic_write)\b",
                r"launchctl[\"']?\s*,?\s*(?:args:\s*\[)?\s*[\"']?(?:load|bootstrap|enable|submit)\b",
            ],
        },
        {
            "id": "shell_rc_tamper",
            "name": "Shell Startup File Tampering",
            "desc": "Appends to ~/.zshrc / ~/.bashrc / /etc/paths from an install hook",
            "ctx": {"hook"},
            "regexes": [
                r"(?:>>|tee\s+-a|\.write|open\([^)]*[\"']a[\"']|File\.open\([^)]*[\"']a)[^\n]*(?:\.zshrc|\.zprofile|\.zshenv|\.bashrc|\.bash_profile|\.profile|/etc/paths|/etc/profile|/etc/zshrc)",
                r"(?:\.zshrc|\.zprofile|\.zshenv|\.bashrc|\.bash_profile|/etc/paths|/etc/profile)[\"')\s]*(?:,\s*[\"']a[\"']|\.(?:write|puts|<<))",
            ],
        },
        {
            "id": "tls_bypass",
            "name": "TLS Verification Bypass",
            "desc": "Disables certificate checking for a download",
            "ctx": SCORED,
            "regexes": [
                r"\bcurl\b[^\n]*[\s\"'](?:-[a-jl-zA-Z]*k[a-zA-Z]*|--insecure)(?=[\s\"',]|$)",
                r"OpenSSL::SSL::VERIFY_NONE",
                r"--no-check-certificate\b",
                r"http\.sslVerify\s*=?\s*false|GIT_SSL_NO_VERIFY",
            ],
        },
        {
            "id": "unverified_plaintext",
            "name": "Unverified Plaintext Download",
            "desc": "Downloads over http:// with no checksum to catch tampering",
            "ctx": EVERYWHERE,
            "regexes": [],  # computed in scan(): http url + (sha256 :no_check | no sha256)
        },
        {
            "id": "setuid",
            "name": "Setuid / World-Writable",
            "desc": "Makes a binary setuid or a path world-writable",
            "ctx": SCORED,
            "regexes": [
                r"chmod\b[\s\"',(]+(?:-R[\s\"',]+)?(?:[ugo]*\+s\b|0?[4-7][0-7]{3}\b)",
                r"\.chmod\s*\(?\s*0?[4-7][0-7]{3}\b",
            ],
        },
    ],
    "medium": [
        {
            "id": "world_writable",
            "name": "World-Writable Path",
            "desc": "chmod 777 / o+w on an installed path",
            "ctx": SCORED,
            "regexes": [r"chmod\b[\s\"',(]+(?:-R[\s\"',]+)?(?:0?777\b|[ao]\+w\b)"],
        },
        {
            "id": "install_fetch",
            "name": "Install-Time Network Fetch",
            "desc": "Downloads during install instead of via url/resource (skips the checksum)",
            "ctx": {"hook"},
            "regexes": [
                r"\b(?:curl|wget)\s+[^\n]*https?://",
                r"system\s*\(?\s*[\"'](?:curl|wget)[\"']",
                r"\bNet::HTTP\.(?:get|start)|URI\.open\(|\bopen\(\s*[\"']https?://",
                r"\bcurl_download\b|Utils::Curl\.\w+|\bcurl_output\(",
            ],
        },
        {
            "id": "raw_sudo",
            "name": "Raw sudo in Install Script",
            "desc": "Shells out to sudo directly instead of the cask `sudo: true` mechanism",
            "ctx": {"hook"},
            "regexes": [
                r"(?:system|exec|`|%x|run)\s*[\(\[\"'{]*\s*sudo\b",
                r"[\"']/usr/bin/sudo[\"']",
                r"[\"']sudo\s+[a-z/]",
            ],
        },
        {
            "id": "missing_checksum",
            "name": "Missing Checksum",
            "desc": "Formula downloads an archive with no sha256",
            "ctx": EVERYWHERE,
            "regexes": [],  # computed in scan()
        },
        {
            "id": "obfuscation",
            "name": "Content Obfuscation",
            "desc": "Long escaped / packed byte strings",
            "ctx": SCORED,
            "regexes": [
                r"(?:\\x[0-9a-fA-F]{2}){8,}",
                r"(?:\\u[0-9a-fA-F]{4}){8,}",
                r"\.pack\(\s*[\"'](?:H\*|m0?|U\*)[\"']\s*\)[^\n]*(?:eval|system|exec)",
                r"[A-Za-z0-9+/]{200,}={0,2}",
            ],
        },
    ],
    "low": [
        {
            "id": "insecure_url",
            "name": "Plaintext URL (checksummed)",
            "desc": "http:// download, but a sha256 still pins the content",
            "ctx": EVERYWHERE,
            "regexes": [],  # computed in scan()
        },
    ],
    # Capability context: reported (with --verbose / in JSON) but never scored.
    "info": [
        {
            "id": "dynamic_eval",
            "name": "Dynamic Ruby Eval",
            "desc": "eval / instance_eval of a string",
            "ctx": SCORED,
            "regexes": [
                r"(?<![\w.:])eval\s*[\( ]\s*(?![\"'][\w\s]*[\"']\s*\))",
                r"\b(?:instance_eval|class_eval|module_eval)\s*\(?\s*(?:[\"'<%]|\w+\s*\)?$)",
            ],
        },
        {"id": "no_check", "name": "sha256 :no_check", "desc": "Unpinned (auto-updating) download",
         "ctx": EVERYWHERE, "regexes": [r"sha256\s+:no_check"]},
        {"id": "sudo_true", "name": "sudo: true", "desc": "Uses Homebrew's own privileged runner",
         "ctx": EVERYWHERE, "regexes": [r"\bsudo:\s*true\b"]},
        {"id": "pkg_installer", "name": "pkg installer", "desc": "Runs an Apple .pkg installer",
         "ctx": EVERYWHERE, "regexes": [r"^\s*pkg\s+[\"']", r"installer\s+(?:script|manual):"]},
        {"id": "install_hook", "name": "Install hook", "desc": "Has preflight/postflight/post_install code",
         "ctx": EVERYWHERE, "regexes": [r"^\s*(?:preflight|postflight|uninstall_preflight|uninstall_postflight)(?:_steps)?\s+do\b",
                                        r"^\s*def\s+post_install\b"]},
        {"id": "launchd_ref", "name": "launchd reference", "desc": "Mentions launchd plists (cleanup/service)",
         "ctx": EVERYWHERE, "regexes": [r"Launch(?:Agents|Daemons)", r"\blaunchctl\b"]},
        {"id": "system_ext", "name": "System extension / kext", "desc": "Installs or removes a kext/system extension",
         "ctx": EVERYWHERE, "regexes": [r"\bkext\b|systemextensionsctl|kextload"]},
    ],
}

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3}
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "SAFE": 0, "INFO": 0}

STANZA = re.compile(
    r"^\s*(?:(?P<test>test\s+do\b)|(?P<livecheck>livecheck\s+do\b)"
    r"|(?P<remove>(?:zap|uninstall|uninstall_preflight|uninstall_postflight)(?:_steps)?\b)"
    r"|(?P<caveats>(?:caveats\b|def\s+caveats\b))"
    r"|(?P<meta>(?:desc|name|homepage|license)\s)"
    r"|(?P<hook>(?:preflight|postflight)(?:_steps)?\s+do\b|def\s+(?:install|post_install|post_install_steps)\b|installer\s+script:))"
)
HEREDOC = re.compile(r"<<[~-]?([\"'`]?)([A-Z_][A-Z0-9_]*)\1")
CRED_TERM = re.compile(
    r"\.ssh/|\.aws/|\bsecurity\s+find-|\bkeychain\b|\.netrc|\.npmrc|"
    r"ENV\[\s*[\"'][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY)[A-Z0-9_]*[\"']\s*\]|"
    r"\$\{?[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY)[A-Z0-9_]*\b",
    re.I,
)
SEND = re.compile(
    r"curl\b[^\n]*(?:[\s\"']-d\b|--data|[\s\"']-F\b|--form|[\s\"']-T\b|--upload-file|-X[\"',\s]*POST)|"
    r"Net::HTTP(?:::Post|\.post|\.post_form)|\bpost_form\b|\bnc\s+-|/dev/tcp/",
)
HOST = re.compile(r"https?://([A-Za-z0-9.-]+)")
TRUSTED_HOST = re.compile(r"(?:^|\.)(?:github\.com|githubusercontent\.com|ghcr\.io|gitlab\.com|brew\.sh)$", re.I)
URL_LINE = re.compile(r"^\s*url\s+[\"'](?P<u>[^\"']+)[\"'](?P<rest>.*)$")
GIT_URL = re.compile(r"\.git[\"']|:?using(?::|\s*=>)\s*:(?:git|svn|hg|bzr|cvs|fossil)|:?\b(?:tag|revision|branch)(?::|\s*=>)")


def classify(lines):
    """Return a context label per line using indentation + heredoc tracking."""
    ctx = []
    stack = []  # (indent, label)
    heredoc = None
    for line in lines:
        if heredoc is not None:
            ctx.append(stack[-1][1] if stack else "top")
            if line.strip() == heredoc:
                heredoc = None
            continue
        s = line.strip()
        if not s:
            ctx.append(stack[-1][1] if stack else "top")
            continue
        ind = len(line) - len(line.lstrip(" \t"))
        while stack and ind <= stack[-1][0] and not s.startswith((")", "]", "}")):
            stack.pop()
        m = STANZA.match(line)
        if m and m.lastgroup == "meta":
            ctx.append("meta")
            continue
        if m:
            label = m.lastgroup
            # inherit the stricter of nested contexts (e.g. a def inside test do stays test)
            if stack and stack[-1][1] in ("test", "livecheck", "remove"):
                label = stack[-1][1]
            stack.append((ind, label))
        ctx.append(stack[-1][1] if stack else "top")
        h = HEREDOC.search(line)
        if h and not s.startswith("#"):
            heredoc = h.group(2)
    return ctx


_COMPILED = [(sev, pg, [re.compile(r, re.I) for r in pg["regexes"]])
             for sev, groups in PATTERNS.items() for pg in groups]


def _item(sev, pg, ln, matched, line, ctx):
    return {"severity": sev.upper(), "id": pg["id"], "name": pg["name"],
            "description": pg["desc"], "line": ln, "context_block": ctx,
            "matched": matched[:120], "context": line.strip()[:200]}


def _by_id(pid):
    for sev, groups in PATTERNS.items():
        for pg in groups:
            if pg["id"] == pid:
                return sev, pg
    raise KeyError(pid)


def scan(content):
    lines = content.split("\n")
    ctxs = classify(lines)
    findings, info, seen = [], [], set()

    def add(sev, pg, ln, matched, line, ctx):
        key = (pg["id"], ln)
        if key in seen:
            return
        seen.add(key)
        it = _item(sev, pg, ln, matched, line, ctx)
        if sev == "info" or ctx not in pg["ctx"]:
            it["severity"] = "INFO"
            info.append(it)
            return
        if ctx == "caveats" and SEVERITY_RANK[it["severity"]] > SEVERITY_RANK["MEDIUM"]:
            it["severity"] = "MEDIUM"
            it["name"] += " (advised to the user in caveats)"
        findings.append(it)

    for i, line in enumerate(lines):
        ln, ctx = i + 1, ctxs[i]
        if line.lstrip().startswith("#"):
            continue
        for sev, pg, regs in _COMPILED:
            for rx in regs:
                m = rx.search(line)
                if m:
                    add(sev, pg, ln, m.group(0), line, ctx)
                    break

    # credential_exfil: credential term + send primitive + non-GitHub host within +-5 lines
    sev, pg = _by_id("credential_exfil")
    for i, line in enumerate(lines):
        if line.lstrip().startswith("#") or not CRED_TERM.search(line):
            continue
        lo, hi = max(0, i - 5), min(len(lines), i + 6)
        window = [l for l in lines[lo:hi] if not l.lstrip().startswith("#")]
        if not any(SEND.search(l) for l in window):
            continue
        hosts = [h for l in window for h in HOST.findall(l)]
        foreign = [h for h in hosts if not TRUSTED_HOST.search(h)]
        if foreign or (not hosts and any(re.search(r"/dev/tcp/|\bnc\s+-", l) for l in window)):
            add(sev, pg, i + 1, CRED_TERM.search(line).group(0), line, ctxs[i])

    # checksum posture (file-level, anchored to the url line)
    has_sha = re.search(r"^\s*(?:sha256|sha1|md5)\s+(?!cellar:|:no_check)\S", content, re.M)
    no_check = re.search(r"^\s*sha256\s+:no_check", content, re.M)
    is_cask = re.search(r"^\s*cask\s+[\"']", content, re.M) is not None
    for i, line in enumerate(lines):
        m = URL_LINE.match(line)
        if not m or ctxs[i] in ("test", "livecheck"):
            continue
        u, rest = m.group("u"), m.group("rest")
        git = GIT_URL.search(line) or u.endswith(".git") or re.match(r"(?:git|svn|hg|bzr|cvs|file)(?:\+\w+)?://", u)
        plain = u.startswith("http://")
        if plain and (no_check or (not has_sha and not git)):
            sev, pg = _by_id("unverified_plaintext")
            add(sev, pg, i + 1, u, line, ctxs[i])
        elif plain:
            sev, pg = _by_id("insecure_url")
            add(sev, pg, i + 1, u, line, ctxs[i])
        if not is_cask and not has_sha and not git and not no_check and not plain:
            sev, pg = _by_id("missing_checksum")
            add(sev, pg, i + 1, u, line, ctxs[i])

    total, counts = 0, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        total += SEVERITY_SCORE[f["severity"].lower()]
        counts[f["severity"]] += 1
    level = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]), "SAFE")
    findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["line"]))
    info.sort(key=lambda f: f["line"])
    parts = ["%d %s" % (counts[s], s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]]
    return {"risk_score": min(total, 100), "risk_level": level, "kind": "cask" if is_cask else "formula",
            "findings": findings, "info": info,
            "summary": ", ".join(parts) if parts else "No issues found",
            "total_findings": len(findings), "info_count": len(info)}


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
def _fetch(url, binary=False):
    headers = dict(UA)
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("HOMEBREW_GITHUB_API_TOKEN")
    if tok and "api.github.com" in url:
        headers["Authorization"] = "Bearer " + tok
    try:
        data = urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60).read()
        return data if binary else data.decode("utf-8", "replace")
    except Exception:
        return b"" if binary else ""


def _is_package_path(rel):
    parts = rel.split("/")
    if len(parts) == 1:
        return True
    return any(p in ("Formula", "Casks", "HomebrewFormula") for p in parts[:-1])


def tap_repo(name):
    owner, repo = name.split("/", 1)
    return owner, repo if repo.startswith("homebrew-") else "homebrew-" + repo


def from_tap(name, every_rb=False):
    owner, repo = tap_repo(name)
    blob = _fetch(f"https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD", binary=True)
    if not blob:
        return []
    out = []
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile() or not m.name.endswith(".rb"):
                continue
            rel = m.name.split("/", 1)[1] if "/" in m.name else m.name
            if every_rb or _is_package_path(rel):
                f = tf.extractfile(m)
                if f:
                    out.append((f"{owner}/{repo}/{rel}", f.read().decode("utf-8", "replace")))
    return out


def _brew_source_path(name, cask):
    try:
        cmd = ["brew", "info", "--json=v2"] + (["--cask"] if cask else ["--formula"]) + [name]
        d = json.loads(subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout or "{}")
        items = d.get("casks" if cask else "formulae") or []
        return items[0].get("ruby_source_path") if items else None
    except Exception:
        return None


def from_name(name, cask=False):
    if name.count("/") == 2:  # owner/tap/name
        owner, tap, pkg = name.split("/")
        files = from_tap(f"{owner}/{tap}")
        return [(l, t) for l, t in files if l.endswith("/" + pkg + ".rb")]
    repo = "Homebrew/homebrew-cask" if cask else "Homebrew/homebrew-core"
    cands = []
    src = _brew_source_path(name, cask)
    if src:
        cands.append(src)
    low = name.lower()
    if cask:
        cands += [f"Casks/{low[0]}/{low}.rb", f"Casks/{low}.rb"]
    else:
        cands += [f"Formula/{low[0]}/{low}.rb", f"Formula/lib/{low}.rb", f"Formula/{low}.rb"]
    for c in cands:
        t = _fetch(f"https://raw.githubusercontent.com/{repo}/HEAD/{c}")
        if len(t) > 40 and not t.startswith("404"):
            return [(f"{repo}/{c}", t)]
    return []


def from_installed():
    out = []
    try:
        cellar = subprocess.run(["brew", "--cellar"], capture_output=True, text=True).stdout.strip()
        caskroom = subprocess.run(["brew", "--caskroom"], capture_output=True, text=True).stdout.strip()
    except Exception:
        return out
    for p in sorted(glob.glob(os.path.join(cellar, "*", "*", ".brew", "*.rb"))):
        out.append((p, open(p, encoding="utf-8", errors="replace").read()))
    seen = set()
    for p in sorted(glob.glob(os.path.join(caskroom, "*", ".metadata", "*", "*", "Casks", "*.rb")), reverse=True):
        c = p.split(os.sep)[-1]
        if c not in seen:
            seen.add(c)
            out.append((p, open(p, encoding="utf-8", errors="replace").read()))
    return out


def from_path(p, every_rb=False):
    if os.path.isdir(p):
        out = []
        for root, _, files in os.walk(p):
            for f in sorted(files):
                if f.endswith(".rb"):
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, p)
                    if every_rb or _is_package_path(rel) or "/" not in rel:
                        out.append((full, open(full, encoding="utf-8", errors="replace").read()))
        return out
    return [(p, sys.stdin.read() if p == "-" else open(p, encoding="utf-8", errors="replace").read())]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    flags = {a for a in args if a in ("--json", "--all", "--verbose", "--every-rb")}
    args = [a for a in args if a not in flags]
    every = "--every-rb" in flags
    targets = []
    i = 0
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if a == "--tap":
            targets += from_tap(nxt, every); i += 2
        elif a == "--formula":
            targets += from_name(nxt); i += 2
        elif a == "--cask":
            targets += from_name(nxt, cask=True); i += 2
        elif a == "--installed":
            targets += from_installed(); i += 1
        elif a == "--text":
            targets.append(("<text>", nxt)); i += 2
        elif os.path.exists(a) or a == "-":
            targets += from_path(a, every); i += 1
        elif a.count("/") == 1:
            targets += from_tap(a, every); i += 1
        else:
            got = from_name(a) or from_name(a, cask=True)
            if not got:
                print(f"homebrew-audit: could not find {a!r} as a file, tap, formula or cask", file=sys.stderr)
            targets += got; i += 1
    if not targets:
        print("homebrew-audit: nothing to scan", file=sys.stderr)
        return 1

    results, worst = [], "SAFE"
    tally = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE")}
    for label, text in targets:
        r = scan(text[:600000])
        tally[r["risk_level"]] += 1
        if SEVERITY_RANK[r["risk_level"]] > SEVERITY_RANK[worst]:
            worst = r["risk_level"]
        if "--json" in flags:
            results.append({"target": label, **r})
            continue
        if r["risk_level"] == "SAFE" and "--all" not in flags and len(targets) > 1:
            continue
        print(f"{_ICON[r['risk_level']]} {label}  [{r['risk_level']}]  score={r['risk_score']}  "
              f"({r['total_findings']} findings, {r['info_count']} info)")
        for f in r["findings"]:
            print(f"    {f['severity']:8} {f['name']} (line {f['line']}, {f['context_block']})")
            print(f"             {f['context']}")
        if "--verbose" in flags:
            for f in r["info"]:
                print(f"    INFO     {f['name']} (line {f['line']}, {f['context_block']})")
    if "--json" in flags:
        print(json.dumps(results if len(results) != 1 else results[0], indent=1))
    else:
        print(f"\nscanned {len(targets)}: " + ", ".join(f"{v} {k}" for k, v in tally.items() if v))
    return 2 if SEVERITY_RANK[worst] >= SEVERITY_RANK["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main())
