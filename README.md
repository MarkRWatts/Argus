# Argus

A native macOS menu-bar app that watches your Mac's process table in real time
for **living-off-the-land (LOLBin) attack patterns** — malicious use of
Apple's own signed, trusted command-line tools (`osascript`, `curl`, `xattr`,
`launchctl`, `security`, `dscl`, `csrutil`, and others) in the sequences and
argument shapes real adversary tradecraft actually uses. Everything runs
locally; nothing is ever sent anywhere.

See the [build plan](https://claude.ai/code/artifact/d7458060-daa3-4e99-8990-7d5734d821e7)
for the full design rationale.

![Argus dashboard — orbit view, risk gauge, activity sparkline, and the event feed](screenshot.png)

## Why this, specifically

Modern macOS intrusions increasingly avoid dropping custom malware binaries —
Gatekeeper and notarization make that expensive to get past. Instead they
chain together binaries Apple already ships and already trusts: an
`osascript` privilege-escalation prompt, a `curl | bash` fetch-and-execute, an
`xattr -d com.apple.quarantine` to dodge Gatekeeper, a `launchctl load` for
persistence. No single line looks like a virus. The signal is in the
**sequence and the arguments** — exactly the class of activity a one-shot
file scanner can't see, because there's no file to scan. Argus gives an
individual user that visibility with an interface actually worth glancing at,
without requiring enterprise EDR tooling or kernel entitlements.

## What it looks like

- **Orbit view** — a live radial visualization: every newly-spawned process
  launches from a central node and drifts into orbit; color and size encode
  severity; a parent process still on screen gets an arc drawn to its child,
  so a whole attack chain visually clusters instead of reading as scattered
  log lines.
- **Risk gauge** — an arced meter for the aggregate threat score, which
  decays over time so it reflects recent posture, not a lifetime tally.
- **Event feed** — reverse-chronological, monospaced, severity-striped,
  tagged with the technique it matched; click a row to expand the full
  command line and explanation.
- **Activity sparkline** — rolling 5-minute histogram of matched events.
- **Menu bar icon** — tints calm teal → amber → red with current posture, so
  you get the gist without opening the window. Argus runs as a menu-bar-only
  app (no Dock icon, no Cmd+Tab entry); closing the main window just hides
  it — reopen it any time via "Open Argus" in the menu bar dropdown.
- **Search & severity filters** — a search field (matches executable,
  command, or technique) plus toggleable severity chips above the feed.
- **Session drill-down** — click the pid on any event to focus the feed on
  every event sharing that process's parent, so a multi-step chain reads as
  one group instead of scattered rows. "Clear" returns to the full feed.
- **Activity history** — a day-by-day heatmap (last ~12 weeks) and a
  top-techniques chart, from the "HISTORY" stat in the header. Matched
  events persist to disk now, so this — and the event feed itself — survives
  a restart instead of resetting to empty.
- **System notifications** — a real macOS notification for matched events at
  or above a threshold you choose (off by default beyond critical-only).
  Notifications carry "Show in Argus" and "Allowlist…" action buttons — the
  allowlist action goes through the exact same Touch ID gate as the in-app path.
  Authorization is requested once on first launch.
- **Event export** — right-click an event to "Copy as JSON"; from the History
  panel, export the full event history as JSON or CSV (RFC 4180-quoted so
  command lines with embedded commas and quotes don't misalign spreadsheets).
- **Settings** (gear icon in the header) — poll interval and risk-decay
  half-life are tunable now rather than fixed constants, the notification
  threshold, and a "Launch at login" toggle (macOS 13+, uses SMAppService).

The app is dark-only by design, matching a monitoring-console identity — it
does not follow the system light/dark appearance toggle.

## How detection works

`ProcessMonitor` samples `ps -axww -o pid,ppid,user,command` roughly every 1.2s
and diffs it against the previous sample to find newly-spawned processes.
Each new process is checked against every active rule; a match becomes an
event with severity, a MITRE technique label, and an explanation.

The sample includes the user column now, so rules can match `User` and
`ParentUser` fields. Parent context (image, command line, and user) is
resolved from a cross-tick cache retained for ~3 polling intervals, so a
short-lived parent that exits before the next poll still resolves for
parent-keyed rules — a common race in LOLBin chains where a spawned parent
like `sh -c` is gone from the process table by the next sample.

The `ps` invocation has a 10-second hard timeout. After 3 consecutive
sampling failures, the app enters a visible "degraded" state: the menu bar
icon switches to a warning triangle, a warning row appears in the flyout, and
a MONITOR DEGRADED badge shows in the header. This prevents a failed sample
from being mistaken for "no processes running". Recovery is automatic.

This is **polling-based, not kernel-event-based** — deliberately. True
exec()-level capture on macOS requires the `endpoint-security` entitlement,
which Apple grants by application review, not something obtainable
unattended in one evening. Polling trades sub-second precision for zero
entitlements and zero permission prompts, which fits a personal visibility
tool better than an enterprise agent. The tradeoff: a process that starts and
exits within the ~1.2s window can be missed as an individual event (though a
parent shell invoking it inline is still visible, since the parent's full
command line is what `ps` reports).

### Sequence and chain correlation

When distinct techniques fire in the same process tree within a rolling
10-minute window, Argus emits a synthetic "Suspicious sequence" event. Its
severity is escalated one level above the members' maximum (capped at
critical), and the event lists the member processes and rules. This is the
signal the "Why this, specifically" section calls out: a single LOLBin invocation is often
unremarkable, but two or more different techniques firing inside the same
process tree is a much stronger indicator. Same-rule refires, same-pid
multi-rule matches, and process trees related only through launchd don't
qualify as chains.

### Persistence-artifact watcher

An independent, event-driven sensor watches standard macOS persistence
locations: `~/Library/LaunchAgents`, `/Library/LaunchAgents`,
`/Library/LaunchDaemons`, and `/etc/periodic`. Added or modified files are
reported with elevated severity; removals are also watched. Baseline state
at startup is silent, but the watcher catches persistence artifacts even
when the writing process was too short-lived for the polling monitor to ever
sample it. Allowlist filtering deliberately doesn't apply to these events —
a persistence artifact change is a different thing than an allowlisted
process.

### Tamper evidence

The app records HMAC-SHA256 MACs of `rules-state.json` and `allowlist.json`
on every authenticated write into a sidecar `integrity.json` file. The signing
key is stored in the login Keychain (service "Argus", account
"integrity-key") rather than on disk, so rewriting the
guarded files in place is not by itself enough to also fix up their MACs. At
launch, any mismatch between a file's current contents and its recorded MAC
is surfaced as a critical "Detection state modified outside Argus" event (T1562.001),
so the tamper itself becomes visible in the feed. This is evidence, not prevention — a same-user attacker can still rewrite the files, but no longer
silently.

## Rule format and management

Rules are [Sigma](https://github.com/SigmaHQ/sigma) — the open, vendor-
neutral YAML format the wider detection-engineering community actually
publishes in, rather than a bespoke format invented for this app. A rule is
a `logsource` (we only match `category: process_creation`, `product: macos`
or Linux), a named `detection` block of field/modifier/value selections, and
a `condition` string combining those selections. `Sources/Argus/Sigma/` is a
real, if partial, implementation of that spec: a hand-rolled YAML parser,
a condition-language parser/evaluator, and a field matcher — not a re-skin
of the old pattern list.

The condition language now supports the general `N of selection_*` quantifier
(not just `1 of` and `all of`). The matcher supports `base64`, `base64offset`
(all three byte-alignment encodings, verified against SigmaHQ reference
vectors), and `cased` modifiers for case-sensitive comparison. Keyword
selections (those with no field name) match against all record fields per
spec, not just CommandLine. Rules whose `logsource` is incompatible
(something other than `process_creation`/`macos` or portable Linux techniques)
are skipped at load time; a count is shown in the rule browser
alongside the rule count in the header.

**85 rules ship with the app**, sourced from three places:

- **67 rules** imported verbatim from `SigmaHQ/sigma`'s `rules/macos/process_creation/` —
  a real, actively-maintained community ruleset (account/SIP/security-tool
  discovery, LaunchAgent and cron persistence, TCC and keychain access,
  known macOS malware families like XCSSET, and much more).
- **8 rules** imported verbatim from `SigmaHQ/sigma`'s Linux `process_creation`
  set — genuinely portable shell/interpreter techniques (netcat/perl/php/
  python/ruby reverse shells, base64 pipe-to-shell) that apply unchanged on
  macOS, since it's the same shell tooling.
- **10 rules** authored for Argus, filling gaps neither imported set covered
  (TCC.db tampering, browser cookie/session theft, pipe-to-interpreter
  fetch-and-execute, credential piping to `sudo -S`, AMFI/code-signing
  tampering, and others).

See `Resources/Rules/NOTICE.md` for full attribution and license details
(SigmaHQ's rules are DRL 1.1; imported files are unmodified).

**Managing rules**: the gear-adjacent "RULES LOADED" stat in the header
opens a rule browser — search, filter by source, expand a rule to read its
description and raw YAML, and toggle any rule off without deleting it
(persisted, survives restarts). **Adding your own**: drop a `.yml` file
(standard Sigma `process_creation`/`macos` format) into the folder the
"Rules folder" button reveals in Finder, then hit "Reload" — no rebuild
required. A rule you write there shows up tagged "Your rules" in the
browser, exactly like the bundled ones.

Toggling a rule requires Touch ID (or your account password as fallback) —
enabling/disabling detections is exactly the kind of thing a LOLBin-style
attacker with local execution would want to do silently before running the
technique it catches, so it isn't a free, unaudited click. Every attempt —
granted or denied, either direction — is written to
`~/Library/Logs/Argus/argus.log`.

## Managing false positives

If a rule fires on something you know is your own legitimate automation,
right-click the event in the feed and choose "Allow future … alerts from
…". This suppresses that specific (rule, executable) pair going forward —
allowlisting one automation's use of `osascript` won't blind Argus to a
*different* technique that happens to also involve `osascript`. Review or
revoke allowlist entries from the "ALLOWLISTED" counter in the header.
Nothing is suppressed silently: the header also shows a running count of
events an allowlist rule has hidden.

Adding or revoking an allowlist entry requires Touch ID/password too, for
the same reason as toggling a rule — it's a way to blind a detection, so
it isn't a free, unaudited click. Same log, same attempt-either-way
guarantee.

## Running it

The built app isn't committed (see `.gitignore`) — only the source and a
build script are. To build and launch:

```bash
./scripts/build_app.sh
open build/Argus.app
```

Requires Xcode command line tools (`xcode-select -p`) and macOS 13+. No
network access, no special permissions, no entitlements to approve.

The build signs with the first codesigning identity in your keychain (or
`$ARGUS_SIGN_IDENTITY`), falling back to an ad-hoc signature when there is
none, as on CI. A stable identity matters beyond cosmetics: the tamper-
evidence key lives in the Keychain, and its ACL matches the app by signing
identity — ad-hoc signatures change every rebuild, so every rebuild would
re-prompt for Keychain access, while a real identity keeps the ACL matching
across rebuilds (and, for Apple Development certificates, across renewals).

A rolling diagnostic log is written to `~/Library/Logs/Argus/argus.log`
independent of the UI:

```bash
tail -f ~/Library/Logs/Argus/argus.log
```

Allowlist decisions persist to `~/Library/Application Support/Argus/allowlist.json`.
Matched events persist to `~/Library/Application Support/Argus/events.jsonl`
(newline-delimited JSON, capped at the most recent 5000 — trimmed
periodically rather than on every write, so a live tail will occasionally
see the file shrink back down). Disabled-rule state persists to
`~/Library/Application Support/Argus/rules-state.json`, and your own rule
files live in `~/Library/Application Support/Argus/rules/`. An `integrity.json`
sidecar records HMAC-SHA256 MACs of the security-relevant JSON files
(allowlist.json and rules-state.json) to detect out-of-band edits.

## Testing

```bash
swift test
```

119 tests. The Sigma engine is validated two ways: `SigmaEngineTests` checks
the YAML parser, condition evaluator, and matcher against real rule text
fetched from SigmaHQ (including the `N of selection_*` quantifier, `base64`/
`base64offset`/`cased` modifiers, and keyword matching), and `BundledRulesTests`
loads all 85 shipped rule files, asserts structural invariants, and — for the
10 Argus-authored rules — verifies they match what they claim to. Also
covered: `RuleStoreTests` (enable/disable persistence, user-rule loading),
`ProcessMonitorTests` (parent-context caching, sampling health tracking),
`AllowlistTests`, `EventStoreTests`, `EventFilterTests`, `HistoryStatsTests`,
`AppSettingsTests`, `EventExportTests` (JSON and CSV serialization),
`ChainCorrelatorTests` (sequence detection), `PersistenceWatcherTests`
(artifact diffing and event generation), and `IntegrityGuardTests` (MAC
recording and verification).

## Project layout

```
Package.swift                  Swift Package Manager manifest (macOS 13+)
Sources/Argus/
  App.swift                    App entry point — main window + MenuBarExtra
  Models.swift                 Severity, RawProcess, ProcessEvent, OrbitNode (Codable)
  Sigma/
    YAMLValue.swift               minimal YAML document tree
    YAMLParser.swift              hand-rolled block-YAML parser
    SigmaRule.swift                rule model + YAML→model mapping
    SigmaCondition.swift           condition-language parser/evaluator (N of, all of)
    SigmaMatcher.swift             field/selection matching (base64, base64offset, cased)
    RuleStore.swift                loads bundled + user rules, enable/disable, skip count
  ProcessMonitor.swift          ps polling, diffing, risk-score decay, Sigma matching,
                                  cross-tick parent cache, sampling watchdog
  ChainCorrelator.swift         correlates techniques in same process tree (10-min window)
  PersistenceWatcher.swift      event-driven monitoring of LaunchAgents/Daemons/periodic
  IntegrityGuard.swift          HMAC verification of rules-state.json and allowlist.json
  AllowlistStore.swift          persisted (rule, executable) suppression
  EventStore.swift              persisted event history (events.jsonl)
  EventFilter.swift             search/severity/session filter logic
  EventExport.swift             JSON and RFC 4180-quoted CSV serialization
  HistoryStats.swift            day-bucketing + technique-frequency aggregation
  AppSettings.swift             tunable poll interval, decay, notification threshold
  NotificationManager.swift     UNUserNotificationCenter wrapper
  NotificationResponder.swift   notification actions (Show in Argus, Allowlist)
  DiagnosticsLog.swift          on-disk activity log
  Theme.swift                   color/type tokens
  OrbitView.swift               Canvas-based radial visualization
  GaugeView.swift               arced risk meter
  SparklineView.swift           activity histogram
  DashboardView.swift           main window, event feed, filters, all panels
  MenuBarPanel.swift            compact menu-bar popover
Tests/ArgusTests/
  SigmaEngineTests.swift         parser/condition/matcher vs. real SigmaHQ rule text
  BundledRulesTests.swift        all 85 shipped rules load + custom-rule fixtures
  RuleStoreTests.swift           enable/disable persistence, user-rule loading
  AllowlistTests.swift           filter logic + persistence round-trip
  EventStoreTests.swift          history persistence + trimming
  EventFilterTests.swift         search/severity/session filter logic
  EventExportTests.swift         JSON/CSV serialization round-trip
  HistoryStatsTests.swift        day-bucketing + technique-frequency aggregation
  AppSettingsTests.swift         settings persistence/clamping + notification-threshold logic
  ProcessMonitorTests.swift      parent-context caching, health tracking
  ChainCorrelatorTests.swift     sequence detection in process trees
  PersistenceWatcherTests.swift  artifact diffing and event generation
  IntegrityGuardTests.swift      MAC recording and verification
Resources/
  Info.plist                   app bundle metadata
  icon_gen.swift                generates the app icon programmatically
  Rules/
    NOTICE.md                     attribution — what's imported vs. authored, and under what license
    SIGMA_LICENSE.txt             SigmaHQ/sigma's license file
    imported/                     67 rules verbatim from SigmaHQ macOS process_creation
    imported-portable/            8 rules verbatim from SigmaHQ Linux process_creation (portable shell techniques)
    custom/                       10 rules authored for Argus, filling gaps in the imported sets
scripts/
  build_app.sh                  release build → signed .app bundle (bundles Resources/Rules)
  sync_sigma_rules.sh           manual dev tool to refresh bundled SigmaHQ rules from upstream
.github/workflows/
  ci.yml                        runs swift test + app build on every push/PR
```

## Non-goals

Not a System Extension, not a blocker/firewall, not a cloud product. It
observes and visualizes; it takes no automated action on your processes, and
nothing about your machine ever leaves it.

## License

Argus's own code and the rules under `Resources/Rules/custom/` are MIT —
see [LICENSE](LICENSE). The rules imported verbatim from SigmaHQ under
`Resources/Rules/imported/` and `imported-portable/` remain under the
[Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License)
— see [Resources/Rules/NOTICE.md](Resources/Rules/NOTICE.md).
