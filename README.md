# Argus

A native macOS menu-bar app that watches your Mac's process table in real time
for **living-off-the-land (LOLBin) attack patterns** — malicious use of
Apple's own signed, trusted command-line tools (`osascript`, `curl`, `xattr`,
`launchctl`, `security`, `dscl`, `csrutil`, and others) in the sequences and
argument shapes real adversary tradecraft actually uses. Everything runs
locally; nothing is ever sent anywhere.

See the [build plan](https://claude.ai/code/artifact/d7458060-daa3-4e99-8990-7d5734d821e7)
for the full design rationale.

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
  you get the gist without opening the window.

## How detection works

`ProcessMonitor` samples `ps -axww -o pid,ppid,command` roughly every 1.2s
and diffs it against the previous sample to find newly-spawned processes.
Each new process's full command line is run through `RuleEngine`, a catalog
of ~20 pattern rules covering macOS-specific LOLBin techniques (Gatekeeper
bypass, keychain/cookie access, LaunchAgent persistence, account/SIP
discovery, reverse-shell primitives, and more), each tagged with a severity
and an informal MITRE ATT&CK-style technique label.

This is **polling-based, not kernel-event-based** — deliberately. True
exec()-level capture on macOS requires the `endpoint-security` entitlement,
which Apple grants by application review, not something obtainable
unattended in one evening. Polling trades sub-second precision for zero
entitlements and zero permission prompts, which fits a personal visibility
tool better than an enterprise agent. The tradeoff: a process that starts and
exits within the ~1.2s window can be missed as an individual event (though a
parent shell invoking it inline is still visible, since the parent's full
command line is what `ps` reports).

## Running it

The built app isn't committed (see `.gitignore`) — only the source and a
build script are. To build and launch:

```bash
./scripts/build_app.sh
open build/Argus.app
```

Requires Xcode command line tools (`xcode-select -p`) and macOS 13+. No
network access, no special permissions, no entitlements to approve.

A rolling diagnostic log is written to `~/Library/Logs/Argus/argus.log`
independent of the UI:

```bash
tail -f ~/Library/Logs/Argus/argus.log
```

## Project layout

```
Package.swift                  Swift Package Manager manifest (macOS 13+)
Sources/Argus/
  App.swift                    App entry point — main window + MenuBarExtra
  Models.swift                 Severity, RawProcess, ProcessEvent, OrbitNode
  RuleEngine.swift              LOLBin pattern catalog
  ProcessMonitor.swift          ps polling, diffing, risk-score decay
  DiagnosticsLog.swift          on-disk activity log
  Theme.swift                  color/type tokens
  OrbitView.swift               Canvas-based radial visualization
  GaugeView.swift               arced risk meter
  SparklineView.swift           activity histogram
  DashboardView.swift           main window layout + event feed
  MenuBarPanel.swift            compact menu-bar popover
Resources/
  Info.plist                   app bundle metadata
  icon_gen.swift                generates the app icon programmatically
scripts/build_app.sh            release build → signed .app bundle
```

## Non-goals

Not a System Extension, not a blocker/firewall, not a cloud product. It
observes and visualizes; it takes no automated action on your processes, and
nothing about your machine ever leaves it.
