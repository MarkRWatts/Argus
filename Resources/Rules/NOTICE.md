# Rule attribution

## `imported/` and `imported-portable/`

67 rules in `imported/` and 8 in `imported-portable/` are unmodified copies
of detection rules from the [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
project (`rules/macos/process_creation/` and a curated subset of
`rules/linux/process_creation/` — genuinely portable shell/interpreter
techniques like netcat/perl/python/php/ruby reverse shells and base64
pipe-to-shell, which apply unchanged on macOS). See `SIGMA_LICENSE.txt` in
this directory for the full license text.

The Sigma rules themselves are released under the
[Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License).
The Sigma specification is public domain. Argus ships these files verbatim,
unmodified, with per-file `author:` fields preserved exactly as published —
credit belongs to the original SigmaHQ contributors, not to this project.

## `custom/`

`argus-gap-fill.yml` contains 10 rules authored specifically for Argus,
covering macOS LOLBin techniques the imported sets didn't have (TCC.db
tampering, browser cookie/session theft, pipe-to-interpreter fetch-and-
execute, credential piping to sudo, and others — see the file itself for
the full list and rationale). Written in the same Sigma format, including
the same field/modifier/condition subset the rest of the catalog uses, so
nothing about how they're loaded or matched is special-cased.

These also carry a non-standard `x-example-match` / `x-example-safe`
extension (an `x-`-prefixed vendor field, a convention tolerated by the
Sigma spec and other tooling for exactly this purpose) — command-line
fixtures the rule should and shouldn't match, used by
`Tests/ArgusTests/BundledRulesTests.swift` to keep every custom rule
self-testing without a parallel hand-maintained fixture list.
