# Cybaa maintenance

This fork keeps Cybaa's checkdmarc changes in the library source. The package
and CLI remain named `checkdmarc`; Cybaa builds use a local version such as
`6.0.4+cybaa.1` to distinguish them from the upstream release.

Cybaa currently preserves complete SMTP error replies and uses a five-second
HTTP timeout for BIMI and MTA-STS requests. A failed probe remains a failed
probe; its warning includes the server's response rather than only its code.
These warnings contain diagnostic text, not a complete SMTP session transcript.

## Keeping up with upstream

Start from the selected upstream release and keep Cybaa changes small. Review
the upstream changelog, dependency changes and SMTP behavior before updating.
Retain the mocked SMTP regression cases and the HTTP timeout checks while
bringing in upstream fixes. If upstream includes an equivalent fix, remove the
duplicate Cybaa implementation while preserving its observable behavior.

For each Cybaa release, update `checkdmarc/_constants.py` and the matching
`CHANGELOG.md` heading. The Git tag must exactly match `__version__`, including
the `+cybaa.N` suffix. Increment `N` for another Cybaa build of the same
upstream version. Do not replace a published tag or release asset.

## Publishing an approved release

Release permission follows `AGENTS.md`. Prepare and review the change before
pushing its version tag. CI checks formatting, lint, types, documentation and
package builds, and runs the test suite on Python 3.10 through 3.14.

Pushing a version tag with a `+cybaa.N` suffix to `milkyjoe90/checkdmarc` starts
`.github/workflows/cybaa-release.yml`. It repeats the full CI checks, builds
the source distribution and wheel, and installs the wheel into a fresh virtual
environment outside the checkout. The installed package must report the tag's
version, use a five-second HTTP timeout, and retain a complete mocked SMTP
rejection from both probes. The workflow then publishes the distributions and
`SHA256SUMS` as a GitHub release using the matching changelog entry as its notes.

The Cybaa workflow does not publish to PyPI or deploy documentation. The
upstream release workflow runs only in `domainaware/checkdmarc`. Fork releases
do not claim a successful upstream security scan: check available Dependabot
alerts, code scanning alerts and Dependabot pull requests during release
review, and report unavailable scans explicitly.

Consumers should pin the Cybaa release asset and expected package version,
verify its checksum, and update local setup and container installs together.
They must not modify files inside the installed package to recover Cybaa's
behavior.
