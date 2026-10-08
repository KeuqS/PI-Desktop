# ADR 0325: Signed Windows GitHub Releases through SignPath

- Status: Accepted
- Date: 2026-10-08
- Deciders: PI-Desktop core
- Decision: D654
- Amends: ADR 0022, ADR 0197
- Related: D126, D364, D603, D450, ADR 0289, E2E-196d

## Context

Windows tag releases publish an NSIS installer (`PI-Desktop-Setup-<version>.exe`),
a self-extracting portable executable, and a portable ZIP (D126, D364, D603),
and electron-updater installs the NSIS package in-app from `latest.yml`. None of
those artifacts carried an Authenticode signature, so Windows showed an unknown
publisher for every download and SmartScreen warned before the first run.
macOS has been signed and notarized since D450 with the settings recorded in
`06-delivery/06-release-runbook.md`; Windows had no equivalent lane.

SignPath's open-source signing program issues the certificate and keeps the
private key on its own hardware, so the release lane never holds signing
material. The SignPath GitHub connector signs an artifact that a GitHub-hosted
workflow produced: it verifies the GitHub origin metadata, applies an artifact
configuration, and returns the signed files over the same API. Local packaging
without credentials has to keep working (D078 did the same for macOS).

## Decision

1. Every GitHub tag release (`vX.Y.Z`) submits the Windows artifacts of that tag
   to SignPath before the publish job uploads them. `workflow_dispatch` signs too
   unless it passes `sign_windows: false`, which exists only for unsigned debug
   artifacts; tag builds always sign. A tag build without the settings fails
   before it starts packaging.
2. The artifact configuration is versioned with the code at
   `apps/desktop/build/signpath/windows-release-artifacts.xml` instead of living
   only in the SignPath project, so the set of signed files is reviewable. Its
   root element is a `<zip-file>`, because `actions/upload-artifact` stores a
   workflow artifact as a ZIP archive and the connector hands SignPath that
   archive. A `version` parameter, supplied from `apps/desktop/package.json`,
   pins every file name to the version this lane built.
   The subscription enforces its own signature watermark, so the signing
   directives carry no `description` or `description-url` attribute: SignPath
   rejects an artifact configuration that tries to override it.
3. Signed files are the two executables users download
   (`PI-Desktop-Setup-<version>.exe`, `PI-Desktop-Portable-<version>.exe`) plus
   `PI-Desktop.exe` and `resources/bin/pi-desktop-host-core.exe` inside
   `PI-Desktop-Portable-<version>.zip`. The ZIP distribution is extracted by the
   user, who then runs `PI-Desktop.exe` directly, so those copies need their own
   signatures. Electron's own DLLs and third-party native modules keep their
   upstream signatures and are covered by the installer signature.
4. The lane runs six steps: require the settings, resolve the release version,
   upload the three unsigned artifacts as one GitHub workflow artifact, submit
   the signing request with `signpath/github-action-submit-signing-request@v3`
   (`wait-for-completion: true`, bounded at 30 minutes, signed files extracted
   back into `apps/desktop/release`), verify the returned signatures with
   `scripts/verify-windows-release-signing.ps1`, and refresh the updater feed.
5. `latest.yml` and `PI-Desktop-Setup-<version>.exe.blockmap` are regenerated from
   the signed installer by `scripts/refresh-windows-update-feed.mjs`, which
   reuses electron-builder's own block map builder. electron-updater verifies the
   feed's `sha512` before it starts an update installer and rebuilds a
   differential download from the block map, so a feed that still describes the
   unsigned bytes would fail checksum validation after download. A feed that does
   not change fails the lane, because that means the signing request did not
   replace the artifacts.
6. Signing settings are a repository secret (`SIGNPATH_API_TOKEN`) and repository
   variables (signing path slugs and the expected publisher) rather than values
   in the workflow, and the signing steps run on GitHub-hosted runners with
   `actions: read` and `contents: read`.
7. Signature verification is mandatory for the package lane and never local: the
   connector only signs artifacts of a GitHub-hosted workflow run, so a local or
   offline packaging run stays unsigned and is not a release candidate.
8. The signing token belongs to the SignPath CI user that the signing policy
   records as a submitter; an interactive user's token is rejected even when
   that user administers the organization. The lane also needs the linked
   GitHub.com trusted build system, because the policy requires trusted build
   system verification.

## Consequences

- Windows downloads show the certificate's publisher instead of an unknown
  publisher, and an in-app NSIS update is installed from a package whose
  signature the lane verified.
- The signature check pins the publisher common name, so a certificate issued
  under another name fails the release until `SIGNPATH_EXPECTED_PUBLISHER` is
  updated.
- The application executable inside the NSIS installer remains unsigned:
  electron-builder packs it before the signing request runs, and the artifact
  configuration cannot reach into the installer payload. Signing the installed
  copy needs an unpack-sign-repack lane, which is deferred and recorded as a
  known limitation in `06-delivery/06-release-runbook.md`.
- The release lane now depends on SignPath availability and on the connector's
  policy evaluation. A stalled request fails after 30 minutes inside the
  60-minute job budget rather than hanging the release.
- Existing installs keep updating: `app-update.yml` carries no `publisherName`
  for unsigned-era packages, so electron-updater skips its own publisher
  comparison for the first signed update and enforces nothing it cannot satisfy.
