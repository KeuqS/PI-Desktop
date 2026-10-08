import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  feedFileNames,
  rewriteFeedDigests,
} from "../../../scripts/refresh-windows-update-feed.mjs";

/**
 * Windows release signing contract (D654 / ADR 0325).
 *
 * The Windows lane signs its artifacts with SignPath after electron-builder
 * produced them, so three things can silently disagree: the artifact
 * configuration SignPath applies, the artifact names the workflow uploads, and
 * the hashes electron-updater verifies before it installs an update. Signing
 * only runs on a tagged release, so a mistake here would first surface in a
 * published installer. These tests pin the configuration, the workflow wiring,
 * and the feed refresh, and they run the signature check against a stubbed
 * Authenticode cmdlet to exercise its accept and reject paths without a
 * certificate.
 */

const repoRoot = new URL("../../..", import.meta.url);
const read = (relativePath) => readFileSync(new URL(relativePath, repoRoot), "utf8");
const scriptPath = (relativePath) =>
  fileURLToPath(new URL(relativePath, repoRoot));

const [workflowSource, artifactConfigurationSource, verifyScriptSource] = [
  read(".github/workflows/release.yml"),
  read("apps/desktop/build/signpath/windows-release-artifacts.xml"),
  read("scripts/verify-windows-release-signing.ps1"),
];

const VERSION = "1.2.3";
const WINDOWS_SIGNING_CONDITION =
  "if: matrix.platform == 'windows' && env.WINDOWS_SIGN_RELEASE == 'true'";
const FEED_REFRESH_SCRIPT = scriptPath("scripts/refresh-windows-update-feed.mjs");
const SIGNATURE_CHECK_SCRIPT = scriptPath(
  "scripts/verify-windows-release-signing.ps1",
);

/** PowerShell renders errors with ANSI colour even when stdout is a pipe. */
function unformatted(text) {
  return text.replace(/\u001b\[[0-9;]*m/g, "").replace(/\s+/g, " ");
}

/** PowerShell writes a terminating error to stderr, so assertions read both. */
function describe(result) {
  return unformatted(`${result.stdout}${result.stderr}`);
}

function runFeedRefresh(releaseDir) {
  return spawnSync(process.execPath, [FEED_REFRESH_SCRIPT, releaseDir], {
    encoding: "utf8",
  });
}

/** Store-only ZIP writer: enough to exercise the PowerShell extraction. */
function writeStoredZip(destination, entries) {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  const crc32 = (data) => {
    let value = 0xffffffff;
    for (const byte of data) {
      value = table[(value ^ byte) & 0xff] ^ (value >>> 8);
    }
    return (value ^ 0xffffffff) >>> 0;
  };

  const local = [];
  const central = [];
  let offset = 0;
  for (const [name, data] of entries) {
    const nameBuffer = Buffer.from(name, "utf8");
    const crc = crc32(data);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt32LE(crc, 14);
    header.writeUInt32LE(data.length, 18);
    header.writeUInt32LE(data.length, 22);
    header.writeUInt16LE(nameBuffer.length, 26);
    local.push(header, nameBuffer, data);

    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(20, 4);
    entry.writeUInt16LE(20, 6);
    entry.writeUInt32LE(crc, 16);
    entry.writeUInt32LE(data.length, 20);
    entry.writeUInt32LE(data.length, 24);
    entry.writeUInt16LE(nameBuffer.length, 28);
    entry.writeUInt32LE(offset, 42);
    central.push(entry, nameBuffer);
    offset += header.length + nameBuffer.length + data.length;
  }

  const centralBuffer = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBuffer.length, 12);
  end.writeUInt32LE(offset, 16);
  writeFileSync(destination, Buffer.concat([...local, centralBuffer, end]));
}

test("the artifact configuration signs exactly the uploaded Windows artifacts", () => {
  // GitHub stores a workflow artifact as a ZIP archive, so the connector
  // requires a ZIP root element.
  assert.match(
    artifactConfigurationSource,
    /<zip-file>\s*\n/,
    "the root artifact element must be a zip-file",
  );
  assert.match(
    artifactConfigurationSource,
    /<parameter name="version"/,
    "the artifact names are pinned by a version parameter",
  );

  const artifactPaths = [
    ...artifactConfigurationSource.matchAll(/<(?:include|zip-file)[^>]*path="([^"]+)"/g),
  ].map((match) => match[1]);
  const releaseArtifacts = artifactPaths.filter((path) => path.startsWith("PI-Desktop-"));
  assert.deepEqual(
    [...releaseArtifacts].sort(),
    [
      "PI-Desktop-Portable-${version}.exe",
      "PI-Desktop-Portable-${version}.zip",
      "PI-Desktop-Setup-${version}.exe",
    ],
    "every released Windows artifact is covered",
  );
  for (const path of releaseArtifacts) {
    assert.match(path, /\$\{version\}/, `${path} is not pinned to the release version`);
  }

  // The ZIP distribution is extracted by the user, so the executables inside it
  // need their own signatures.
  assert.deepEqual(
    artifactPaths.filter((path) => !path.startsWith("PI-Desktop-")).sort(),
    ["PI-Desktop.exe", "resources/bin/pi-desktop-host-core.exe"],
  );
  assert.equal(
    (artifactConfigurationSource.match(/<authenticode-sign/g) ?? []).length,
    2,
    "each file set carries one signing directive",
  );
});

test("the release workflow signs Windows artifacts before they are uploaded", () => {
  const buildJob = workflowSource.match(
    /^  build:\n[\s\S]*?(?=^  pi-host-bundle:)/m,
  )?.[0];
  assert.ok(buildJob, "release build job is missing");

  assert.match(workflowSource, /^      sign_windows:/m);
  assert.match(
    workflowSource,
    /WINDOWS_SIGN_RELEASE: \$\{\{ github\.event_name != 'workflow_dispatch' \|\| inputs\.sign_windows == true \}\}/,
    "tag pushes must sign Windows artifacts",
  );
  assert.match(
    buildJob,
    /permissions:\n      actions: read\n      contents: read/,
    "the SignPath connector reads job metadata and the uploaded artifact",
  );

  // Every SignPath step is Windows-only, and a missing setting fails before the
  // expensive packaging phase rather than after it.
  assert.equal(
    (buildJob.match(new RegExp(WINDOWS_SIGNING_CONDITION, "g")) ?? []).length,
    6,
    "all six SignPath steps are gated on the Windows signing lane",
  );
  const requireIndex = buildJob.indexOf("Require Windows signing configuration");
  const packageIndex = buildJob.indexOf("Prepare package inputs");
  assert.ok(
    requireIndex > 0 && requireIndex < packageIndex,
    "the configuration check runs before packaging",
  );
  for (const setting of [
    "secrets.SIGNPATH_API_TOKEN",
    "vars.SIGNPATH_ORGANIZATION_ID",
    "vars.SIGNPATH_PROJECT_SLUG",
    "vars.SIGNPATH_SIGNING_POLICY_SLUG",
    "vars.SIGNPATH_ARTIFACT_CONFIGURATION_SLUG",
  ]) {
    assert.ok(
      buildJob.includes(`missing+=(${setting})`),
      `${setting} is reported when it is missing`,
    );
  }

  const orderedSteps = [
    "Upload unsigned Windows artifacts for signing",
    "Submit the SignPath signing request",
    "Verify signed Windows artifacts",
    "Refresh the Windows updater feed",
    "- name: Upload artifacts",
  ];
  let previous = -1;
  for (const step of orderedSteps) {
    const index = buildJob.indexOf(step, previous + 1);
    assert.ok(index > previous, `${step} is missing or out of order`);
    previous = index;
  }

  assert.match(buildJob, /uses: signpath\/github-action-submit-signing-request@v3/);
  assert.match(
    buildJob,
    /github-artifact-id: \$\{\{ steps\.upload-unsigned-windows\.outputs\.artifact-id \}\}/,
    "the signing request points at the artifact this lane uploaded",
  );
  assert.match(buildJob, /output-artifact-directory: apps\/desktop\/release/);
  assert.match(
    buildJob,
    /version: "\$\{\{ steps\.windows-release-version\.outputs\.version \}\}"/,
    "the version parameter comes from the version this lane built",
  );
  assert.match(
    buildJob,
    /node scripts\/refresh-windows-update-feed\.mjs apps\/desktop\/release/,
  );
});

test("the feed refresh rewrites the signed installer digest and block map", () => {
  const releaseDir = mkdtempSync(join(tmpdir(), "pi-desktop-feed-"));
  try {
    const installer = `PI-Desktop-Setup-${VERSION}.exe`;
    writeFileSync(join(releaseDir, installer), randomBytes(2 * 1024 * 1024));
    writeFileSync(join(releaseDir, `${installer}.blockmap`), randomBytes(512));
    const staleBlockMap = readFileSync(join(releaseDir, `${installer}.blockmap`));
    const staleDigest = "ZHluYW1pYyBmZWVkIGhhc2ggZnJvbSBiZWZvcmUgc2lnbmluZw==";
    writeFileSync(
      join(releaseDir, "latest.yml"),
      [
        `version: ${VERSION}`,
        "files:",
        `  - url: ${installer}`,
        `    sha512: ${staleDigest}`,
        "    size: 1",
        `path: ${installer}`,
        `sha512: ${staleDigest}`,
        "releaseDate: '2026-10-07T01:54:53.421Z'",
        "",
      ].join("\n"),
    );

    const result = runFeedRefresh(releaseDir);
    assert.equal(result.status, 0, result.stderr);

    const installerBytes = readFileSync(join(releaseDir, installer));
    const expectedSha512 = createHash("sha512")
      .update(installerBytes)
      .digest("base64");
    const feed = readFileSync(join(releaseDir, "latest.yml"), "utf8");
    const digestLines = feed
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.startsWith("sha512:") || line.startsWith("size:"));
    assert.deepEqual(digestLines, [
      `sha512: ${expectedSha512}`,
      `size: ${installerBytes.length}`,
      `sha512: ${expectedSha512}`,
    ]);
    assert.match(feed, /releaseDate: '2026-10-07T01:54:53\.421Z'/);
    assert.ok(
      !readFileSync(join(releaseDir, `${installer}.blockmap`)).equals(staleBlockMap),
      "the block map must describe the signed bytes",
    );

    const repeated = runFeedRefresh(releaseDir);
    assert.notEqual(
      repeated.status,
      0,
      "a feed whose artifacts were not signed again must stop the lane",
    );
    assert.match(repeated.stderr, /No digest in latest\.yml changed/);
  } finally {
    rmSync(releaseDir, { recursive: true, force: true });
  }
});

test("the feed refresh refuses a feed whose artifact is missing", () => {
  const releaseDir = mkdtempSync(join(tmpdir(), "pi-desktop-feed-missing-"));
  try {
    writeFileSync(
      join(releaseDir, "latest.yml"),
      [
        `version: ${VERSION}`,
        "files:",
        `  - url: PI-Desktop-Setup-${VERSION}.exe`,
        "    sha512: hash",
        "    size: 1",
        `path: PI-Desktop-Setup-${VERSION}.exe`,
        "sha512: hash",
        "",
      ].join("\n"),
    );
    const result = runFeedRefresh(releaseDir);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /is missing from/);
  } finally {
    rmSync(releaseDir, { recursive: true, force: true });
  }
});

test("feed digests are rewritten in place without reformatting the feed", () => {
  const feed = [
    `version: ${VERSION}`,
    "files:",
    `  - url: PI-Desktop-Setup-${VERSION}.exe`,
    "    sha512: stale-installer-digest",
    "    size: 1",
    `path: PI-Desktop-Setup-${VERSION}.exe`,
    "sha512: 'stale-installer-digest'",
    "releaseDate: '2026-10-07T01:54:53.421Z'",
    "",
  ].join("\n");
  assert.deepEqual(feedFileNames(feed), [
    `PI-Desktop-Setup-${VERSION}.exe`,
    `PI-Desktop-Setup-${VERSION}.exe`,
  ]);

  const digests = new Map([
    [`PI-Desktop-Setup-${VERSION}.exe`, { sha512: "signed-installer-digest", size: 42 }],
  ]);
  const { text, updated } = rewriteFeedDigests(feed, digests);
  assert.equal(updated.length, 3);
  assert.equal(
    text,
    [
      `version: ${VERSION}`,
      "files:",
      `  - url: PI-Desktop-Setup-${VERSION}.exe`,
      "    sha512: signed-installer-digest",
      "    size: 42",
      `path: PI-Desktop-Setup-${VERSION}.exe`,
      "sha512: signed-installer-digest",
      "releaseDate: '2026-10-07T01:54:53.421Z'",
      "",
    ].join("\n"),
    "only the digest fields change",
  );
});

test("the signature check covers the installer, the portable exe, and the ZIP", () => {
  for (const artifact of [
    "PI-Desktop-Setup-$Version.exe",
    "PI-Desktop-Portable-$Version.exe",
    "PI-Desktop-Portable-$Version.zip",
    '"PI-Desktop.exe"',
    '"resources/bin/pi-desktop-host-core.exe"',
  ]) {
    assert.ok(verifyScriptSource.includes(artifact), `${artifact} is not verified`);
  }
  assert.match(verifyScriptSource, /Get-AuthenticodeSignature/);
  assert.match(verifyScriptSource, /SignatureStatus\]::Valid/);
  assert.match(verifyScriptSource, /unexpected certificate/);
});

const powerShellCommand = (() => {
  const command = process.platform === "win32" ? "powershell" : "pwsh";
  const probe = spawnSync(command, ["-NoProfile", "-Command", "$PSVersionTable.PSVersion.Major"], {
    encoding: "utf8",
  });
  return probe.status === 0 ? command : null;
})();

test(
  "the signature check accepts signed artifacts and rejects every broken variant",
  { skip: powerShellCommand == null ? "PowerShell is not installed" : false },
  () => {
    const workDir = mkdtempSync(join(tmpdir(), "pi-desktop-signature-check-"));
    try {
      const releaseDir = join(workDir, "release");
      mkdirSync(releaseDir);
      writeFileSync(join(releaseDir, `PI-Desktop-Setup-${VERSION}.exe`), "installer");
      writeFileSync(join(releaseDir, `PI-Desktop-Portable-${VERSION}.exe`), "portable");
      const archivePath = join(releaseDir, `PI-Desktop-Portable-${VERSION}.zip`);
      const fullArchive = [
        ["PI-Desktop.exe", Buffer.alloc(2048, 1)],
        ["resources/bin/pi-desktop-host-core.exe", Buffer.alloc(1024, 2)],
        ["resources/app.asar", Buffer.alloc(64, 3)],
      ];
      writeStoredZip(archivePath, fullArchive);

      const driverPath = join(workDir, "driver.ps1");
      writeFileSync(
        driverPath,
        [
          "param(",
          "  [string]$Script,",
          "  [string]$ReleaseDirectory,",
          "  [string]$Version,",
          '  [string]$Publisher = "SignPath Foundation",',
          '  [string]$SignerSubject = "SignPath Foundation",',
          '  [string]$Unsigned = ""',
          ")",
          "$unsignedNames = @()",
          'if ($Unsigned) { $unsignedNames = $Unsigned -split "," }',
          // Replaces the Windows-only Authenticode cmdlet with a stub; a
          // function shadows a cmdlet of the same name.
          "function Get-AuthenticodeSignature {",
          "  param([Parameter(Mandatory = $true, Position = 0)][string]$LiteralPath)",
          "  $leaf = [System.IO.Path]::GetFileName($LiteralPath)",
          "  $status = [System.Management.Automation.SignatureStatus]::Valid",
          "  if ($unsignedNames -contains $leaf) {",
          "    $status = [System.Management.Automation.SignatureStatus]::NotSigned",
          "  }",
          "  [pscustomobject]@{",
          "    Status                 = $status",
          '    StatusMessage          = "stub"',
          '    SignerCertificate      = [pscustomobject]@{ Subject = "CN=$SignerSubject" }',
          '    TimeStamperCertificate = [pscustomobject]@{ Subject = "CN=timestamp" }',
          "  }",
          "}",
          "& $Script -ReleaseDirectory $ReleaseDirectory -Version $Version -ExpectedPublisher $Publisher",
          "",
        ].join("\n"),
      );

      const runVerify = (extraArgs) =>
        spawnSync(
          powerShellCommand,
          [
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            driverPath,
            "-Script",
            SIGNATURE_CHECK_SCRIPT,
            "-ReleaseDirectory",
            releaseDir,
            "-Version",
            VERSION,
            ...extraArgs,
          ],
          { encoding: "utf8" },
        );

      const signed = runVerify([]);
      assert.equal(signed.status, 0, describe(signed));
      for (const label of [
        "NSIS installer",
        "portable executable",
        "PI-Desktop.exe",
        "resources/bin/pi-desktop-host-core.exe",
      ]) {
        assert.ok(
          describe(signed).includes(`signed: ${label}`),
          `${label} was not reported as signed`,
        );
      }

      const unsigned = runVerify(["-Unsigned", `PI-Desktop-Portable-${VERSION}.exe`]);
      assert.notEqual(unsigned.status, 0);
      assert.match(describe(unsigned), /is not validly signed/);

      const wrongPublisher = runVerify(["-Publisher", "Someone Else"]);
      assert.notEqual(wrongPublisher.status, 0);
      assert.match(
        describe(wrongPublisher),
        /was signed by an unexpected certificate/,
      );

      rmSync(archivePath);
      const missingArtifact = runVerify([]);
      assert.notEqual(missingArtifact.status, 0);
      assert.match(describe(missingArtifact), /Missing Windows release artifact/);

      writeStoredZip(archivePath, [fullArchive[0]]);
      const missingMember = runVerify([]);
      assert.notEqual(missingMember.status, 0);
      assert.match(
        describe(missingMember),
        // PowerShell wraps its error rendering across lines with a "|" gutter.
        /does not contain[\s\S]*pi-desktop-host-core\.exe/,
      );
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  },
);
