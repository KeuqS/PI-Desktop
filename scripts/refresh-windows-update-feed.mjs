#!/usr/bin/env node
/**
 * Refresh the Windows electron-updater feed after the SignPath signing request
 * replaced the installer bytes (ADR 0324).
 *
 * electron-builder wrote `latest.yml` and `*.exe.blockmap` while the artifacts
 * were still unsigned. Authenticode signing appends a signature and a new PE
 * checksum, so both files describe bytes that no longer exist:
 *
 *   - electron-updater verifies the downloaded installer against the `sha512`
 *     in `latest.yml` before it starts it, so the feed has to carry the signed
 *     file's hash or every in-app update fails with a checksum error;
 *   - the NSIS updater downloads `<installer>.blockmap` and rebuilds the file
 *     from unchanged ranges of the installed version's installer, so a stale
 *     block map would validate ranges against the wrong content.
 *
 * Block maps are regenerated with electron-builder's own block map builder, so
 * the published map is byte-compatible with the one electron-builder would
 * have written for the same file.
 *
 * Usage:
 *   node scripts/refresh-windows-update-feed.mjs <release-directory>
 */
import { createHash } from "node:crypto";
import { createReadStream, existsSync, statSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

export const FEED_FILE = "latest.yml";
export const BLOCK_MAP_SUFFIX = ".blockmap";

/**
 * Resolve electron-builder's block map builder.
 *
 * The file lives inside `app-builder-lib`, a transitive dependency of
 * electron-builder: pnpm's public hoisting places it in the root
 * `node_modules`, and a nested layout keeps it reachable from the desktop
 * package. Both bases are tried so a dependency-layout change fails with a
 * readable message instead of a stack trace.
 */
async function loadBlockMapBuilder() {
  const bases = [
    new URL("../apps/desktop/package.json", import.meta.url),
    new URL("../package.json", import.meta.url),
  ];
  for (const base of bases) {
    try {
      const require = createRequire(base);
      const resolved = require.resolve(
        "app-builder-lib/out/targets/blockmap/blockmap.js",
      );
      return require(resolved).buildBlockMap;
    } catch (error) {
      if (error?.code !== "MODULE_NOT_FOUND") {
        throw error;
      }
    }
  }
  throw new Error(
    "Cannot resolve app-builder-lib/out/targets/blockmap/blockmap.js; run this script from an installed workspace (pnpm install).",
  );
}

async function hashFile(filePath) {
  const hash = createHash("sha512");
  await new Promise((resolve, reject) => {
    const stream = createReadStream(filePath, { highWaterMark: 256 * 1024 });
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", resolve);
  });
  return { sha512: hash.digest("base64"), size: statSync(filePath).size };
}

/** Strip the optional YAML quoting from a scalar value. */
function scalar(value) {
  return value.trim().replace(/^['"]|['"]$/g, "");
}

/**
 * File names referenced by an electron-builder update feed, in feed order:
 * every `- url:` entry of the `files` list plus the top-level `path`.
 */
export function feedFileNames(source) {
  const names = [];
  for (const line of source.split("\n")) {
    const entry = /^\s+-\s*url:\s*(\S+)\s*$/.exec(line);
    if (entry) {
      names.push(entry[1]);
      continue;
    }
    const topLevelKey = /^([A-Za-z][\w-]*):(.*)$/.exec(line);
    if (topLevelKey?.[1] === "path") {
      names.push(scalar(topLevelKey[2]));
    }
  }
  return names.filter((name) => name.length > 0);
}

/**
 * Rewrite every `sha512:`/`size:` field with the digest of the file its feed
 * entry points at. The feed's own layout is preserved: electron-builder's field
 * order, quoting, and comments stay untouched.
 */
export function rewriteFeedDigests(source, digests) {
  const updated = [];
  let inFiles = false;
  let entryFileName = null;
  let primaryFileName = null;

  const text = source
    .split("\n")
    .map((line) => {
      const entry = /^\s*-\s*url:\s*(\S+)\s*$/.exec(line);
      if (entry) {
        inFiles = true;
        entryFileName = entry[1];
        return line;
      }

      const topLevelKey = /^([A-Za-z][\w-]*):(.*)$/.exec(line);
      if (topLevelKey) {
        inFiles = false;
        if (topLevelKey[1] === "path") {
          primaryFileName = scalar(topLevelKey[2]);
        }
      }

      const field = /^(\s*)(sha512|size):\s*(.*)$/.exec(line);
      const fileName = inFiles ? entryFileName : primaryFileName;
      if (field == null || fileName == null) {
        return line;
      }
      const digest = digests.get(fileName);
      if (digest == null) {
        return line;
      }
      const previous = field[3].trim();
      const value = field[2] === "sha512" ? digest.sha512 : String(digest.size);
      if (previous === value) {
        return line;
      }
      updated.push({ fileName, field: field[2], previous, value });
      return `${field[1]}${field[2]}: ${value}`;
    })
    .join("\n");

  return { text, updated };
}

async function main() {
  const releaseDir = process.argv[2];
  if (releaseDir == null) {
    throw new Error(
      "Usage: node scripts/refresh-windows-update-feed.mjs <release-directory>",
    );
  }
  if (!existsSync(releaseDir)) {
    throw new Error(`Release directory does not exist: ${releaseDir}`);
  }

  const feedPath = path.join(releaseDir, FEED_FILE);
  if (!existsSync(feedPath)) {
    throw new Error(
      `No ${FEED_FILE} in ${releaseDir}: the Windows NSIS lane must have produced an updater feed.`,
    );
  }

  const source = await readFile(feedPath, "utf8");
  const fileNames = [...new Set(feedFileNames(source))];
  if (fileNames.length === 0) {
    throw new Error(`${FEED_FILE} does not reference any artifact`);
  }

  const blockMapBuilder = await loadBlockMapBuilder();
  const digests = new Map();
  for (const fileName of fileNames) {
    const filePath = path.join(releaseDir, fileName);
    if (!existsSync(filePath)) {
      throw new Error(
        `${FEED_FILE} references ${fileName}, which is missing from ${releaseDir}`,
      );
    }
    const blockMapPath = `${filePath}${BLOCK_MAP_SUFFIX}`;
    if (existsSync(blockMapPath)) {
      // Rebuilds the map from the signed bytes. The installer itself is left
      // untouched: signing is the signing request's job, not this script's.
      await blockMapBuilder(filePath, "gzip", blockMapPath);
      console.log(`regenerated block map for ${fileName}`);
    }
    digests.set(fileName, await hashFile(filePath));
  }

  const { text, updated } = rewriteFeedDigests(source, digests);
  if (updated.length === 0) {
    throw new Error(
      `No digest in ${FEED_FILE} changed: the signing request left the artifacts untouched, so this feed would publish hashes that do not match a signed release.`,
    );
  }
  for (const change of updated) {
    console.log(
      `${change.fileName}: ${change.field} ${change.previous} -> ${change.value}`,
    );
  }
  await writeFile(feedPath, text);
  console.log(`updated ${FEED_FILE} for ${updated.length} field(s)`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  await main();
}
