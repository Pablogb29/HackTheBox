/**
 * Normalize README image paths for GitHub rendering.
 *
 * 1. cases/HackTheBox/.../screenshots/file.png -> screenshots/file.png
 * 2. file.png -> screenshots/file.png when the file lives in screenshots/
 */
const { readFileSync, writeFileSync, readdirSync, statSync, existsSync } = require("fs");
const { join, normalize, basename } = require("path");

const ROOT = join(__dirname, "..");
const ABSOLUTE_PREFIX_RE = /cases\/HackTheBox\/[^)\s]*?\/screenshots\//g;
const IMAGE_MD_RE = /!\[([^\]]*)\]\(([^)]+)\)/g;

function walk(dir, files = []) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      if (name === ".git" || name === "node_modules") continue;
      walk(full, files);
    } else if (name.endsWith(".md")) {
      files.push(full);
    }
  }
  return files;
}

function normalizeImagePath(readmeFile, rawPath) {
  const rel = rawPath.trim();
  if (!rel || rel.startsWith("http://") || rel.startsWith("https://")) {
    return rel;
  }

  const readmeDir = normalize(readmeFile.replace(/[/\\]README\.md$/, ""));

  let normalized = rel.replace(ABSOLUTE_PREFIX_RE, "screenshots/");
  if (normalized !== rel) {
    return normalized;
  }

  if (normalized.startsWith("screenshots/")) {
    return normalized;
  }

  const directPath = normalize(join(readmeDir, ...normalized.split("/")));
  if (existsSync(directPath)) {
    return normalized;
  }

  const screenshotsPath = normalize(join(readmeDir, "screenshots", basename(normalized)));
  if (existsSync(screenshotsPath)) {
    return `screenshots/${basename(normalized)}`;
  }

  return normalized;
}

let changedFiles = 0;
let replacedCount = 0;

for (const file of walk(ROOT)) {
  const original = readFileSync(file, "utf8");
  const updated = original.replace(IMAGE_MD_RE, (match, alt, path) => {
    const nextPath = normalizeImagePath(file, path);
    if (nextPath === path.trim()) {
      return match;
    }
    replacedCount += 1;
    return `![${alt}](${nextPath})`;
  });

  if (updated !== original) {
    writeFileSync(file, updated, "utf8");
    changedFiles += 1;
    console.log(`fixed: ${file.replace(ROOT + "\\", "").replace(ROOT + "/", "")}`);
  }
}

console.log(`\nDone. ${changedFiles} file(s), ${replacedCount} path(s) updated.`);
