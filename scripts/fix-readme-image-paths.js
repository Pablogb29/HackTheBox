/**
 * Normalize README image paths to be relative to each machine/challenge folder.
 * Replaces cases/HackTheBox/.../screenshots/file.png -> screenshots/file.png
 */
const { readFileSync, writeFileSync, readdirSync, statSync } = require("fs");
const { join } = require("path");

const ROOT = join(__dirname, "..");
const IMAGE_PATH_RE = /cases\/HackTheBox\/[^)\s]*?\/screenshots\//g;

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

let changedFiles = 0;
let replacedCount = 0;

for (const file of walk(ROOT)) {
  const original = readFileSync(file, "utf8");
  const updated = original.replace(IMAGE_PATH_RE, () => {
    replacedCount += 1;
    return "screenshots/";
  });

  if (updated !== original) {
    writeFileSync(file, updated, "utf8");
    changedFiles += 1;
    console.log(`fixed: ${file.replace(ROOT + "\\", "").replace(ROOT + "/", "")}`);
  }
}

console.log(`\nDone. ${changedFiles} file(s), ${replacedCount} path(s) updated.`);
