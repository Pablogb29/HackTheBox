/**
 * Fix UTF-8 mojibake in Markdown (UTF-8 bytes misinterpreted as Windows-1252).
 */
const { readFileSync, writeFileSync, readdirSync, statSync } = require("fs");
const { join } = require("path");

const ROOT = join(__dirname, "..");

const REPLACEMENTS = [
  ["\u00e2\u2020\u2019", "\u2192"], // â†' →
  ["\u00e2\u0153\u2026", "\u2705"], // âœ… → ✅
  ["\u00f0\u0178\u008f\u0081", "🏁"],
  ["\u00f0\u0178\u2019\u00a1", "💡"],
  ["\u00f0\u0178\u201d\u2014", "🔗"],
  ["\u00e2\u20ac\u2122", "\u2019"], // â€™ → '
  ["\u00e2\u20ac\u201d", "\u2014"], // â€" → —
  ["\u00e2\u20ac\u0153", "\u201c"], // â€œ → "
  ["\u00e2\u20ac\u009d", "\u201d"], // â€ → "
  ["\u00e2\u20ac\u201c", "\u2013"], // â€" → –
  ["\u00e2\u20ac\u00a6", "\u2026"], // â€¦ → …
  ["\u00c2\u00a7", "\u00a7"], // Â§ → §
  ["Let\u00c2\u00b4s", "Let's"], // LetÂ´s → Let's
  ["\u00e2\u009d\u2014", "❗"],
];

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

function fixMojibake(text) {
  let out = text;
  for (const [from, to] of REPLACEMENTS) {
    out = out.split(from).join(to);
  }
  return out;
}

let changedFiles = 0;

for (const file of walk(ROOT)) {
  const original = readFileSync(file, "utf8");
  const updated = fixMojibake(original);
  if (updated !== original) {
    writeFileSync(file, updated, { encoding: "utf8" });
    changedFiles += 1;
    console.log(`fixed: ${file.replace(ROOT + "\\", "").replace(ROOT + "/", "")}`);
  }
}

const remaining = [];
for (const file of walk(ROOT)) {
  const text = readFileSync(file, "utf8");
  if (/â|ð|Â§|LetÂ/.test(text)) remaining.push(file);
}

console.log(`\nDone. ${changedFiles} file(s) updated.`);
if (remaining.length) {
  console.log(`Remaining suspicious files: ${remaining.length}`);
  remaining.slice(0, 10).forEach((f) => console.log(`  - ${f}`));
}
