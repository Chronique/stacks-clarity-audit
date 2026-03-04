// parser.js — Read and tokenize .clar files
const fs = require("fs");
const path = require("path");

function parseContract(filePath) {
  const absolutePath = path.resolve(filePath);

  if (!fs.existsSync(absolutePath)) {
    throw new Error(`File not found: ${absolutePath}`);
  }

  const ext = path.extname(absolutePath);
  if (ext !== ".clar") {
    throw new Error(`Expected a .clar file, got: ${ext || "no extension"}`);
  }

  const rawContent = fs.readFileSync(absolutePath, "utf-8");
  const lines = rawContent.split("\n");

  return {
    filePath: absolutePath,
    fileName: path.basename(absolutePath),
    lines,
    rawContent,
  };
}

function findClarityFiles(dirPath) {
  const absoluteDir = path.resolve(dirPath);

  if (!fs.existsSync(absoluteDir)) {
    throw new Error(`Directory not found: ${absoluteDir}`);
  }

  const results = [];

  function walk(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (
        entry.isDirectory() &&
        entry.name !== "node_modules" &&
        !entry.name.startsWith(".")
      ) {
        walk(fullPath);
      } else if (entry.isFile() && entry.name.endsWith(".clar")) {
        results.push(fullPath);
      }
    }
  }

  walk(absoluteDir);
  return results;
}

module.exports = { parseContract, findClarityFiles };
