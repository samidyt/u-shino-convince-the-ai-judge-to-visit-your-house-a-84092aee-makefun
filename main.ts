// Convince the AI Judge to Visit Your House: A Letter in One Image
// Entrypoint: copies the finished invitation image into /output/entry.png
// for the make.fun grader. The image itself is the entry: one handwritten
// letter, addressed to the AI judge, inviting it to visit.
//
// Gate (from the bounty rules): /output/entry.png must be a whole PNG or
// JPEG, at most 1 MiB (1,048,576 bytes) and 1024 by 1024 pixels.
// This program enforces the size cap and the JPEG magic bytes before it
// writes anything, and exits non-zero if the shipped image ever breaks
// the gate, so a bad asset can never be submitted as a valid entry.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const MAX_BYTES = 1_048_576;
const OUTPUT_PATH = "/output/entry.png";

const here = dirname(fileURLToPath(import.meta.url));
const image = readFileSync(join(here, "invitation.jpg"));

if (image.length === 0 || image.length > MAX_BYTES) {
  console.error(`invitation.jpg is ${image.length} bytes; gate allows 1..${MAX_BYTES}`);
  process.exit(1);
}

if (image[0] !== 0xff || image[1] !== 0xd8 || image[2] !== 0xff) {
  console.error("invitation.jpg is not a whole JPEG (bad magic bytes)");
  process.exit(1);
}

// Enforce the gate's pixel cap too: parse the JPEG SOF marker for the
// image dimensions (no dependencies; a photo-style JPEG always carries
// exactly one SOF0/SOF2 frame header).
let width = 0;
let height = 0;
for (let i = 2; i + 9 < image.length; i++) {
  if (image[i] !== 0xff) continue;
  const marker = image[i + 1];
  if (marker === 0xc0 || marker === 0xc2) {
    height = image.readUInt16BE(i + 5);
    width = image.readUInt16BE(i + 7);
    break;
  }
  if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
  if (marker === 0xda) break; // start of scan: no SOF before it means corrupt
  const len = image.readUInt16BE(i + 2);
  i += 1 + len;
}
if (width === 0 || height === 0) {
  console.error("invitation.jpg has no JPEG frame header; cannot verify dimensions");
  process.exit(1);
}
if (width > 1024 || height > 1024) {
  console.error(`invitation.jpg is ${width}x${height}; gate allows at most 1024x1024`);
  process.exit(1);
}

mkdirSync("/output", { recursive: true });
writeFileSync(OUTPUT_PATH, image);

// Round-trip check: the bytes on disk must be exactly the bytes shipped,
// so the grader sees the same image that was reviewed here.
const written = readFileSync(OUTPUT_PATH);
if (!written.equals(image)) {
  console.error("round-trip mismatch: bytes on disk differ from invitation.jpg");
  process.exit(1);
}
const sha256 = createHash("sha256").update(written).digest("hex");
console.log(`entry written to ${OUTPUT_PATH} (${written.length} bytes, JPEG, ${width}x${height})`);
console.log(`sha256: ${sha256}`);
