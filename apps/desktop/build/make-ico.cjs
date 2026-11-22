// Generates a Windows .ico embedding a PNG (Vista+ PNG-in-ICO format). No deps.
const fs = require("node:fs");
const path = require("node:path");

const png = fs.readFileSync(path.join(__dirname, "icon-256.png"));
const header = Buffer.alloc(6);
header.writeUInt16LE(0, 0); // reserved
header.writeUInt16LE(1, 2); // type: icon
header.writeUInt16LE(1, 4); // image count

const entry = Buffer.alloc(16);
entry.writeUInt8(0, 0); // width: 0 means 256
entry.writeUInt8(0, 1); // height: 0 means 256
entry.writeUInt8(0, 2); // palette
entry.writeUInt8(0, 3); // reserved
entry.writeUInt16LE(1, 4); // color planes
entry.writeUInt16LE(32, 6); // bits per pixel
entry.writeUInt32LE(png.length, 8); // data size
entry.writeUInt32LE(22, 12); // offset: 6 + 16

fs.writeFileSync(path.join(__dirname, "icon.ico"), Buffer.concat([header, entry, png]));
console.log("icon.ico written:", 22 + png.length, "bytes");
