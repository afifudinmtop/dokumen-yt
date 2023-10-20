const fs = require("fs");

// Gantikan ini dengan path ke file HAR Anda
const harFilePath = "./file.har";

fs.readFile(harFilePath, "utf8", (err, data) => {
  if (err) {
    console.error("Error reading HAR file:", err);
    return;
  }

  const harJSON = JSON.parse(data);
  const entries = harJSON.log.entries;

  // Menghitung total request
  const totalRequests = entries.length;

  // Menghitung request dengan response yang bukan kode 200
  const non200Responses = entries.filter(
    (entry) => entry.response.status !== 200
  ).length;

  console.log(`Total request: ${totalRequests}`);
  console.log(`Request dengan response selain kode 200: ${non200Responses}`);
});
