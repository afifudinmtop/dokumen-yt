const fs = require("fs");
const axios = require("axios");

// Gantikan ini dengan path ke file HAR Anda
const harFilePath = "./file.har";

// Fungsi untuk mengirim ulang permintaan
async function resendRequest(entry) {
  const request = entry.request;
  const response = entry.response;

  // Hanya ulangi permintaan yang tidak mendapatkan status 200
  if (response.status !== 200) {
    const method = request.method.toLowerCase();
    const url = request.url;
    const headers = request.headers.reduce((acc, header) => {
      if (header.name.toLowerCase() !== "cookie") {
        acc[header.name] = header.value;
      }
      return acc;
    }, {});
    const data = request.postData ? request.postData.text : null;

    try {
      const result = await axios({ method, url, headers, data });
      return { statusCode: result.status, url, data: result.data }; // Anda bisa menyesuaikan ini
    } catch (error) {
      console.error(
        `Error with ${method.toUpperCase()} ${url}:`,
        error.message
      );
    }
  } else {
    return null;
  }
}

// Baca file HAR dan proses entri
fs.readFile(harFilePath, "utf8", async (err, data) => {
  if (err) {
    console.error("Error reading HAR file:", err);
    return;
  }

  const harJSON = JSON.parse(data);

  // Simpan hasil dalam array dan tunggu semua permintaan selesai
  const results = await Promise.all(harJSON.log.entries.map(resendRequest));

  // Cetak hasil atau lakukan sesuatu dengannya
  results.forEach((result) => {
    if (result) {
      console.log(result); // Atau lakukan sesuatu dengan hasilnya
    }
  });
});
