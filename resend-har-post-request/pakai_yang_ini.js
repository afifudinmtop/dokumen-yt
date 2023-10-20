const fs = require("fs");
const axios = require("axios");

// Gantikan ini dengan path ke file HAR Anda
const harFilePath = "./file.har";

// Fungsi untuk mengirim ulang permintaan
async function resendRequest(entry, index) {
  // Tambahkan parameter 'index' untuk mengidentifikasi request
  const request = entry.request;
  const response = entry.response;

  console.log(`Request ${index} jalan`); // Log ketika permintaan dimulai

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
      console.log(`Request ${index} selesai`); // Log ketika permintaan selesai
      return { statusCode: result.status, url, data: result.data };
    } catch (error) {
      console.error(
        `Error with ${method.toUpperCase()} ${url}:`,
        error.message
      );
    }
  } else {
    console.log(`Request ${index} tidak diulangi karena statusnya 200`); // Log jika permintaan tidak diulangi
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

  // Jalankan permintaan satu per satu
  for (let i = 0; i < harJSON.log.entries.length; i++) {
    const result = await resendRequest(harJSON.log.entries[i], i + 1); // Gunakan 'index' untuk mengidentifikasi request
    console.log(`Hasil dari Request ${i}:`, result);
  }
});
