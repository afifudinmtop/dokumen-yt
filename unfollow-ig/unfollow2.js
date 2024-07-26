function checkAndClick() {
  // Cari elemen dengan selektor yang ditentukan
  const element = document.querySelector("._a9--._ap36._a9-_");

  // Jika elemen ditemukan, klik elemen tersebut
  if (element) {
    element.click();
  }
}

// Jalankan fungsi checkAndClick setiap detik
setInterval(checkAndClick, 500);
