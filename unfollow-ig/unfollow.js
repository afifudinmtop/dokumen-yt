function checkAndClick1() {
  document.querySelectorAll(`._acan._acap._acat._aj1-._ap30`)[2].click();
}

function checkAndClick() {
  // Cari elemen dengan selektor yang ditentukan
  const element = document.querySelector("._a9--._ap36._a9-_");

  // Jika elemen ditemukan, klik elemen tersebut
  if (element) {
    element.click();
  }
}

// Jalankan fungsi checkAndClick setiap detik
setInterval(checkAndClick1, 500);

// Jalankan fungsi checkAndClick setiap detik
setInterval(checkAndClick, 500);
