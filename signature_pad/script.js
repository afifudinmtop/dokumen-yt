let canvas = document.getElementById("signature-pad");
let signaturePad = new SignaturePad(canvas);

// tombol save
document.getElementById("save").addEventListener("click", function () {
  if (signaturePad.isEmpty()) {
    return alert("Please provide a signature first.");
  }

  let dataURL = signaturePad.toDataURL();
  saveSignature(dataURL);
});

// tombol clear
document.getElementById("clear").addEventListener("click", function () {
  signaturePad.clear();
});

// tombol save png
document.getElementById("save-png").addEventListener("click", function () {
  if (signaturePad.isEmpty()) {
    return alert("Please provide a signature first.");
  }

  let dataURL = signaturePad.toDataURL("image/png");
  download(dataURL, randomFileName("png"));
});

// generate random name
function randomFileName(extension) {
  let randomString = Math.random().toString(36).substring(2, 15);
  return "signature-" + randomString + "." + extension;
}

// download file
function download(dataURL, fileName) {
  let a = document.createElement("a");
  a.href = dataURL;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

// upload to php
function saveSignature(dataURL) {
  let xhr = new XMLHttpRequest();
  xhr.open("POST", "save_signature.php", true);
  xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
  xhr.send("imgBase64=" + encodeURIComponent(dataURL));

  xhr.onload = function () {
    console.log(this.responseText);
    alert(this.responseText);
  };
}
