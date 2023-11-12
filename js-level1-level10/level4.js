// Callbacks
function greeting(name) {
  alert("Hello " + name);
}

function processUserInput(callback) {
  var name = prompt("Please enter your name.");
  callback(name);
}

processUserInput(greeting);

//
//
//
//

// Promises
function fetchDataPromise() {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      // Meniru permintaan jaringan
      resolve("Data received from Promise!");
    }, 1000);
  });
}

fetchDataPromise().then((data) => console.log(data));

//
//
//
//

// Membuat sebuah Promise sederhana
const myPromise = new Promise((resolve, reject) => {
  // Simulasi operasi asynchronous (misalnya, pengambilan data dari server)
  setTimeout(() => {
    const randomNumber = Math.random();

    if (randomNumber < 0.5) {
      // Promise berhasil (resolve)
      resolve(randomNumber);
    } else {
      // Promise gagal (reject)
      reject(new Error("Angka terlalu besar!"));
    }
  }, 1000);
});

// Menggunakan Promise
myPromise
  .then((result) => {
    console.log(`Promise berhasil! Hasil: ${result}`);
  })
  .catch((error) => {
    console.error(`Promise gagal! Error: ${error.message}`);
  });

//
//
//
//

// Async/Await
async function fetchDataAsync() {
  try {
    let data = await fetchDataPromise();
    console.log(data); // 'Data received from Promise!' setelah 1 detik
  } catch (error) {
    console.error("An error occurred:", error);
  }
}

fetchDataAsync();

//
//
//
//

// Event Handling
document.getElementById("myButton").addEventListener("click", function (event) {
  console.log("Button clicked!", event);
});
