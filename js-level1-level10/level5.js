// Closures
function createGreeting(greeting) {
  return function (name) {
    console.log(greeting + ", " + name);
  };
}

const sayHello = createGreeting("Hello");
sayHello("Alice"); // Outputs: Hello, Alice
// Closure memungkinkan 'sayHello' untuk mengingat variabel 'greeting'

//
//
//
//

function hitungPenjumlahan(a) {
  // Fungsi dalam ini adalah closure karena memiliki akses ke variabel 'a'
  return function (b) {
    return a + b;
  };
}

// Membuat sebuah fungsi yang menggunakan closure
const tambahDua = hitungPenjumlahan(2);

// Menggunakan fungsi yang menggunakan closure
console.log(tambahDua(3)); // Output: 5
console.log(tambahDua(7)); // Output: 9

//
//
//
//

// Scope
let globalVar = "I am a global variable";

function checkScope() {
  let localVar = "I am a local variable";
  console.log(globalVar); // Akses variabel global
  console.log(localVar); // Akses variabel lokal
}

checkScope();
// console.log(localVar); // Error: localVar is not defined di luar fungsi

//
//
//
//

// IIFEs
(function () {
  let privateVar = "I am private";
  console.log(privateVar); // Outputs: I am private
})();

(() => {
  const pesan = "Ini adalah contoh IIFE dengan arrow function";
  console.log(pesan);
})();

// console.log(privateVar); // Error: privateVar is not defined di luar IIFE

//
//
//
//

// The `this` Keyword
function showDetails() {
  console.log(this.name + " is " + this.age + " years old.");
}

const person = {
  name: "Alice",
  age: 25,
  details: showDetails,
};

person.details(); // Outputs: Alice is 25 years old.

//
//
//
//

// Higher-Order Functions
// Array asal
const numbers = [1, 2, 3, 4, 5];

// Fungsi yang akan diterapkan pada setiap elemen array
const double = (number) => number * 2;

// Menggunakan map() untuk menggandakan setiap elemen dalam array
const doubledNumbers = numbers.map(double);

console.log(doubledNumbers); // Output: [2, 4, 6, 8, 10]

//
//
//
//

// Fungsi yang akan digunakan untuk menyaring elemen
const isEven = (number) => number % 2 === 0;

// Menggunakan filter() untuk menyaring elemen yang genap
const evenNumbers = numbers.filter(isEven);

console.log(evenNumbers); // Output: [2, 4]
