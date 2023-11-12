// Classes
class Person {
  constructor(name, age) {
    this.name = name;
    this.age = age;
  }

  greet() {
    console.log(`Hello, my name is ${this.name}`);
  }
}

const alice = new Person("Alice", 25);
alice.greet(); // Outputs: Hello, my name is Alice

//
//
//
//

// Inheritance
class Employee extends Person {
  constructor(name, age, jobTitle) {
    super(name, age);
    this.jobTitle = jobTitle;
  }

  work() {
    console.log(`${this.name} is working as a ${this.jobTitle}`);
  }
}

const bob = new Employee("Bob", 30, "Developer");
bob.greet(); // Outputs: Hello, my name is Bob
bob.work(); // Outputs: Bob is working as a Developer

//
//
//
//

// Method Overriding
class Manager extends Employee {
  work() {
    super.work();
    console.log(`${this.name} is managing the team.`);
  }
}

const carol = new Manager("Carol", 35, "Manager");
carol.work();
// Outputs: Carol is working as a Manager
// Outputs: Carol is managing the team.

//
//
//
//

// Static Methods
class MathUtility {
  static sum(a, b) {
    return a + b;
  }
}

console.log(MathUtility.sum(5, 10)); // Outputs: 15

//
//
//
//

class Matematika {
  // Metode statis untuk menghitung jumlah dua angka
  static tambah(angka1, angka2) {
    return angka1 + angka2;
  }

  // Metode statis untuk menghitung selisih dua angka
  static kurang(angka1, angka2) {
    return angka1 - angka2;
  }
}

// Menggunakan metode statis tanpa membuat instance kelas Matematika
const hasilTambah = Matematika.tambah(5, 3);
console.log(hasilTambah); // Output: 8

const hasilKurang = Matematika.kurang(10, 4);
console.log(hasilKurang); // Output: 6

//
//
//
//

//
//
//
//

// Setters and Getters
class User {
  constructor(name) {
    this._name = name;
  }

  get name() {
    return this._name;
  }

  set name(value) {
    this._name = value;
  }
}

const user = new User("Dave");
console.log(user.name); // Outputs: Dave
user.name = "David";
console.log(user.name); // Outputs: David

//
//
//
//

class Produk {
  constructor(nama, harga) {
    this._nama = nama;
    this._harga = harga;
  }

  set namaProduk(nama) {
    this._nama = nama;
  }

  get namaProduk() {
    return this._nama;
  }

  set hargaProduk(harga) {
    this._harga = harga;
  }

  get hargaProduk() {
    return this._harga;
  }
}

const produk1 = new Produk("Laptop", 5000000);
produk1.namaProduk = "Smartphone";
produk1.hargaProduk = 2000000;

console.log(produk1.namaProduk); // Output: Smartphone
console.log(produk1.hargaProduk); // Output: 2000000
