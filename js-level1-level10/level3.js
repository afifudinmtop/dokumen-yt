// Array dan Metodenya
let numbers = [1, 2, 3, 4, 5];

let students = [
  { name: "Alice", grade: 85 },
  { name: "Bob", grade: 75 },
  { name: "Charlie", grade: 90 },
];

//
//
//
//

// Metode map()
let squares = numbers.map(function (num) {
  return num * num;
});
console.log(squares); // [1, 4, 9, 16, 25]

//
//
//
//

let names = students.map(function (student) {
  return student.name;
});

console.log(names); // Output: ['Alice', 'Bob', 'Charlie']

//
//
//
//

// Metode filter()
let evenNumbers = numbers.filter((num) => {
  return num % 2 === 0;
});
console.log(evenNumbers); // [2, 4]

//
//
//
//

let passingStudents = students.filter(function (student) {
  return student.grade >= 80;
});

console.log(passingStudents);
// Output: [{ name: 'Alice', grade: 85 }, { name: 'Charlie', grade: 90 }]

//
//
//
//

// Metode reduce()
let sum = numbers.reduce((accumulator, current) => {
  return accumulator + current;
}, 0); // 0 is the initial value
console.log(sum); // 15

//
//
//
//

let totalGrade = students.reduce(function (accumulator, student) {
  return accumulator + student.grade;
}, 0);

let averageGrade = totalGrade / students.length;

console.log(averageGrade); // Output: 83.33333333333333

//
//
//
//

// Objek dan Propertinya
let person = {
  name: "Alice",
  age: 25,
  greet: function () {
    console.log("Hello, my name is " + this.name);
  },
};
person.greet(); // "Hello, my name is Alice"
person["age"] = 26; // Mengubah umur Alice menjadi 26

//
//
//
//

// JSON
let jsonString = JSON.stringify(person);
console.log(jsonString); // {"name":"Alice","age":26,"greet":{}}
let parsedPerson = JSON.parse(jsonString);
console.log(parsedPerson); // {name: "Alice", age: 26, greet: [Object]}

//
//
//
//

// Date dan Math Objects
let now = new Date();
console.log("Today is: " + now.toDateString());

let randomNumber = Math.random();
console.log("Random number: " + randomNumber);

let roundedNumber = Math.round(4.7);
console.log("Rounded number: " + roundedNumber);
