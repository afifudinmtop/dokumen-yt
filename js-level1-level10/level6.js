// Arrow Functions
const add = (a, b) => a + b;
function add2(a, b) {
  return a + b;
}
console.log(add(2, 3)); // Outputs: 5

//
//
//
//

// Template Literals
const name = "Alice";
const greeting = `Hello, ${name}!`;
console.log(greeting); // Outputs: Hello, Alice!

//
//
//
//

// Destructuring
const point = { x: 10, y: 20 };
const { x, y } = point;
console.log(x); // Outputs: 10
console.log(y); // Outputs: 20

//
//
//
//

// Default Parameters
function greet(name = "Guest") {
  return `Hi, ${name}!`;
}
console.log(greet()); // Outputs: Hi, Guest!

//
//
//
//

// Spread/Rest Operator
const nums = [1, 2, 3];
const moreNums = [...nums, 4, 5];
console.log(moreNums); // Outputs: [1, 2, 3, 4, 5]

//
//
//
//
//

function sumAll(...args) {
  return args.reduce((sum, current) => sum + current, 0);
}
console.log(sumAll(1, 2, 3, 4, 5)); // Outputs: 15

//
//
//
//

// Let dan Const
let counter = 10;
counter = 5; // OK, karena let memperbolehkan reassignment
const pi = 3.14;
// pi = 3.14159; // Error, const tidak memperbolehkan reassignment

//
//
//
//

// Modules (import/export)
// file math.js
export function add(a, b) {
  return a + b;
}

// file main.js
import { add } from "./math.js";
console.log(add(4, 5)); // Outputs: 9
