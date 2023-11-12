// Asynchronous Programming
async function fetchData(url) {
  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP error: ${response.status}`);
    }
    const data = await response.json();
    console.log(data);
    return data;
  } catch (error) {
    console.error(`Could not fetch data: ${error}`);
  } finally {
    console.log("Fetch attempt finished.");
  }
}

fetchData("https://dummyjson.com/products/1");

//
//
//
//

// DOM Manipulation
const newElement = document.createElement("div");
newElement.textContent = "Hello, World!";
document.body.appendChild(newElement);

//
//
//
//

// Advanced Error Handling
class CustomError extends Error {
  constructor(message) {
    super(message);
    this.name = "CustomError";
  }
}

try {
  throw new CustomError("Something went wrong");
} catch (error) {
  console.error(error.name + ": " + error.message);
}

// Event Bubbling dan Capturing
document.getElementById("parent").addEventListener(
  "click",
  (event) => {
    console.log("Parent clicked");
  },
  false
); // false untuk bubbling, true untuk capturing

document.getElementById("child").addEventListener(
  "click",
  (event) => {
    console.log("Child clicked");
  },
  false
);

// Event Delegation
document.getElementById("list").addEventListener("click", (event) => {
  if (event.target.tagName === "LI") {
    console.log("List item clicked:", event.target.textContent);
  }
});

// Web APIs
localStorage.setItem("key", "value");
console.log(localStorage.getItem("key")); // Outputs: value
