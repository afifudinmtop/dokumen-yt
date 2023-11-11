// Pernyataan Kondisional
let score = 75;
if (score >= 90) {
  console.log("Grade: A");
} else if (score >= 80) {
  console.log("Grade: B");
} else if (score >= 70) {
  console.log("Grade: C");
} else if (score >= 60) {
  console.log("Grade: D");
} else {
  console.log("Grade: F");
}

// Switch Case
let day = 3;
switch (day) {
  case 1:
    console.log("Monday");
    break;
  case 2:
    console.log("Tuesday");
    break;
  case 3:
    console.log("Wednesday");
    break;
  // tambahkan kasus lainnya...
  default:
    console.log("Unknown day");
}

// Looping dengan 'for'
for (let i = 0; i < 5; i++) {
  console.log("i is now", i);
}

// Looping dengan 'while'
let j = 0;
while (j < 3) {
  console.log("j is now", j);
  j++;
}

// Nested Loop
for (let i = 0; i < 3; i++) {
  for (let j = 0; j < 2; j++) {
    console.log(`i is ${i} and j is ${j}`);
  }
}

// Break dan Continue
for (let i = 0; i < 10; i++) {
  if (i === 5) {
    break; // Keluar dari loop ketika i adalah 5
  }
  if (i % 2 === 0) {
    continue; // Lewati iterasi saat i adalah bilangan genap
  }
  console.log("Odd number:", i);
}

// Break dan Continue
for (let i = 0; i < 10; i++) {
  if (i === 5) {
    break; // Keluar dari loop ketika i adalah 5
  }
  if (i == 2) {
    continue; // Lewati iterasi saat i adalah bilangan genap
  }
  console.log("number:", i);
}
