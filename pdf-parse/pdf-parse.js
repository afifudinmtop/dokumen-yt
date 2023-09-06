const fs = require("fs");
const pdf = require("pdf-parse");
const { v4: uuidv4 } = require("uuid"); // Using the v4 UUID for random UUIDs

async function parsePDF(filePath) {
  let dataBuffer = fs.readFileSync(filePath);

  let data = await pdf(dataBuffer);

  // Generate a UUID for the filename
  let fileName = uuidv4() + ".txt";

  // Ensure the "output" directory exists
  if (!fs.existsSync("output")) {
    fs.mkdirSync("output");
  }

  // Write the parsed text to the output file
  fs.writeFileSync(`output/${fileName}`, data.text);

  console.log(`Parsed text saved to: output/${fileName}`);
}

// Use the function
parsePDF("./data2.pdf"); // Replace with the path to your PDF file.
