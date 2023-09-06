const { exec } = require("child_process");
const fs = require("fs");
const { v4: uuidv4 } = require('uuid');

function extractTextFromPDF(pdfPath, callback) {
  // Generate a unique filename with UUID
  const outputFileName = `./output/${uuidv4()}.txt`;

  // Adjust the exec command to output to the file rather than stdout
  exec(`pdftotext ${pdfPath} ${outputFileName}`, (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      callback(error, null);
      return;
    }

    // Instead of passing the text to the callback, pass the file path where the text is saved
    callback(null, outputFileName);
  });
}

// Ensure the "output" directory exists
if (!fs.existsSync("./output")) {
    fs.mkdirSync("./output");
}

// Example usage:
extractTextFromPDF("./data2.pdf", (err, outputPath) => {
  if (err) {
    console.error("Error:", err);
    return;
  }

  // Read the text from the output file (or you can just use the outputPath as needed)
  fs.readFile(outputPath, 'utf8', (err, text) => {
    if (err) {
      console.error("Read file error:", err);
      return;
    }
    console.log(text);
  });
});
