const puppeteer = require("puppeteer");
const userAgent = require("user-agents");

// Function to generate a random duration between min and max values
function getRandomDuration(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

(async () => {
  while (true) {
    const browser = await puppeteer.launch({
      headless: true,
      args: ["--incognito", `--user-agent=${new userAgent().toString()}`],
    });

    const page = await browser.newPage();

    const videoUrl = "https://www.youtube.com/watch?v=jVKsUzG4YFw";

    await page.goto(videoUrl, { waitUntil: "networkidle2" });

    // Play the video
    await page.keyboard.press("k");

    // Randomize the view duration
    const viewDuration = getRandomDuration(10, 30);

    console.log(`Simulating playback for ${viewDuration} seconds.`);
    await page.waitForTimeout(viewDuration * 1000);

    // Capture a screenshot of the video (optional)
    await page.screenshot({
      path: "./1/youtube_screenshot_" + Date.now() + ".png",
    });

    await browser.close();

    // Wait for some time before starting the next iteration
    const intervalBetweenViews = getRandomDuration(5, 20); // Adjust as needed
    console.log(
      `Waiting for ${intervalBetweenViews} seconds before the next view.`
    );
    await new Promise((resolve) =>
      setTimeout(resolve, intervalBetweenViews * 1000)
    );
  }
})();
