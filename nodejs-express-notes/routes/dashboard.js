const express = require("express");
const router = express.Router();

router.get("/", (req, res, next) => {
  const context = {
    title: "Dashboard",
  };
  res.render("dashboard", context);
});

module.exports = router;
