const express = require("express");
const router = express.Router();
const { v4: uuidv4 } = require("uuid");

let notes = {};

router.post("/add", (req, res, next) => {
  const uuid = uuidv4();
  notes[uuid] = { uuid: uuid, judul: req.body.judul, isi: req.body.isi };
  res.redirect("/notes/list");
});

router.post("/edit", (req, res, next) => {
  notes[req.body.uuid] = {
    uuid: req.body.uuid,
    judul: req.body.judul,
    isi: req.body.isi,
  };
  res.redirect("/notes/list");
});

router.get("/hapus/:uuid", (req, res, next) => {
  delete notes[req.params.uuid];
  res.redirect("/notes/list");
});

exports.routes = router;
exports.notes = notes;
