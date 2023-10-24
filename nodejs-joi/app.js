const express = require("express");
const Joi = require("joi");

const app = express();
app.use(express.json());

// Skema validasi yang lebih kompleks dengan Joi
const dataSchema = Joi.object({
  nama: Joi.string().min(3).max(30).required(),

  email: Joi.string().email().required(),

  usia: Joi.number().integer().min(0).required(),

  tanggalLahir: Joi.date()
    .less("1-1-2010") // contoh, harus lahir sebelum tahun 2010
    .required(),

  alamat: Joi.object({
    jalan: Joi.string().required(),
    kota: Joi.string().required(),
    kodePos: Joi.string().pattern(/\d{5}/), // asumsikan kode pos adalah 5 digit angka
  }),

  hobi: Joi.array().items(Joi.string()).required(),
});

app.post("/data", (req, res) => {
  // Validasi request data
  const { error, value } = dataSchema.validate(req.body, {
    abortEarly: false, // mengumpulkan semua kesalahan, bukan hanya yang pertama
    allowUnknown: true, // mengizinkan kunci yang tidak didefinisikan di skema
  });

  if (error) {
    const messages = error.details.map((detail) => detail.message);
    return res.status(400).json({ error: messages });
  }

  // Jika validasi berhasil, kirim balik nilai yang telah divalidasi dan dinormalisasi
  res.json({ message: "Data valid!", data: value });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server berjalan di port ${PORT}`);
});
