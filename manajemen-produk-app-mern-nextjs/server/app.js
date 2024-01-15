const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const app = express();

app.use(express.json());
const url_mongo =
  "mongodb+srv://<username>:<password>@cluster0.3sxiksv.mongodb.net/productdb?retryWrites=true&w=majority";

app.use(cors());

const productSchema = new mongoose.Schema({
  name: String,
  qty: Number,
});

const Product = mongoose.model("Product", productSchema);

// Endpoint to list all products
app.get("/products", async (req, res) => {
  const products = await Product.find();
  res.json(products);
});

// Endpoint to create a new product
app.post("/products", async (req, res) => {
  const product = new Product(req.body);
  await product.save();
  res.status(201).json(product);
});

// Endpoint to get a single product by ID
app.get("/products/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).send("Product not found");
    }
    res.json(product);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Endpoint to update a product by ID
app.put("/products/:id", async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });
    if (!product) {
      return res.status(404).send("Product not found");
    }
    res.json(product);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Endpoint to delete a product by ID
app.delete("/products/:id", async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) {
      return res.status(404).send("Product not found");
    }
    res.send("Product deleted");
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// MongoDB connection
mongoose
  .connect(url_mongo, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log(err));

const port = 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
