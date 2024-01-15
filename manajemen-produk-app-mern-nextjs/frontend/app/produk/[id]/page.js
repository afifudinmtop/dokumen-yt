"use client";
import { useState, useEffect } from "react";

const produk = ({ params }) => {
  const id = params.id;
  const [name, setName] = useState("");
  const [qty, setQty] = useState(0);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = () => {
    fetch("http://localhost:3000/products/" + id, {
      cache: "no-store",
      method: "GET",
    })
      .then((res) => res.json())
      .then((data) => {
        setName(data.name);
        setQty(data.qty);
      })
      .catch((error) => {
        console.error("Error fetching data: ", error);
      });
  };

  const updateData = () => {
    fetch("http://localhost:3000/products/" + id, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name, qty }),
    })
      .then(() => {
        window.location.href = "/";
      })
      .catch((error) => {
        console.error("Error fetching data: ", error);
      });
  };

  const deleteData = () => {
    fetch("http://localhost:3000/products/" + id, {
      method: "delete",
    })
      .then(() => {
        window.location.href = "/";
      })
      .catch((error) => {
        console.error("Error fetching data: ", error);
      });
  };

  return (
    <div className="w-50 mx-auto bg-white p-4 rounded mt-4">
      <div className="mb-3 d-flex gap-3">
        <label className="form-label my-auto label_form">Name</label>
        <input
          type="text"
          className="form-control"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </div>

      <div className="mb-3 d-flex gap-3">
        <label className="form-label my-auto label_form">Qty</label>
        <input
          type="number"
          className="form-control"
          value={qty}
          onChange={(e) => setQty(e.target.value)}
        />
      </div>

      <div className="d-flex mt-4">
        <div className="col-6 d-grid p-3">
          <button
            type="button"
            onClick={updateData}
            className="btn btn-success fw-bold "
          >
            Simpan
          </button>
        </div>

        <div className="col-6 d-grid p-3">
          <button
            type="button"
            onClick={deleteData}
            className="btn btn-danger fw-bold "
          >
            Hapus
          </button>
        </div>
      </div>
    </div>
  );
};

export default produk;
