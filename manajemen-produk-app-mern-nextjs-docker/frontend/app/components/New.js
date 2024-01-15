"use client";
import { useState } from "react";

const New = () => {
  const [name, setName] = useState("");
  const [qty, setQty] = useState(0);

  const sendData = () => {
    fetch("https://tes3.apip.dev//products/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name, qty }),
    })
      .then(() => {
        document.getElementById("button_reload_list").click();
        setName("");
        setQty(0);
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

      <div className="d-grid mt-4">
        <button
          type="button"
          onClick={sendData}
          className="btn btn-success fw-bold"
        >
          Submit
        </button>
      </div>
    </div>
  );
};

export default New;
