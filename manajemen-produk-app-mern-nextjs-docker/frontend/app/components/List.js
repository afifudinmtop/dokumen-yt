"use client";
import { useState, useEffect } from "react";
import Link from "next/link";

export default function List() {
  const [data, setData] = useState([]);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = () => {
    fetch("https://tes3.apip.dev//products/", {
      cache: "no-store",
      method: "GET",
    })
      .then((res) => res.json())
      .then((data) => {
        setData(data);
      })
      .catch((error) => {
        console.error("Error fetching data: ", error);
      });
  };

  return (
    <div className="row mt-4 w-75 mx-auto">
      <button
        id="button_reload_list"
        onClick={fetchData}
        className="d-none btn btn-primary mb-3"
      >
        Refresh Products
      </button>

      {data.map((item) => (
        <div className="col-3 d-flex mb-3" key={item._id}>
          <Link
            href={"/produk/" + item._id}
            className="bg-dark text-white w-100 rounded p-3 fs-3 text-decoration-none"
          >
            <div>{item.name}</div>
            <div>{item.qty}</div>
          </Link>
        </div>
      ))}
    </div>
  );
}
