"use client";

import Kanan from "./components/kanan";
import Kiri from "./components/kiri";

export default function Home() {
  return (
    <div className="w-[100svw] h-[100svh] bg-[#f0f2f5] grid grid-cols-2 py-[100px] px-[180px] content-center">
      {/* <!-- kiri --> */}
      <Kiri />

      {/* <!-- kanan --> */}
      <Kanan />
    </div>
  );
}
