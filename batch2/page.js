"use client";

import Kiri from "./components/kiri";
import Kiri_logo from "./components/kiri/logo";

export default function Page() {
  return (
    <div className="w-svw h-svh bg-[#f0f2f5] grid grid-cols-2">
      {/* kiri */}
      <Kiri />

      {/* kanan */}
      <div className="bg-red-700"></div>
    </div>
  );
}
