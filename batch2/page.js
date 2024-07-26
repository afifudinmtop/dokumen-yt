"use client";

export default function Page() {
  return (
    <div className="w-svw h-svh bg-[#f0f2f5] grid grid-cols-2">
      {/* kiri */}
      <div className="pt-[200px] pl-[50px]">
        {/* logo */}
        <img src="/logo.svg" className="h-[106px]" />

        {/* sub title */}
        <div className="text-[28px] leading-[32px]">
          Facebook helps you connect and share with the people in your life.
        </div>
      </div>

      {/* kanan */}
      <div className="bg-red-700"></div>
    </div>
  );
}
