"use client";

import Facebook from "./facebook";
import Login from "./login";
import Password from "./password";
import Username from "./username";

export default function Box_putih() {
  return (
    <div className="w-[350px]  bg-white border px-[40px] pb-[30px]">
      {/* logo */}
      <img src="./2.png" className="w-[175px] h-[51px] mx-auto my-[30px]" />

      {/* input username */}
      <Username />

      {/* input password */}
      <Password />

      {/* login button */}
      <Login />

      {/* facebook */}
      <Facebook />

      <div className="text-center text-[12px] text-[#00376b] mt-[10px]">
        forgot password?
      </div>
    </div>
  );
}
