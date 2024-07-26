"use client";

import Input_email from "./kanan/input_email";
import Input_password from "./kanan/input_password";

export default function Kanan() {
  return (
    <div className="pt-[200px]">
      {/* box putih */}
      <div className="w-[400px] h-[350px] bg-[#fff] rounded-[8px] shadow-xl p-[10px]">
        {/* Input email */}
        <Input_email />

        {/* Input password */}
        <Input_password />

        {/* button login */}

        {/* forgotten password */}

        {/* button create */}
      </div>
    </div>
  );
}
