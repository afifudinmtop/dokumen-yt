"use client";

import Button_create from "./kanan/button_create";
import Button_login from "./kanan/button_login";
import Forgotten_password from "./kanan/forgotten_password";
import Input_email from "./kanan/input_email";
import Input_password from "./kanan/input_password";

export default function Kanan() {
  return (
    <div className="pt-[200px]">
      {/* box putih */}
      <div className="w-[400px] h-fit bg-[#fff] rounded-[8px] shadow-xl px-[10px] py-[24px]">
        {/* Input email */}
        <Input_email />

        {/* Input password */}
        <Input_password />

        {/* button login */}
        <Button_login />

        {/* forgotten_password */}
        <Forgotten_password />

        {/* button_create */}
        <Button_create />
      </div>
    </div>
  );
}
