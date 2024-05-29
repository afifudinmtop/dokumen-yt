"use client";

import Button_login from "./button_login";
import Button_new_account from "./button_new_account";
import Password from "./password";
import Username from "./username";

export default function Box_putih() {
  return (
    <div className="bg-white h-[350px] w-[400px] rounded-[8px] shadow-lg p-[20px]">
      {/* <!-- username --> */}
      <Username />

      {/* <!-- password --> */}
      <Password />

      {/* <!-- button login --> */}
      <Button_login />

      <div className="text-center mt-[12px] text-[#0866ff]">
        forgotten password?
      </div>

      <hr className="mt-[20px]" />

      <Button_new_account />
    </div>
  );
}
