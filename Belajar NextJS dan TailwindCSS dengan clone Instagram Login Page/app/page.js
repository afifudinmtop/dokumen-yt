import Box_putih from "./components/box_putih_";
import Sign_up from "./components/sign_up";

export default function Home() {
  return (
    <div className="bg-white w-[100svw] h-[100svh] grid grid-cols-2 pt-[32px]">
      {/* kiri */}
      <img className="w-[380px] h-[581px] ms-auto pr-[32px]" src="./1.png" />

      {/* kanan */}
      <div className="">
        <Box_putih />

        {/* sign up */}
        <Sign_up />

        <div className="w-[350px] text-center my-[20px] text-[14px]">
          Get the app.
        </div>

        <div className="w-[350px]">
          <img src="./4.png" className="h-[40px] mx-auto" />
        </div>
      </div>
    </div>
  );
}
