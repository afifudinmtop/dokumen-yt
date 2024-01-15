import New from "./components/New";
import List from "./components/List";

import "./page.css";

const Home = () => {
  return (
    <div>
      <h1 className="text-center text-decoration-underline">
        Manajemen Produk
      </h1>
      <New />
      <List />
    </div>
  );
};

export default Home;
