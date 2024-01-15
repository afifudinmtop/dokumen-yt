import "./globals.css";

export const metadata = {
  title: "Manajemen Produk",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body className="pt-4 bg-body-secondary">
        <link
          href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"
          rel="stylesheet"
        />
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>

        {children}
      </body>
    </html>
  );
}
