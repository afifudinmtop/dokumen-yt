const mysqldump = require("mysqldump");
const cron = require("node-cron");

const backupDatabase = () => {
  const date = new Date();

  const folder = "./backup/";

  const filename = `backup-${date.getFullYear()}-${
    date.getMonth() + 1
  }-${date.getDate()}-${date.getHours()}-${date.getMinutes()}-${date.getSeconds()}.sql`;

  mysqldump({
    connection: {
      host: "localhost",
      user: "admin",
      password: "admin",
      database: "tes",
    },
    dumpToFile: `${folder}${filename}`,
  });
};

// // Atur jadwal backup, misalnya setiap hari pada jam 1 pagi
// cron.schedule("0 1 * * *", () => {
//   console.log("Menjalankan backup database...");
//   backupDatabase();
// });

// Atur jadwal backup setiap jam
// cron.schedule("0 * * * *", () => {
//   console.log("Menjalankan backup database...");
//   backupDatabase();
// });

// Atur jadwal backup setiap menit
cron.schedule("* * * * *", () => {
  console.log("Menjalankan backup database...");
  backupDatabase();
});
