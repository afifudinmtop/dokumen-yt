<?php
include './env.php';

$cetak = [];

$uuid = $_POST['uuid'];
$judul = $_POST['judul'];
$isi = $_POST['isi'];

$sql = 'UPDATE notes SET judul = ? , isi = ? WHERE uuid = ?';

$stmt = mysqli_prepare($conn, $sql);

// Bind the values to the statement
mysqli_stmt_bind_param($stmt, "sss", $judul, $isi, $uuid);

// Execute the statement
mysqli_stmt_execute($stmt);

// Close the statement
mysqli_stmt_close($stmt);

header("Location: ../list.php");
exit();
?>
