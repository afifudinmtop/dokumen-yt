<?php
include './env.php';

function generateUuidV4() {
    return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
}


$uuid = generateUuidV4();
$judul = $_POST['judul'];
$isi = $_POST['isi'];

$sql = 'INSERT INTO notes (uuid, judul, isi) VALUES (?, ?, ?)';

$stmt = mysqli_prepare($conn, $sql);

// Bind the values to the statement
mysqli_stmt_bind_param($stmt, "sss", $uuid, $judul, $isi);

// Execute the statement
mysqli_stmt_execute($stmt);

// Close the statement
mysqli_stmt_close($stmt);

header("Location: ../list.php");
exit();
?>
