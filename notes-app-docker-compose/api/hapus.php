<?php
include './env.php';

$cetak = [];

$uuid = $_GET['uuid'];

$sql = 'DELETE FROM notes WHERE uuid = ?';

$stmt = mysqli_prepare($conn, $sql);

// Bind the values to the statement
mysqli_stmt_bind_param($stmt, "s", $uuid);

// Execute the statement
mysqli_stmt_execute($stmt);

// Close the statement
mysqli_stmt_close($stmt);

header("Location: ../list.php");
exit();
?>
