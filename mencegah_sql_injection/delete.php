<?php
$servername = "localhost";
$username = "db-user";
$password = "db-password";
$dbname = "db-user";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$uuid = $_POST['uuid'];

$sql = 'DELETE FROM user WHERE uuid = ?';

$stmt = mysqli_prepare($conn, $sql);

// Bind the values to the statement
mysqli_stmt_bind_param($stmt, "s", $uuid);

// Execute the statement
mysqli_stmt_execute($stmt);

// Close the statement
mysqli_stmt_close($stmt);

echo "ok";
?>
