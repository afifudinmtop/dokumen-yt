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
$first_name = $_POST['first_name'];
$last_name = $_POST['last_name'];

$sql = 'INSERT INTO user (uuid, first_name, last_name) VALUES (?, ?, ?)';

$stmt = mysqli_prepare($conn, $sql);

// Bind the values to the statement
mysqli_stmt_bind_param($stmt, "sss", $uuid, $first_name, $last_name);

// Execute the statement
mysqli_stmt_execute($stmt);

// Close the statement
mysqli_stmt_close($stmt);

echo "ok";
?>
