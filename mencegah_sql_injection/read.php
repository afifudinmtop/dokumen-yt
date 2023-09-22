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

$cetak = [];
$gender = $_POST['gender'];

$stmt = $conn->prepare("SELECT * FROM user WHERE gender = ?");
$stmt->bind_param("s", $gender);

$stmt->execute();

$result = $stmt->get_result();
if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        $cetak[] = [
            "uuid" => $row["uuid"],
            "first_name" => $row["first_name"],
            "last_name" => $row["last_name"]
        ];
    }
    $stmt->close();
    echo json_encode($cetak);
}
?>
