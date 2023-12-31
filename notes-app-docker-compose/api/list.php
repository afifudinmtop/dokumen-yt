<?php
include './env.php';

$cetak = [];

$stmt = $conn->prepare("SELECT * FROM notes");
$stmt->execute();

$result = $stmt->get_result();
if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        $cetak[] = [
            "uuid" => $row["uuid"],
            "judul" => $row["judul"],
            "isi" => $row["isi"]
        ];
    }
    $stmt->close();
    echo json_encode($cetak);
}
?>
