<?php
if (!empty($_FILES['file'])) {
    $tempPath = $_FILES['file']['tmp_name'];
    $uploadPath = './uploads/' . $_FILES['file']['name'];

    if (move_uploaded_file($tempPath, $uploadPath)) {
        echo 'File successfully uploaded!';
    } else {
        echo 'Error uploading file.';
    }
} else {
    echo 'No file uploaded.';
}
?>
