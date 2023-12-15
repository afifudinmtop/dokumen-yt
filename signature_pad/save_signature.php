<?php
if (isset($_POST['imgBase64'])) {
    $img = $_POST['imgBase64'];
    $img = str_replace('data:image/png;base64,', '', $img);
    $img = str_replace(' ', '+', $img);
    $data = base64_decode($img);
    $file = 'upload/signature-' . time() . '.png';

    if (file_put_contents($file, $data)) {
        echo "File saved: " . $file;
    } else {
        echo "Error saving file.";
    }
}
?>
