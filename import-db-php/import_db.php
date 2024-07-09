<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);
// ini_set('memory_limit', '1G'); // Adjust as necessary
set_time_limit(0); // Remove execution time limit

$koneksi = mysqli_connect('localhost', 'username', 'password', 'dbname'); // Adjust these values

$sql_file = './data.sql';

$handle = fopen($sql_file, "r");
if ($handle) {
    while (($line = fgets($handle)) !== false) {
        // Check if it's a comment or an empty line
        if (substr($line, 0, 2) == '--' || $line == '') {
            continue;
        }
        
        $query .= $line;
        // If the end of the statement
        if (substr(trim($line), -1, 1) == ';') {
            if (!mysqli_query($koneksi, $query)) {
                echo "Error performing query '<b>$query</b>': " . mysqli_error($koneksi) . "<br/>";
            }
            // Reset the variable to empty
            $query = '';
        }
    }
    fclose($handle);
    echo "Import SQL berhasil.";
} else {
    echo "Error opening the file.";
}

mysqli_close($koneksi);
?>
