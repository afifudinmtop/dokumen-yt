<?php
function checkUserSession() {
    session_start();
    
    if (isset($_SESSION["username"]) && $_SESSION["username"] == "admin") {

    }
    else {
      header("Location: ./index.php");
      exit();
    }
    
    session_write_close();
}

checkUserSession();
?>

<h2>hello there</h2>