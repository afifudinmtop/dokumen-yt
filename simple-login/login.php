<?php
$username = $_POST['username'];
$password = $_POST['password'];

if ($username == "admin" && $password == "pass-admin") {
    session_start();
    $_SESSION["username"] = $username;
    session_write_close();

    echo "ok";
}
else{
    echo "xxx";
}