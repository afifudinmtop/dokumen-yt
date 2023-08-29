<?php
function checkUserSession() {
    session_start();
    
    if (isset($_SESSION["username"]) && $_SESSION["username"] == "admin") {
      header("Location: ./dashboard.php");
      exit();
    }
    
    session_write_close();
}

checkUserSession();
?>
<!DOCTYPE html>
<html lang="id">
  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Simple Login</title>

    <!-- bootstrap -->
    <link
      rel="stylesheet"
      href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css"
    />
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/css/bootstrap.min.css"
      rel="stylesheet"
    />
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/js/bootstrap.bundle.min.js"></script>

    <!-- style -->
    <style>
      #root {
        max-width: 80vw;
        width: 400px;
      }
    </style>
  </head>

  <body class="scroll-content bg-primary-subtle">
    <div id="root" class="mx-auto p-4 mt-5 bg-white rounded">
      <!-- title -->
      <div class="h4 mb-4 text-center">Simple Login</div>

      <!-- alert -->
      <div id="alert" class="alert alert-danger d-none" role="alert">
        wrong username/password!
      </div>

      <!-- username -->
      <div class="mb-3">
        <label for="username" class="form-label"> Username </label>
        <input
          type="text"
          class="form-control"
          id="username"
          placeholder="username"
        />
      </div>

      <!-- password -->
      <div class="mb-3">
        <label for="password" class="form-label"> Password </label>
        <input
          type="password"
          class="form-control"
          id="password"
          placeholder="password"
        />
      </div>

      <!-- button login -->
      <button
        onclick="login()"
        type="button"
        class="btn btn-primary d-grid w-100"
      >
        Login
      </button>
    </div>

    <script>
      function login() {
        let username = document.getElementById("username").value;
        let password = document.getElementById("password").value;

        let data_upload = new FormData();
        data_upload.append("username", username);
        data_upload.append("password", password);

        let xhttp = new XMLHttpRequest();
        xhttp.onload = () => {
          const data = xhttp.responseText;
          if (data == "ok") {
            window.location.href = "./dashboard.php";
          } else {
            document.getElementById("alert").className = "alert alert-danger";
          }
        };

        xhttp.open("POST", "./login.php", true);
        xhttp.send(data_upload);
      }
    </script>
  </body>
</html>
