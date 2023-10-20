<?php

//Import PHPMailer classes into the global namespace
//These must be at the top of your script, not inside a function
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

//Load Composer's autoloader
require './vendor/autoload.php';

//Create an instance; passing `true` enables exceptions
$mail = new PHPMailer(true);

//Server settings
$mail->SMTPDebug = false;                      //Enable verbose debug output
$mail->isSMTP();                                            //Send using SMTP
$mail->Host       = 'smtp.gmail.com';                      //Set the SMTP server to send through
$mail->SMTPAuth   = true;                                   //Enable SMTP authentication
$mail->Username   = 'your@gmail.com';                      //SMTP username
$mail->Password   = 'wezijciofbmggyda';                               //SMTP password
$mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;             //Enable implicit TLS encryption
$mail->Port       = 587;                                    //TCP port to connect to; use 587 if you have set `SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS`

//Recipients
$mail->setFrom('your@gmail.com', 'Your Name');
$mail->addAddress('penerima@gmail.com');               //Name is optional

//Content
$mail->isHTML(true);                                  //Set email format to HTML
$mail->Subject = 'Penting';
$mail->Body    = 'Pagi-pagi nanem kaktus, Pinjam dulu seratus.';

$mail->send();
