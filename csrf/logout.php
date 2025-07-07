<?php
session_start();
session_destroy();
setcookie("auth", "", time() - 3600, "/");
header("Location: login.php");
exit;
