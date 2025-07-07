<?php
$ck1_name = "course";
$ck1_value = "Network";
$ck2_name = "Subject";
$ck2_value = "Comp. Sc";
$ck3_name = "Instructor";
$ck3_value = "Prof. Ram Rustagi";


$path1 = "/";
$path2 = "/courses";
$path3 = "/courses/CN";

setcookie($ck1_name, $ck1_value, time() + (60), $path1); 
setcookie($ck2_name, $ck2_value, time() + (600), $path2);
setcookie($ck3_name, $ck3_value, time() + (86400), $path3);

?>
<html>
<body>

<?php
if(count($_COOKIE) > 0) {
    echo "Cookies are <br>";
    print_r($_COOKIE);
} else {
    echo "No cookies are set";
}

?>

</body>
</html>
