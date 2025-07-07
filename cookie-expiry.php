<?php
$ck1_name = "course";
$ck1_value = "Network";
$ck2_name = "Subject";
$ck2_value = "Comp. Sc";
$ck3_name = "Instructor";
$ck3_value = "Prof. Ram Rustagi";

setcookie($ck1_name, $ck1_value, time() + (30));
setcookie($ck2_name, $ck2_value, time() + (300)); 
setcookie($ck3_name, $ck3_value, time() + (86400)); 

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
