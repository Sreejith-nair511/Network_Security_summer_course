<?php
$qry = $_GET['qry'] ?? '';
?>
<!DOCTYPE html>
<html>
<head>
  <title>Search Results</title>
</head>
<body>
  <h2>Search Results</h2>
  <p>Your query: <?= $qry ?></p>
</body>
</html>
