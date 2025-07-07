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
  ($msg)
  <p>Your query: <?= htmlspecialchars($qry) ?></p>
</body>
</html>
