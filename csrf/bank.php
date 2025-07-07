<?php
session_start();

// Require login
if (!isset($_SESSION['user']) || ($_COOKIE['auth'] ?? '') !== 'authenticated') {
    header("Location: login.php");
    exit;
}

$user = $_SESSION['user'];
$is_admin = $_SESSION['is_admin'] ?? false;
$file = __DIR__ . '/transactions.txt';
$status = '';

// Handle transactions submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $to = $_POST['to'] ?? 'unknown';
    $amount = $_POST['amount'] ?? '0';
    $timestamp = date('Y-m-d H:i:s');
    $log_entry = "[$timestamp] $user sent $amount to $to\n";

    if (file_put_contents($file, $log_entry, FILE_APPEND) !== false) {
        $status = "<p style='color:green'> Transaction recorded:</p><pre>$log_entry</pre>";
    } else {
        $status = "<p style='color:red'> Failed to write transaction.</p>";
    }
}
?>

<!DOCTYPE html>
<html>
<head><title>Welcome to Your Bank</title></head>
<body>
  <h1>Hello, <?= htmlspecialchars($user) ?>!</h1>
  <p><a href="logout.php">Logout</a></p>
  <?php if ($is_admin): ?>
      <p><a href="admin.php">Admin: Create Users</a></p>
  <?php endif; ?>

  <h3>Transfer Money</h3>

  <?php
    $users = json_decode(file_get_contents(__DIR__ . '/users.json'), true);
    // Send Money To: <input name="to" ><br>
  ?>
  <form method="post">

  <label>Send Money to :</label>
   <select name="to" id="to">
            <option value="">--Select a user--</option>
            <?php
            if ($users) {
              foreach ($users as $u => $p) { 
                if ($u=== "_comment") {
                  continue;
                }
               echo "<option value='$u'>$u</option>"; 
                //echo "$u"; 
              }
            }
            ?>
   </select>
   <br><br>

    Amount: <input name="amount" ><br>
    <button type="submit">Transfer</button>
  </form>

  <?= $status ?>
</body>
</html>
