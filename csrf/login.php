<?php
session_start();
$errors = [];

$users = json_decode(file_get_contents(__DIR__ . '/users.json'), true);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    if (isset($users[$username]) && password_verify($password, $users[$username])) {
        $_SESSION['user'] = $username;
        $_SESSION['is_admin'] = ($username === 'admin');
        setcookie("auth", "authenticated", time() + 3600, "/");
        header("Location: bank.php");
        exit;
    } else {
        $errors[] = "Invalid username or password.";
    }
}
?>

<!DOCTYPE html>
<html>
<head><title>Bank Login</title></head>
<body>
  <h2>Login to Your Bank Account</h2>
  <?php foreach ($errors as $e): ?>
        <p style="color:red"><?= htmlspecialchars($e) ?></p>
  <?php endforeach; ?>
  <form method="post">
    Username: <input type="text" name="username" required><br>
    Password: <input type="password" name="password" required><br>
    <button type="submit">Login</button>
  </form>
</body>
</html>
