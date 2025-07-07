<?php
session_start();
if (!($_SESSION['user'] ?? null) || !($_SESSION['is_admin'] ?? false)) {
    die("Access denied");
}

$success = "";
$error = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $new_user = trim($_POST['new_user'] ?? '');
    $new_pass = $_POST['new_pass'] ?? '';

    if ($new_user && $new_pass) {
        $users = file_exists('users.json') ? json_decode(file_get_contents('users.json'), true) : [];
        if (isset($users[$new_user])) {
            $error = "User already exists.";
        } else {
            $users[$new_user] = password_hash($new_pass, PASSWORD_DEFAULT);
            file_put_contents('users.json', json_encode($users, JSON_PRETTY_PRINT));
            $success = "User '$new_user' created successfully.";
        }
    } else {
        $error = "Both username and password are required.";
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>Admin - Create Users</title></head>
<body>
    <h2>Admin Panel</h2>
    <p><a href="bank.php">Back to Bank</a></p>

    <?php if ($success): ?>
        <p style="color:green"><?= htmlspecialchars($success) ?></p>
    <?php endif; ?>
    <?php if ($error): ?>
        <p style="color:red"><?= htmlspecialchars($error) ?></p>
    <?php endif; ?>

    <form method="post">
        New Username: <input name="new_user" required><br>
        New Password: <input name="new_pass" type="password" required><br>
        <button type="submit">Create User</button>
    </form>
</body>
</html>
