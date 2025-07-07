<?php
session_start();

// Require login
if (!isset($_SESSION['user'])) {
    header("Location: login.php");
    exit;
}

$user = $_SESSION['user'];
$is_admin = $_SESSION['is_admin'] ?? false;
$file = __DIR__ . '/messages.txt';

// Handle message submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $to = $_POST['to'] ?? '';
    $msg = $_POST['message'] ?? '';
    //$entry = "$user|$to|" . htmlspecialchars($msg) . "|" . date('Y-m-d H:i:s') . "\n";
    $entry = "$user|$to|" . $msg . "|" . date('Y-m-d H:i:s') . "\n";
    file_put_contents($file, $entry, FILE_APPEND);
    header("Location: guestbook.php");
    exit;
}

// Load messages sent to this user
$messages = [];
if (file_exists($file)) {
    $lines = file($file, FILE_IGNORE_NEW_LINES);
    foreach ($lines as $line) {
        [$from, $to, $msg, $time] = explode('|', $line);
        if ($to === $user) {
            $messages[] = "<strong>$from</strong> at $time:<br>" . nl2br($msg);
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>Guestbook</title></head>
<body>
    <h2>Welcome, <?= htmlspecialchars($user) ?>!</h2>
    <p><a href="logout.php">Logout</a></p>
    <?php if ($is_admin): ?>
        <p><a href="admin.php">Admin: Create Users</a></p>
    <?php endif; ?>

    <h3>Leave a message</h3>
    <form method="post">
        To (username): <input name="to" required><br>
        Message:<br>
        <textarea name="message" required></textarea><br>
        <button type="submit">Send Message</button>
    </form>

    <h3>Your Messages</h3>
    <?php if (empty($messages)): ?>
        <p>No messages yet.</p>
    <?php else: ?>
        <?php foreach ($messages as $m): ?>
            <div style="margin-bottom:10px;"><?= $m ?></div>
        <?php endforeach; ?>
    <?php endif; ?>
</body>
</html>
