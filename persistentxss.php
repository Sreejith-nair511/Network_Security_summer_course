<?php
$messages = file('messages.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
?>
<html>
<head><title>Demo Persistent XSS Attack</title></head>
<body>
    <h1> Persistent XSS Attack Demo</h2>
    <p>Please leave a message to understand XSS Attack</p>
    <form method="post" action="xsssubmit.php">
        Name: <input name="name"><br>
        Message: <textarea name="message"></textarea><br>
        <button type="submit">Submit</button>
    </form>

    <h2>Messages</h2>
    <?php foreach ($messages as $line): ?>
        <div><?php echo $line ?></div><hr>
    <?php endforeach; ?>
</body>
</html>
