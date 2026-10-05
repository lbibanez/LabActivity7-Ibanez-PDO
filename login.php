<?php
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'httponly' => true,
    'samesite' => 'Lax',
    'secure'   => !empty($_SERVER['HTTPS']),
]);
session_start();
function csrf_token() {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function csrf_valid() {
    return isset($_POST['csrf'], $_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $_POST['csrf']);
}
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
function e($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
if (!empty($_SESSION['user_id'])) { header('Location: index.php'); exit; }
require 'db.php';

$errors = [];
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_valid()) { http_response_code(403); die('Invalid request. Please go back, reload the page and try again.'); }
    $email = trim($_POST['email'] ?? '');
    $pass = $_POST['password'] ?? '';

    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'A valid email is required.';
    if ($pass === '') $errors[] = 'Password is required.';

    if (!$errors) {
        try {
            $pdo->beginTransaction();
            $stmt = $pdo->prepare('SELECT id, first_name, last_name, password FROM users WHERE email = ?');
            $stmt->execute([$email]);
            $user = $stmt->fetch();
            $pdo->commit();
        } catch (PDOException $ex) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            $user = false;
            $errors[] = 'Login failed. Please try again.';
        }
        if (!$errors) {
            if ($user && password_verify($pass, $user['password'])) {
                session_regenerate_id(true);
                unset($_SESSION['csrf']);
                $_SESSION['user_id'] = (int)$user['id'];
                $_SESSION['user_name'] = $user['first_name'] . ' ' . $user['last_name'];
                header('Location: index.php');
                exit;
            }
            $errors[] = 'Invalid email or password.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Login</title>
<link rel="stylesheet" href="style.css"></head>
<body><div class="container"><div class="card">
<h2>Login</h2>
<?php if (isset($_GET['registered'])): ?><p class="success">Registration successful. Please log in.</p><?php endif; ?>
<div id="clientErrors" class="errors hidden"></div>
<?php if ($errors): ?><div class="errors"><ul><?php foreach ($errors as $er): ?><li><?= e($er) ?></li><?php endforeach; ?></ul></div><?php endif; ?>
<form method="post" id="loginForm" novalidate><input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
  <label>Email</label><input type="email" name="email" required value="<?= e($email) ?>">
  <label>Password</label><input type="password" name="password" required>
  <button type="submit">Login</button>
</form>
<p>No account yet? <a href="register.php">Register</a></p>
</div></div>
<script>
document.getElementById('loginForm').addEventListener('submit', function (ev) {
  var f = this, errs = [];
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(f.email.value.trim())) errs.push('A valid email is required.');
  if (!f.password.value) errs.push('Password is required.');
  var box = document.getElementById('clientErrors');
  if (errs.length) {
    ev.preventDefault();
    box.innerHTML = '<ul><li>' + errs.join('</li><li>') + '</li></ul>';
    box.style.display = 'block';
  }
});
</script></body></html>
