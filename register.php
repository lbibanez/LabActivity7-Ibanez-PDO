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
$old = ['first_name' => '', 'last_name' => '', 'email' => ''];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_valid()) { http_response_code(403); die('Invalid request. Please go back, reload the page and try again.'); }
    $old['first_name'] = trim($_POST['first_name'] ?? '');
    $old['last_name'] = trim($_POST['last_name'] ?? '');
    $old['email'] = trim($_POST['email'] ?? '');
    $pass = $_POST['password'] ?? '';
    $confirm = $_POST['confirm_password'] ?? '';

    if ($old['first_name'] === '') $errors[] = 'First name is required.';
    elseif (mb_strlen($old['first_name']) > 100) $errors[] = 'First name must be at most 100 characters.';
    if ($old['last_name'] === '') $errors[] = 'Last name is required.';
    elseif (mb_strlen($old['last_name']) > 100) $errors[] = 'Last name must be at most 100 characters.';
    if ($old['email'] === '') $errors[] = 'Email is required.';
    elseif (!filter_var($old['email'], FILTER_VALIDATE_EMAIL) || mb_strlen($old['email']) > 255) $errors[] = 'Email is invalid.';
    if (strlen($pass) < 8) $errors[] = 'Password must be at least 8 characters.';
    if ($pass !== $confirm) $errors[] = 'Passwords do not match.';

    if (!$errors) {
        try {
            $pdo->beginTransaction();
            $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? FOR UPDATE');
            $stmt->execute([$old['email']]);
            if ($stmt->fetch()) {
                $pdo->rollBack();
                $errors[] = 'Email is already registered.';
            } else {
                $stmt = $pdo->prepare('INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)');
                $stmt->execute([$old['first_name'], $old['last_name'], $old['email'], password_hash($pass, PASSWORD_DEFAULT)]);
                $pdo->commit();
                header('Location: login.php?registered=1');
                exit;
            }
        } catch (PDOException $ex) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            $errors[] = ($ex->getCode() === '23000') ? 'Email is already registered.' : 'Registration failed. Please try again.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Register</title>
<link rel="stylesheet" href="style.css"></head>
<body><div class="container"><div class="card">
<h2>Register</h2>
<div id="clientErrors" class="errors hidden"></div>
<?php if ($errors): ?><div class="errors"><ul><?php foreach ($errors as $er): ?><li><?= e($er) ?></li><?php endforeach; ?></ul></div><?php endif; ?>
<form method="post" id="regForm" novalidate><input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
  <label>First Name</label><input type="text" name="first_name" maxlength="100" required value="<?= e($old['first_name']) ?>">
  <label>Last Name</label><input type="text" name="last_name" maxlength="100" required value="<?= e($old['last_name']) ?>">
  <label>Email</label><input type="email" name="email" maxlength="255" required value="<?= e($old['email']) ?>">
  <label>Password</label><input type="password" name="password" minlength="8" required>
  <label>Confirm Password</label><input type="password" name="confirm_password" required>
  <button type="submit">Register</button>
</form>
<p>Already have an account? <a href="login.php">Login</a></p>
</div></div>
<script>
document.getElementById('regForm').addEventListener('submit', function (ev) {
  var f = this, errs = [];
  if (!f.first_name.value.trim()) errs.push('First name is required.');
  if (!f.last_name.value.trim()) errs.push('Last name is required.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(f.email.value.trim())) errs.push('A valid email is required.');
  if (f.password.value.length < 8) errs.push('Password must be at least 8 characters.');
  if (f.password.value !== f.confirm_password.value) errs.push('Passwords do not match.');
  var box = document.getElementById('clientErrors');
  if (errs.length) {
    ev.preventDefault();
    box.innerHTML = '<ul><li>' + errs.join('</li><li>') + '</li></ul>';
    box.style.display = 'block';
  }
});
</script></body></html>
