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
header('Expires: 0');
function e($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}
require 'db.php';

$me = (int)$_SESSION['user_id'];
$errors = [];   // keyed by context: new_post, comment_ID, edit_post_ID, edit_comment_ID
$old = [];
$editPost = (int)($_GET['edit_post'] ?? 0);
$editComment = (int)($_GET['edit_comment'] ?? 0);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_valid()) { http_response_code(403); die('Invalid request. Please go back, reload the page and try again.'); }
    $action = $_POST['action'] ?? '';
    if ($action === 'logout') {
        $_SESSION = [];
        session_destroy();
        header('Location: login.php');
        exit;
    }
    $id = (int)($_POST['id'] ?? 0);
    $title = trim($_POST['title'] ?? '');
    $content = trim($_POST['content'] ?? '');

    $checkTitle = function () use ($title) {
        if ($title === '') return 'Title is required.';
        if (mb_strlen($title) > 150) return 'Title must be at most 150 characters.';
    };
    $checkPost = function () use ($content) {
        if ($content === '') return 'Content is required.';
        if (mb_strlen($content) > 5000) return 'Content must be at most 5000 characters.';
    };
    $checkComment = function () use ($content) {
        if ($content === '') return 'Comment is required.';
        if (mb_strlen($content) > 2000) return 'Comment must be at most 2000 characters.';
    };

    if ($action === 'delete_post' || $action === 'delete_comment') {
        $table = $action === 'delete_post' ? 'posts' : 'comments';
        try {
            $pdo->beginTransaction();
            // Ownership is enforced in the WHERE clause; comments on a deleted post are removed by ON DELETE CASCADE.
            $stmt = $pdo->prepare("DELETE FROM $table WHERE id = ? AND user_id = ?");
            $stmt->execute([$id, $me]);
            if ($stmt->rowCount() === 0) {
                $pdo->rollBack();
                $errors['global'][] = 'Item not found or you are not allowed to delete it.';
            } else {
                $pdo->commit();
                header('Location: index.php');
                exit;
            }
        } catch (PDOException $ex) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            $errors['global'][] = 'Could not delete. Please try again.';
        }
    } elseif ($action === 'add_post') {
        $ctx = 'new_post';
        $old[$ctx] = ['title' => $title, 'content' => $content];
        $errors[$ctx] = array_filter([$checkTitle(), $checkPost()]);
        if (!$errors[$ctx]) {
            try {
                $pdo->beginTransaction();
                $pdo->prepare('INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)')->execute([$me, $title, $content]);
                $pdo->commit();
                header('Location: index.php');
                exit;
            } catch (PDOException $ex) {
                if ($pdo->inTransaction()) $pdo->rollBack();
                $errors[$ctx][] = 'Could not save the post. Please try again.';
            }
        }
    } elseif ($action === 'add_comment') {
        $ctx = 'comment_' . $id;
        $old[$ctx] = ['content' => $content];
        $errors[$ctx] = array_filter([$checkComment()]);
        if (!$errors[$ctx]) {
            try {
                $pdo->beginTransaction();
                $stmt = $pdo->prepare('SELECT id FROM posts WHERE id = ? FOR UPDATE');
                $stmt->execute([$id]);
                if (!$stmt->fetch()) {
                    $pdo->rollBack();
                    $errors[$ctx][] = 'Post not found.';
                } else {
                    $pdo->prepare('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)')->execute([$id, $me, $content]);
                    $pdo->commit();
                    header('Location: index.php#post-' . $id);
                    exit;
                }
            } catch (PDOException $ex) {
                if ($pdo->inTransaction()) $pdo->rollBack();
                $errors[$ctx][] = 'Could not save the comment. Please try again.';
            }
        }
    } elseif ($action === 'edit_post') {
        $ctx = 'edit_post_' . $id;
        $editPost = $id;
        $old[$ctx] = ['title' => $title, 'content' => $content];
        $errors[$ctx] = array_filter([$checkTitle(), $checkPost()]);
        if (!$errors[$ctx]) {
            try {
                $pdo->beginTransaction();
                $stmt = $pdo->prepare('UPDATE posts SET title = ?, content = ?, updated_at = NOW() WHERE id = ? AND user_id = ?');
                $stmt->execute([$title, $content, $id, $me]);
                if ($stmt->rowCount() === 0) {
                    $pdo->rollBack();
                    $errors[$ctx][] = 'Post not found or you are not allowed to edit it.';
                } else {
                    $pdo->commit();
                    header('Location: index.php#post-' . $id);
                    exit;
                }
            } catch (PDOException $ex) {
                if ($pdo->inTransaction()) $pdo->rollBack();
                $errors[$ctx][] = 'Could not update the post. Please try again.';
            }
        }
    } elseif ($action === 'edit_comment') {
        $ctx = 'edit_comment_' . $id;
        $editComment = $id;
        $old[$ctx] = ['content' => $content];
        $errors[$ctx] = array_filter([$checkComment()]);
        if (!$errors[$ctx]) {
            try {
                $pdo->beginTransaction();
                $stmt = $pdo->prepare('UPDATE comments SET content = ?, updated_at = NOW() WHERE id = ? AND user_id = ?');
                $stmt->execute([$content, $id, $me]);
                if ($stmt->rowCount() === 0) {
                    $pdo->rollBack();
                    $errors[$ctx][] = 'Comment not found or you are not allowed to edit it.';
                } else {
                    $stmt = $pdo->prepare('SELECT post_id FROM comments WHERE id = ?');
                    $stmt->execute([$id]);
                    $postId = (int)$stmt->fetchColumn();
                    $pdo->commit();
                    header('Location: index.php#post-' . $postId);
                    exit;
                }
            } catch (PDOException $ex) {
                if ($pdo->inTransaction()) $pdo->rollBack();
                $errors[$ctx][] = 'Could not update the comment. Please try again.';
            }
        }
    }
}

function show_errors($errors, $ctx) {
    if (empty($errors[$ctx])) return;
    echo '<div class="errors"><ul>';
    foreach ($errors[$ctx] as $er) echo '<li>' . e($er) . '</li>';
    echo '</ul></div>';
}

// Read both lists inside one transaction so the feed is a consistent snapshot.
$pdo->beginTransaction();
$stmt = $pdo->prepare(
    'SELECT p.*, u.first_name, u.last_name FROM posts p
     JOIN users u ON u.id = p.user_id
     ORDER BY p.created_at DESC, p.id DESC'
);
$stmt->execute();
$posts = $stmt->fetchAll();

$commentsByPost = [];
$stmt = $pdo->prepare(
    'SELECT c.*, u.first_name, u.last_name FROM comments c
     JOIN users u ON u.id = c.user_id
     ORDER BY c.created_at ASC, c.id ASC'
);
$stmt->execute();
$rows = $stmt->fetchAll();
$pdo->commit();
foreach ($rows as $r) $commentsByPost[$r['post_id']][] = $r;
?>
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>News Feed</title>
<link rel="stylesheet" href="style.css"></head>
<body>
<nav><strong>Blog Site</strong><span><?= e($_SESSION['user_name']) ?> <form method="post" class="inline"><input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>"><input type="hidden" name="action" value="logout"><button type="submit" class="link-btn">Logout</button></form></span></nav>
<div class="container">
<?php show_errors($errors, 'global'); ?>

<div class="card">
  <h3>New Post</h3>
  <div class="errors js-errors hidden"></div>
  <?php show_errors($errors, 'new_post'); ?>
  <form method="post" class="validate" novalidate><input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
    <input type="hidden" name="action" value="add_post">
    <label>Title</label><input type="text" name="title" maxlength="150" required data-label="Title" value="<?= e($old['new_post']['title'] ?? '') ?>">
    <label>Content</label><textarea name="content" rows="4" maxlength="5000" required data-label="Content"><?= e($old['new_post']['content'] ?? '') ?></textarea>
    <button type="submit">Post</button>
  </form>
</div>

<?php if (!$posts): ?><p>No posts yet.</p><?php endif; ?>
<?php foreach ($posts as $p): $pid = (int)$p['id']; $mine = (int)$p['user_id'] === $me; ?>
<div class="card" id="post-<?= $pid ?>">
  <?php if ($mine && $editPost === $pid): $ctx = 'edit_post_' . $pid; ?>
    <div class="errors js-errors hidden"></div>
    <?php show_errors($errors, $ctx); ?>
    <form method="post" class="validate" novalidate><input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <input type="hidden" name="action" value="edit_post">
      <input type="hidden" name="id" value="<?= $pid ?>">
      <label>Title</label><input type="text" name="title" maxlength="150" required data-label="Title" value="<?= e($old[$ctx]['title'] ?? $p['title']) ?>">
      <label>Content</label><textarea name="content" rows="4" maxlength="5000" required data-label="Content"><?= e($old[$ctx]['content'] ?? $p['content']) ?></textarea>
      <button type="submit">Save</button> <a href="index.php#post-<?= $pid ?>">Cancel</a>
    </form>
  <?php else: ?>
    <h3 class="post-title"><?= e($p['title']) ?></h3>
    <div class="meta">
      by <?= e($p['first_name'] . ' ' . $p['last_name']) ?> &middot; <?= e($p['created_at']) ?>
      <?php if ($p['updated_at'] !== null): ?><span class="tag" title="<?= e($p['updated_at']) ?>">Edited</span><?php endif; ?>
      <?php if ($mine): ?> &middot; <a href="index.php?edit_post=<?= $pid ?>#post-<?= $pid ?>">Edit</a>
        &middot; <form method="post" class="inline confirm-delete"><input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>"><input type="hidden" name="action" value="delete_post"><input type="hidden" name="id" value="<?= $pid ?>"><button type="submit" class="link-btn">Delete</button></form><?php endif; ?>
    </div>
    <p><?= nl2br(e($p['content'])) ?></p>
  <?php endif; ?>

  <?php foreach ($commentsByPost[$pid] ?? [] as $c): $cid = (int)$c['id']; $cmine = (int)$c['user_id'] === $me; ?>
  <div class="comment">
    <?php if ($cmine && $editComment === $cid): $ctx = 'edit_comment_' . $cid; ?>
      <div class="errors js-errors hidden"></div>
      <?php show_errors($errors, $ctx); ?>
      <form method="post" class="validate" novalidate><input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
        <input type="hidden" name="action" value="edit_comment">
        <input type="hidden" name="id" value="<?= $cid ?>">
        <textarea name="content" rows="2" maxlength="2000" required data-label="Comment"><?= e($old[$ctx]['content'] ?? $c['content']) ?></textarea>
        <button type="submit">Save</button> <a href="index.php#post-<?= $pid ?>">Cancel</a>
      </form>
    <?php else: ?>
      <div class="meta">
        <?= e($c['first_name'] . ' ' . $c['last_name']) ?> &middot; <?= e($c['created_at']) ?>
        <?php if ($c['updated_at'] !== null): ?><span class="tag" title="<?= e($c['updated_at']) ?>">Edited</span><?php endif; ?>
        <?php if ($cmine): ?> &middot; <a href="index.php?edit_comment=<?= $cid ?>#post-<?= $pid ?>">Edit</a>
          &middot; <form method="post" class="inline confirm-delete"><input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>"><input type="hidden" name="action" value="delete_comment"><input type="hidden" name="id" value="<?= $cid ?>"><button type="submit" class="link-btn">Delete</button></form><?php endif; ?>
      </div>
      <?= nl2br(e($c['content'])) ?>
    <?php endif; ?>
  </div>
  <?php endforeach; ?>

  <?php $ctx = 'comment_' . $pid; ?>
  <div class="errors js-errors hidden"></div>
  <?php show_errors($errors, $ctx); ?>
  <form method="post" class="validate" novalidate><input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
    <input type="hidden" name="action" value="add_comment">
    <input type="hidden" name="id" value="<?= $pid ?>">
    <textarea name="content" rows="2" maxlength="2000" placeholder="Write a comment..." required data-label="Comment"><?= e($old[$ctx]['content'] ?? '') ?></textarea>
    <button type="submit">Comment</button>
  </form>
</div>
<?php endforeach; ?>
</div>
<script>
window.addEventListener('pageshow', function (e) {
  if (e.persisted) location.reload();
});
document.querySelectorAll('form.confirm-delete').forEach(function (form) {
  form.addEventListener('submit', function (ev) {
    if (!confirm('Delete this permanently?')) ev.preventDefault();
  });
});
document.querySelectorAll('form.validate').forEach(function (form) {
  form.addEventListener('submit', function (ev) {
    var errs = [];
    form.querySelectorAll('[required]').forEach(function (el) {
      if (!el.value.trim()) errs.push(el.dataset.label + ' is required.');
    });
    var box = form.previousElementSibling;
    while (box && !box.classList.contains('js-errors')) box = box.previousElementSibling;
    if (errs.length) {
      ev.preventDefault();
      box.innerHTML = '<ul><li>' + errs.join('</li><li>') + '</li></ul>';
      box.style.display = 'block';
    }
  });
});
</script>
</body></html>