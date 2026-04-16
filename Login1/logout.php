<?php
session_start();

// ─── Validar token CSRF en el logout (protección CSRF) ───────────────────────
if (
    $_SERVER['REQUEST_METHOD'] === 'POST' &&
    isset($_POST['csrf_token']) &&
    isset($_SESSION['csrf_token']) &&
    hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
) {
    // Destruir sesión de forma segura
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }

    session_destroy();
}

// Siempre redirigir al login
header('Location: index.php');
exit;
