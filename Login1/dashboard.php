<?php
session_start();

// ─── 1. Manejo de actividad vía AJAX (dentro del mismo archivo) ─────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'keep_alive') {
    header('Content-Type: application/json');
    if (!empty($_SESSION['is_logged_in']) && isset($_POST['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $_SESSION['last_activity'] = time();
        echo json_encode(['ok' => true]);
    } else {
        http_response_code(403);
        echo json_encode(['ok' => false]);
    }
    exit;
}

// ─── 2. Protección: Si no hay sesión activa, redirigir al login ─────────────────
if (empty($_SESSION['is_logged_in']) || $_SESSION['is_logged_in'] !== true) {
    header('Location: index.php');
    exit;
}

$sessionDuration = 120; // 2 minutos

// ─── 3. Expiración de sesión por inactividad (server-side) ──────────────────────
$lastActivity = $_SESSION['last_activity'] ?? $_SESSION['login_time'] ?? time();
$elapsed      = time() - $lastActivity;

if ($elapsed >= $sessionDuration) {
    session_unset();
    session_destroy();
    header('Location: index.php?expired=1');
    exit;
}

// Actualizar última actividad al cargar la página manualmente
$_SESSION['last_activity'] = time();

$username      = htmlspecialchars($_SESSION['username'] ?? 'Usuario');
$timeRemaining = $sessionDuration - $elapsed;
?>
<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Panel de Control</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="styles.css">
    <style>
        .dashboard-card {
            text-align: center;
            padding: 50px;
        }
        .welcome-text {
            color: var(--text-muted);
            margin-bottom: 0.5rem;
        }
        .username-highlight {
            color: var(--primary);
            font-weight: 700;
        }
        .activity-hint {
            font-size: 0.78rem;
            color: var(--gray);
            margin-top: 0.4rem;
        }
        .logout-btn {
            background: var(--gray);
            color: white;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 0.75rem;
            font-family: inherit;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s ease;
            margin-top: 1rem;
            width: auto;
        }
        .logout-btn:hover {
            opacity: 0.8;
        }
    </style>
</head>

<body>
    <div class="login-container dashboard-card">
        <span class="logo-icon">✅</span>
        <h1>Sesión Iniciada</h1>
        <p class="welcome-text">
            Bienvenido al sistema seguro,
            <span class="username-highlight"><?= $username ?></span>.
        </p>
        <p>Tu sesión expirará por inactividad en:</p>
        <div class="timer" id="sessionTimer">
            <?php
                $mins = floor($timeRemaining / 60);
                $secs = $timeRemaining % 60;
                printf('%02d:%02d', $mins, $secs);
            ?>
        </div>
        <p class="activity-hint">🖱️ Movimiento o clic reinician el timer</p>
        <br>
        <form method="POST" action="logout.php">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <button type="submit" class="logout-btn">Cerrar Sesión Ahora</button>
        </form>
    </div>

    <script>
        const SESSION_DURATION = <?= (int)$sessionDuration ?>;
        let timeLeft = <?= (int)$timeRemaining ?>;
        const timerElement = document.getElementById('sessionTimer');

        function updateDisplay() {
            const minutes = Math.floor(timeLeft / 60);
            const seconds = timeLeft % 60;
            timerElement.textContent = 
                String(minutes).padStart(2, '0') + ':' + String(seconds).padStart(2, '0');
        }

        const countdown = setInterval(() => {
            timeLeft--;
            if (timeLeft <= 0) {
                clearInterval(countdown);
                timerElement.textContent = '00:00';
                alert('Tu sesión ha expirado por inactividad.');
                window.location.href = 'index.php?expired=1';
                return;
            }
            updateDisplay();
        }, 1000);

        let debounceTimer = null;
        function onUserActivity() {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                // Reiniciar localmente
                timeLeft = SESSION_DURATION;
                updateDisplay();

                // Notificar al servidor (a este mismo archivo)
                const formData = new FormData();
                formData.append('action', 'keep_alive');
                formData.append('csrf_token', '<?= htmlspecialchars($_SESSION['csrf_token']) ?>');

                fetch('dashboard.php', {
                    method: 'POST',
                    body: formData
                }).catch(() => {});
            }, 300);
        }

        document.addEventListener('mousemove', onUserActivity);
        document.addEventListener('click',     onUserActivity);
        document.addEventListener('keydown',   onUserActivity);
    </script>
</body>

</html>
