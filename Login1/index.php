<?php
session_start();

// ─── Generar token CSRF si no existe ─────────────────────────────────────────
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$errors = [];

// ─── Procesar el formulario cuando se envía ───────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // 1. Validar token CSRF
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $errors['general'] = 'Token de seguridad inválido. Recarga la página.';
    } else {

        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        // 2. Validar formato de usuario
        if (strlen($username) < 3 || preg_match('/\s/', $username)) {
            $errors['username'] = 'Ingresa un usuario válido (mín. 3 caracteres, sin espacios).';
        }

        // 3. Validar requisitos de contraseña
        if (!empty($password)) {
            if (strlen($password) > 8) {
                $errors['password'][] = 'Máximo 8 caracteres.';
            }
            if (!preg_match('/[A-Z]/', $password)) {
                $errors['password'][] = 'Debe tener al menos una mayúscula.';
            }
            if (!preg_match('/[0-9]/', $password)) {
                $errors['password'][] = 'Debe tener al menos un número.';
            }
            if (!preg_match('/[!@#$%^&*()\-_=+\[\]{};\':"\\|,.<>\/?]/', $password)) {
                $errors['password'][] = 'Debe tener al menos un carácter especial.';
            }
            if (preg_match('/\s/', $password)) {
                $errors['password'][] = 'No debe contener espacios.';
            }
        } else {
            $errors['password'][] = 'La contraseña es requerida.';
        }

        // 4. Validar reCAPTCHA
        $recaptchaSecret   = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';
        $recaptchaResponse = $_POST['g-recaptcha-response'] ?? '';

        if (empty($recaptchaResponse)) {
            $errors['captcha'] = 'Por favor, completa la verificación reCAPTCHA.';
        } else {
            $verifyUrl = 'https://www.google.com/recaptcha/api/siteverify';
            $data = http_build_query([
                'secret'   => $recaptchaSecret,
                'response' => $recaptchaResponse,
                'remoteip' => $_SERVER['REMOTE_ADDR']
            ]);
            $options = ['http' => [
                'method'  => 'POST',
                'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
                'content' => $data
            ]];
            $result        = file_get_contents($verifyUrl, false, stream_context_create($options));
            $captchaResult = json_decode($result, true);

            if (!$captchaResult['success']) {
                $errors['captcha'] = 'La verificación reCAPTCHA falló. Intenta de nuevo.';
            }
        }

        // 5. Si no hay errores de formato → iniciar sesión (cualquier usuario entra)
        if (empty($errors)) {
            session_regenerate_id(true);
            $_SESSION['is_logged_in'] = true;
            $_SESSION['username']     = $username;
            $_SESSION['login_time']   = time();
            $_SESSION['csrf_token']   = bin2hex(random_bytes(32)); // rotar CSRF

            header('Location: dashboard.php');
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Acceso Seguro</title>
    <meta name="description" content="Página de acceso seguro al sistema. Ingresa tus credenciales para continuar.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="styles.css">
    <!-- Google reCAPTCHA v2 -->
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
</head>

<body>
    <div class="login-container">
        <form id="loginForm" method="POST" action="index.php" novalidate>

            <!-- Token CSRF oculto -->
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

            <div class="form-header">
                <span class="logo-icon">🔐</span>
                <h2>Bienvenido</h2>
                <p class="subtitle">Ingresa tus credenciales para continuar</p>
            </div>

            <?php if (!empty($errors['general'])): ?>
                <span class="error-message" style="display:block; margin-bottom:1rem; text-align:center;">
                    <?= htmlspecialchars($errors['general']) ?>
                </span>
            <?php endif; ?>

            <!-- Campo Usuario -->
            <div class="input-group">
                <label for="username">Usuario</label>
                <div class="input-wrapper">
                    <span class="input-icon">👤</span>
                    <input type="text" id="username" name="username"
                           placeholder="Ej: SGutierrez"
                           autocomplete="off"
                           value="<?= htmlspecialchars($_POST['username'] ?? '') ?>">
                </div>
                <span class="error-message" id="userError">
                    <?= htmlspecialchars($errors['username'] ?? '') ?>
                </span>
            </div>

            <!-- Campo Contraseña -->
            <div class="input-group">
                <label for="password">Contraseña</label>
                <div class="password-wrapper input-wrapper">
                    <span class="input-icon">🔑</span>
                    <input type="password" id="password" name="password"
                           placeholder="Escribe tu contraseña">
                    <button type="button" id="togglePassword" aria-label="Mostrar/ocultar contraseña">👁️</button>
                </div>

                <?php if (!empty($errors['password'])): ?>
                    <span class="error-message">
                        <?= htmlspecialchars(implode(' ', $errors['password'])) ?>
                    </span>
                <?php endif; ?>

                <ul class="requirements-list" id="requirements">
                    <li id="req-length"  class="invalid">Máximo 8 caracteres</li>
                    <li id="req-upper"   class="invalid">Una mayúscula</li>
                    <li id="req-number"  class="invalid">Un número</li>
                    <li id="req-special" class="invalid">Un carácter especial (!@#$...)</li>
                    <li id="req-space"   class="valid">Sin espacios vacíos</li>
                </ul>
            </div>

            <!-- Google reCAPTCHA v2 -->
            <div class="captcha-container">
                <div class="g-recaptcha"
                     data-sitekey="6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
                     data-theme="light">
                </div>
                <span class="error-message" id="captchaError">
                    <?= htmlspecialchars($errors['captcha'] ?? '') ?>
                </span>
            </div>

            <button type="submit" id="submitBtn">Entrar al Sistema</button>
        </form>
    </div>

    <script>
        const passwordInput = document.getElementById('password');
        const usernameInput = document.getElementById('username');
        const loginForm     = document.getElementById('loginForm');

        // ─── Referencias a los requisitos de contraseña ───────────────────────
        const requirements = {
            length:  document.getElementById('req-length'),
            upper:   document.getElementById('req-upper'),
            number:  document.getElementById('req-number'),
            special: document.getElementById('req-special'),
            space:   document.getElementById('req-space')
        };

        // ─── Validación en tiempo real de contraseña ──────────────────────────
        passwordInput.addEventListener('input', () => {
            const val = passwordInput.value;
            updateRequirement(requirements.length,  val.length <= 8 && val.length > 0);
            updateRequirement(requirements.upper,   /[A-Z]/.test(val));
            updateRequirement(requirements.number,  /[0-9]/.test(val));
            updateRequirement(requirements.special, /[!@#$%^&*()\-_=+\[\]{};':"\\|,.<>\/?]/.test(val));
            updateRequirement(requirements.space,   !/\s/.test(val) && val.length > 0);
        });

        function updateRequirement(element, isValid) {
            element.classList.toggle('valid',   isValid);
            element.classList.toggle('invalid', !isValid);
        }

        // ─── Mostrar / Ocultar contraseña ─────────────────────────────────────
        document.getElementById('togglePassword').addEventListener('click', function () {
            const isPwd = passwordInput.type === 'password';
            passwordInput.type = isPwd ? 'text' : 'password';
            this.textContent   = isPwd ? '🔒' : '👁️';
        });

        // ─── Validación client-side antes de enviar ───────────────────────────
        loginForm.addEventListener('submit', (e) => {
            const userVal  = usernameInput.value.trim();
            const allValid = Object.values(requirements).every(r => r.classList.contains('valid'));

            if (!userVal || userVal.length < 3 || /\s/.test(userVal)) {
                document.getElementById('userError').textContent = 'Ingresa un usuario válido (mín. 3 caracteres, sin espacios).';
                usernameInput.focus();
                e.preventDefault();
                return;
            }
            document.getElementById('userError').textContent = '';

            if (!allValid) {
                alert('La contraseña no cumple con todos los requisitos.');
                e.preventDefault();
                return;
            }

            const recaptchaToken = typeof grecaptcha !== 'undefined' ? grecaptcha.getResponse() : '';
            if (!recaptchaToken) {
                document.getElementById('captchaError').textContent = 'Por favor, completa la verificación reCAPTCHA.';
                e.preventDefault();
                return;
            }
            document.getElementById('captchaError').textContent = '';
        });
    </script>
</body>

</html>
