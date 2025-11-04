<?php
require_once "db.php";
global $db;

if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}
$error = "";

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 900;

if (isset($_SESSION["user_id"])) {
    header("Location: index.php");
    exit();
}

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["login"])) {
    if (
        !isset($_POST["csrf_token"]) ||
        !hash_equals($_SESSION["csrf_token"], $_POST["csrf_token"])
    ) {
        $error = "Invalid CSRF token. Please try again.";
    } elseif (empty($_POST["email"]) || empty($_POST["password"])) {
        $error = "Email and password are required.";
    } else {
        $email = $_POST["email"];
        $password = $_POST["password"];

        $stmt = $db->prepare("SELECT * FROM users WHERE email = :email");
        $stmt->bindParam(":email", $email);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $attempts = $user["failed_login_attempts"];
            $last_attempt_time = strtotime($user["last_login_attempt"]);

            if (
                $attempts >= MAX_LOGIN_ATTEMPTS &&
                time() - $last_attempt_time < LOCKOUT_TIME
            ) {
                $error =
                    "Too many failed login attempts. Please wait 15 minutes and try again.";
            } else {
                if (password_verify($password, $user["password"])) {
                    $stmt = $db->prepare(
                        "UPDATE users SET failed_login_attempts = 0, last_login_attempt = NULL WHERE id = :id",
                    );
                    $stmt->bindParam(":id", $user["id"]);
                    $stmt->execute();

                    session_regenerate_id(true);
                    $_SESSION["user_id"] = $user["id"];
                    unset($_SESSION["csrf_token"]);
                    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));

                    header("Location: index.php");
                    exit();
                } else {
                    $stmt = $db->prepare(
                        "UPDATE users SET failed_login_attempts = failed_login_attempts + 1, last_login_attempt = datetime('now') WHERE id = :id",
                    );
                    $stmt->bindParam(":id", $user["id"]);
                    $stmt->execute();

                    sleep(2);
                    $error = "Invalid email or password.";
                }
            }
        } else {
            sleep(2);
            $error = "Invalid email or password.";
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Login - Task Tracker</title>
    <link rel="stylesheet" type="text/css" href="style.css">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <div class="container">
        <h2>Login to Task Tracker</h2>
        <?php if ($error): ?>
            <p class="error"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
        <?php if (isset($_GET["registered"])): ?>
            <p class="success">Registration successful! You can now log in.</p>
        <?php endif; ?>
        <form action="login.php" method="post">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(
                $_SESSION["csrf_token"],
            ); ?>">
            <label for="email">Email</label>
            <input type="email" name="email" required placeholder="Enter Email">
            <label for="password">Password</label>
            <input type="password" name="password" required placeholder="Enter Password">
            <button type="submit" name="login">Login</button>
        </form>
        <p>Don't have an account? <a href="register.php">Register here</a>.</p>
    </div>
</body>
</html>
