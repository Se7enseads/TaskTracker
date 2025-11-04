<?php
/*
 * This script handles user registration for the Task Tracker application.
 *
 * - It includes the database connection and session management.
 * - If a user is already logged in, it redirects them to the main page.
 * - On POST request, it validates the registration form data:
 *   - Verifies the CSRF token for security.
 *   - Ensures email and password are not empty.
 *   - Validates the email format.
 *   - Enforces password complexity rules (length, character types).
 * - If validation is successful, it hashes the password and inserts the new
 *   user into the database.
 * - Upon successful registration, it redirects the user to the login page.
 * - It handles potential database errors, such as a duplicate email,
 *   and displays appropriate user-friendly error messages.
 * - The script then renders the HTML registration form, displaying any
 *   validation or registration errors.
 */
require_once "db.php";
require_once "func/passwd.php";

global $db;

$error = "";

if (isset($_SESSION["user_id"])) {
    header("Location: index.php");
    exit();
}

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["register"])) {
    if (
        !isset($_POST["csrf_token"]) ||
        !hash_equals($_SESSION["csrf_token"], $_POST["csrf_token"])
    ) {
        $error = "Invalid security token. Please try again.";
    } else {
        $password_regex = '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/';

        if (empty($_POST["email"]) || empty($_POST["password"])) {
            $error = "Email and password are required.";
        } elseif (!filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
            $error = "Invalid email format.";
        } elseif (!preg_match($password_regex, $_POST["password"])) {
            $error =
                "Password must be at least 8 characters long and include an uppercase, lowercase, number, and special character.";
        } else {
            $email = $_POST["email"];
            $password = hash_pass($_POST["password"]);

            try {
                $stmt = $db->prepare(
                    "INSERT INTO users (email, password) VALUES (:email, :password)",
                );
                $stmt->bindParam(":email", $email);
                $stmt->bindParam(":password", $password);
                $stmt->execute();
                header("Location: login.php?registered=true");
                exit();
            } catch (PDOException $e) {
                switch ($e->errorInfo[1]) {
                    case 19:
                        $error = "Email already registered. Please login.";
                        break;
                    default:
                        log_event(
                            "Registration Error for email $email: " .
                                $e->getMessage(),
                            "error",
                        );
                        $error =
                            "An unexpected error occurred. Please try again.";
                        break;
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Register - Task Tracker</title>
    <link rel="stylesheet" type="text/css" href="style.css">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <div class="container">
        <h2>Register for Task Tracker</h2>
        <?php if ($error): ?>
            <p class="error"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
        <form action="register.php" method="post">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(
                $_SESSION["csrf_token"],
            ); ?>">
            <label for="email">Email</label>
            <input type="email" name="email" required placeholder="Enter Email">
            <label for="password">Password</label>
            <input type="password" name="password" required placeholder="Enter Password" title="Password must be 8+ characters and include an uppercase, lowercase, number, and special character.">
            <button type="submit" name="register">Register</button>
        </form>
        <p>Already have an account? <a href="login.php">Login here</a>.</p>
    </div>
</body>
</html>
