<?php
require_once "db.php";
global $db;

if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}
$error = "";

if (isset($_SESSION["user_id"])) {
    header("Location: index.php");
    exit();
}

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["register"])) {
    $password_regex = '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/';

    if (empty($_POST["email"]) || empty($_POST["password"])) {
        $error = "Email and password are required.";
    } elseif (!filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email format.";
    } elseif (!preg_match($password_regex, $_POST["password"])) {
        $error =
            "Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.";
    } else {
        $email = $_POST["email"];
        $password = password_hash($_POST["password"], PASSWORD_DEFAULT);

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
            if ($e->errorInfo[1] == 19) {
                $error = "Email already registered. Please login.";
            } else {
                error_log("Registration Error: " . $e->getMessage());
                $error = "An unexpected error occurred. Please try again.";
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
