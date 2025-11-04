<?php
/**
 * Logout Script
 *
 * This script handles the user logout process. It verifies a CSRF token
 * from a POST request, destroys the current session, and then redirects
 * the user to the login page.
 */
require_once "db.php";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (
        isset($_POST["csrf_token"]) &&
        hash_equals($_SESSION["csrf_token"], $_POST["csrf_token"])
    ) {
        session_unset();
        session_destroy();
    }
}

header("Location: login.php");
exit();
