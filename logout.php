<?php
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
