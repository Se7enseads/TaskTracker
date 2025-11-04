<?php
function log_event($msg, $level = "info")
{
    $line = date("c") . " [$level] " . $msg . PHP_EOL;
    file_put_contents(__DIR__ . "/logs/app.log", $line, FILE_APPEND | LOCK_EX);
}
