<?php
$pepper = "c1isvFdxMDdmjOlvxpecFw";

function hash_pass($password): string
{
    global $pepper;
    $pwd_peppered = hash_hmac("sha256", $password, $pepper);
    $pwd_hashed = password_hash($pwd_peppered, PASSWORD_ARGON2ID);

    return $pwd_hashed;
}

function verify_pass($input_pass, $hashed_pass): bool
{
    global $pepper;
    $pwd_peppered = hash_hmac("sha256", $input_pass, $pepper);
    return password_verify($pwd_peppered, $hashed_pass);
}
