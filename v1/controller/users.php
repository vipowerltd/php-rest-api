<?php

require_once('db.php');
require_once('../model/Response.php');

try {

    $writeDB = DB::connectWriteDB();

} catch(PDOException $ex) {
    error_log("Connection Error - ".$ex, 0);
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage("Database Connection Error");
    $response->send();
    exit;
}

if($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $response = new Response();
    $response->setHttpStatusCode(405);
    $response->setSuccess(false);
    $response->addMessage("Request method not allowed");
    $response->send();
    exit;
}

if(!isset($_SERVER['CONTENT_TYPE']) || $_SERVER['CONTENT_TYPE'] != 'application/json') {
    $response = new Response();
    $response->setHttpStatusCode(400);
    $response->setSuccess(false);
    $response->addMessage("Content type not set to JSON");
    $response->send();
    exit;
}

$rawPostData = file_get_contents('php://input');

if(!$jsonData = json_decode($rawPostData)){
    $response = new Response();
    $response->setHttpStatusCode(400);
    $response->setSuccess(false);
    $response->addMessage("Request body is not valid JSON");
    $response->send();
    exit;
}

if(!isset($jsonData->fullname) || !isset($jsonData->username) || !isset($jsonData->password)) {
    $response = new Response();
    $response->setHttpStatusCode(400);
    $response->setSuccess(false);
    (!isset($jsonData->fullname) ? $response->addMessage("Full name is required") : false);
    (!isset($jsonData->username) ? $response->addMessage("Username is required") : false);
    (!isset($jsonData->password) ? $response->addMessage("Passoword is required") : false);
    $response->send();
    exit;
}

if(strlen($jsonData->fullname) < 1 || strlen($jsonData->fullname) > 255 || strlen($jsonData->username) < 1 || strlen($jsonData->username) > 255 || strlen($jsonData->password) < 1 || strlen($jsonData->password) > 255) {
    $response = new Response();
    $response->setHttpStatusCode(400);
    $response->setSuccess(false);
    (strlen($jsonData->fullname) < 1 ? $response->addMessage("Full name cannot be blank") : false);
    (strlen($jsonData->fullname) > 255 ? $response->addMessage("Full name cannot be greater than 255 characters") : false);
    (strlen($jsonData->username) < 1 ? $response->addMessage("Username cannot be blank") : false);
    (strlen($jsonData->username) > 255 ? $response->addMessage("Username cannot be greater than 255 characters") : false);
    (strlen($jsonData->password) < 1 ? $response->addMessage("Password cannot be blank") : false);
    (strlen($jsonData->password) > 255 ? $response->addMessage("Password cannot be greater than 255 characters") : false);
    $response->send();
    exit;
}

$fullname = trim($jsonData->fullname);
$username = trim($jsonData->username);
$password = $jsonData->password;

try {

    $query = $writeDB->prepare('select id from users where username = :username');
    $query->bindParam(':username', $username, PDO::PARAM_INT);
    $query->execute();

    $rowCount = $query->rowCount();

    if($rowCount !== 0) {
        $response = new Response();
        $response->setHttpStatusCode(409);
        $response->setSuccess(false);
        $response->addMessage("Username already exists");
        $response->send();
        exit;
    }

    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    $query = $writeDB->prepare('insert into users (fullname, username, password) values (:fullname, :username, :password)');
    $query->bindParam(':fullname', $fullname, PDO::PARAM_STR);
    $query->bindParam(':username', $username, PDO::PARAM_STR);
    $query->bindParam(':password', $hashed_password, PDO::PARAM_STR);

    $query->execute();

    $rowCount = $query->rowCount();
    if($rowCount === 0) {
        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage("Failed to create user account");
        $response->send();
        exit;
    }

    $lastUserId = $writeDB->lastInsertID();

    $returnData = array();
    $returnData['user_id'] = $lastUserId;
    $returnData['fullname'] = $fullname;
    $returnData['username'] = $username;

    $response = new Response();
    $response->setHttpStatusCode(201);
    $response->setSuccess(true);
    $response->setData($returnData);
    $response->addMessage("User Created");
    $response->send();
    exit;

} 
catch(PDOException $ex) {
    error_log('Database query error'.$ex,0);
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage("Failed to create user account");
    $response->send();
    exit;
}