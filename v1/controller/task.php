<?php

require_once('db.php');
require_once('../model/Task.php');
require_once('../model/Response.php');

try {
    $writeDB = DB::connectWriteDB();
    $readDB = DB::connectReadDB();
} catch(PDOException $ex) {
    error_log("Connection error - " .$ex, 0);
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage("Database Connection Error");
    $response->send();
    exit();
}


// begin auth script

if(!isset($_SERVER['HTTP_AUTHORIZATION']) || strlen($_SERVER['HTTP_AUTHORIZATION']) < 1) {
    $response = new Response();
    $response->setHttpStatusCode(401);
    $response->setSuccess(false);
    $response->addMessage("Access token cannot be blank");
    $response->send();
    exit();
}

$accesstoken = $_SERVER['HTTP_AUTHORIZATION'];

try {

    $query = $writeDB->prepare('select userid, accesstokenexpiry, useractive, loginattempts from sessions, users where sessions.userid = users.id and accesstoken = :accesstoken');
    $query->bindParam(':accesstoken', $accesstoken, PDO::PARAM_INT);
    $query->execute();

    $rowCount = $query->rowCount();
    if($rowCount === 0) {
        $response = new Response();
        $response->setHttpStatusCode(401);
        $response->setSuccess(false);
        $response->addMessage("Invalid access token");
        $response->send();
        exit();
    }

    $row = $query->fetch(PDO::FETCH_ASSOC);

    $returned_userid = $row['userid'];
    $returned_useractive = $row['useractive'];
    $returned_loginattempts = $row['loginattempts'];
    $returned_accesstokenexpiry = $row['accesstokenexpiry'];

    if($returned_useractive !== 'Y') {
        $response = new Response();
        $response->setHttpStatusCode(401);
        $response->setSuccess(false);
        $response->addMessage("User account is not active");
        $response->send();
        exit;
    }

    if($returned_loginattempts >= 3) {
        $response = new Response();
        $response->setHttpStatusCode(401);
        $response->setSuccess(false);
        $response->addMessage("User account is currently locked out");
        $response->send();
        exit;
    }


    if(strtotime($returned_accesstokenexpiry) < time()) {
        $response = new Response();
        $response->setHttpStatusCode(401);
        $response->setSuccess(false);
        $response->addMessage("Access token has expired - please login again". date_default_timezone_get());
        $response->send();
        exit;
    }
}
catch(PDOException $ex) {
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage("There was an issue authenticating - please try again");
    $response->send();
    exit;
} 

// end auth script




if(array_key_exists("taskid", $_GET)) {
    $taskid = $_GET['taskid'];
    
    if($taskid == '' || !is_numeric($taskid)) {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage("Task ID cannot be blank and must be numeric");
        $response->send();
        exit();
    }
    
    if($_SERVER['REQUEST_METHOD'] === 'GET') {

        try {

            $query = $readDB->prepare('select id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed from tasks where id = :taskid and userid = :userid');
            $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
            $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
            $query->execute();

            $rowCount = $query->rowCount();

            if($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage("Task not found");
                $response->send();
                exit();
            }

            while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                $taskArray[] = $task->returnTasksAsArray();
            }

            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $taskArray;

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();
            exit();

        } 
        
        catch(TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit();
        }

        catch(PDOException $ex) {
            error_log("Database Query error - " .$ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to get Task");
            $response->send();
            exit();
        }

    } 
    
    elseif($_SERVER['REQUEST_METHOD'] === 'DELETE') {

        try {

            $query = $writeDB->prepare('delete from tasks where id= :taskid and userid = :userid');
            $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
            $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
            $query->execute();

            $rowCount = $query->rowCount();

            if($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage("Task Not Found");
                $response->send();
                exit();
            }

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->addMessage("Task Deleted");
            $response->send();
            exit();

        } catch (PDOException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to delete task");
            $response->send();
            exit();
        }

    } 
    
    elseif($_SERVER['REQUEST_METHOD'] === 'PATCH') {
        try {

            if(!isset($_SERVER['CONTENT_TYPE']) || $_SERVER['CONTENT_TYPE'] !== 'application/json') {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Content Type header not set to JSON");
                $response->send();
                exit();
            }
            
            $rawPatchData = file_get_contents('php://input');

            if(!$jsonData = json_decode($rawPatchData)) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Request body is not valid JSON");
                $response->send();
                exit();
            }

            $title_updated = false;
            $description_updated = false;
            $deadline_updated = false;
            $completed_updated = false;

            $queryFields = "";

            if(isset($jsonData->title)) {
                $title_updated = true;
                $queryFields .= "title = :title, ";
            }

            if(isset($jsonData->description)) {
                $description_updated = true;
                $queryFields .= "description = :description, ";
            }

            if(isset($jsonData->deadline)) {
                $deadline = true;
                $queryFields .= "deadline = STR_TO_DATE(:deadline. '%d/%m/%Y %H:%i'), ";
            }

            if(isset($jsonData->completed)) {
                $completed_updated = true;
                $queryFields .= "completed = :completed, ";
            }
 
            $queryFields = rtrim($queryFields, ", ");

            if($title_updated == false && $description_updated == false && $deadline_updated == false && $completed_updated == false) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("No task field provided");
                $response->send();
                exit();
            }

            $query = $writeDB->prepare('select id, title, description, DATE_FORMAT(deadline, "%m/%d/%Y %H:%i") as deadline, completed from tasks where id = :taskid and userid = :userid');
            $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
            $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
            $query->execute();

            $rowCount = $query->rowCount();
            if($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage("No Task Found to Update");
                $response->send();
                exit();
            }


            while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
            }

            $queryString = "update tasks set ".$queryFields." where id = :taskid and userid = :userid";
            $query = $writeDB->prepare($queryString);

            if($title_updated === true) {
                $task->setTitle($jsonData->title);
                $updated_title = $task->getTitle();
                $query->bindParam(':title', $updated_title, PDO::PARAM_STR);
            }

            if($description_updated === true) {
                $task->setDescription($jsonData->description);
                $updated_description = $task->getDescription();
                $query->bindParam(':description', $updated_description, PDO::PARAM_STR);
            }

            if($deadline_updated === true) {
                $task->setDeadline($jsonData->deadline);
                $updated_deadline = $task->getDeadline();
                $query->bindParam(':deadline', $updated_deadline, PDO::PARAM_STR);
            }

            if($completed_updated === true) {
                $task->setCompleted($jsonData->completed);
                $updated_completed = $task->getCompleted();
                $query->bindParam(':completed', $updated_completed, PDO::PARAM_STR);
            }

            $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
            $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);

            $query->execute();

            $rowCount = $query->rowCount();
            if($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Task not updated");
                $response->send();
                exit();
            }

            $query = $writeDB->prepare('select id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed from tasks where id = :taskid and userid = :userid');
            $query->bindParam('taskid', $taskid, PDO::PARAM_INT);
            $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
            $query->execute();

            $rowCount = $query->rowCount();

            if($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("No Task Found after update");
                $response->send();
                exit();
            }

            $taskArray = array();

            while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                $taskArray[] = $task->returnTasksAsArray();
                $returnData['tasks'] = $taskArray;

                $response = new Response();
                $response->setHttpStatusCode(200);
                $response->setSuccess(true);
                $response->addMessage('Task Updated');
                $response->setData($returnData);
                $response->send();
                exit();
            }

            $returnData = array();
            $returnData['rows_returned'] = $rowCount;


        } 
        catch(TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit();
        }
        catch(PDOException $ex) {
            error_log("Database Query Error -".$ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to update task");
            $response->send();
            exit();
        }
    } 
    
    else {
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage("Requested method not allowed");
        $response->send();
        exit();
    }
} 
elseif(array_key_exists("completed", $_GET)) {
    $completed = $_GET['completed'];

    if($completed !== 'Y' && $completed !== 'N') {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage("Completed fileter must be Y or N");
        $response->send();
        exit;
    }

    if($_SERVER['REQUEST_METHOD'] === 'GET') {

        try {

            $query = $readDB->prepare('select id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed from tasks where completed = :completed and userid = :userid');
            $query->bindParam(':completed', $completed, PDO::PARAM_STR);
            $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
            $query->execute();

            $rowCount = $query->rowCount();

            $taskArray = array();

            while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);

                $taskArray[] = $task->returnTasksAsArray();
            }

            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $taskArray;

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();
            exit;

        } catch(PDOException $ex) {
            error_log("DB Query Error -" .$ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to get Tasks");
            $response->send();
            exit;
        }

        catch(TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit;
        }

    } else {
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage("REquest Method Not Supported");
        $response->send();
        exit;
    }
}
elseif(array_key_exists("page", $_GET)) {
    if($_SERVER['REQUEST_METHOD'] === 'GET') {

        $page = $_GET['page'];

        if($page == '' || !is_numeric($page)) {
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage("Invalid Page Number");
            $response->send();
            exit();
        }

        $limitPerPage = 2;

        try {
            $query = $readDB->prepare('select count(id) as totalNoOfTasks from tasks where userid = :userid');
            $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
            $query->execute();

            $row = $query->fetch(PDO::FETCH_ASSOC);

            $taskCount = intval($row['totalNoOfTasks']);

            $noOfPages = ceil($taskCount/$limitPerPage);

            if($noOfPages == 0) {
                $noOfPages = 1;
            }

            if($page > $noOfPages || $page == 0) {
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage("Page Not Found");
                $response->send();
                exit();
            }

            $offset = ($page == 1 ? 0 : ($limitPerPage*($page-1)));

            $query = $readDB->prepare('select id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed from tasks where userid = :userid limit :pglimit offset :offset');
            $query->bindParam(':pglimit', $limitPerPage, PDO::PARAM_INT);
            $query->bindParam(':offset', $offset, PDO::PARAM_INT);
            $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);

            $query->execute();

            $rowCount = $query->rowCount();

            $taskArray = array();

            while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);

                $taskArray[] = $task->returnTasksAsArray();
            }

            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['total_rows'] = $taskCount;
            $returnData['total_pages'] = $noOfPages;
            ($page < $noOfPages ? $returnData['has_next_page'] = true : $returnData['has_next_page'] = false);
            ($page > 1 ? $returnData['has_prev_page'] = true : $returnData['has_prev_page'] = false);
            $returnData['tasks'] = $taskArray;

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();
            exit();

        } 
        catch(TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit();
        }

        catch(PDOException $ex) {
            error_log("Database query error - ".$ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to Get Tasks");
            $response->send();
            exit();
        }

    } else {
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage("Requested Method Not Allowed");
        $response->send();
        exit();
    }
}
elseif(empty($_GET)){

    if($_SERVER['REQUEST_METHOD'] === 'GET') {

        try {

            $query = $readDB->prepare('select id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed from tasks where userid = :userid');
            $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
            $query->execute();

            $rowCount = $query->rowCount();

            $taskArray = array();

            while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                $taskArray[] = $task->returnTasksAsArray();
            }

            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $taskArray;

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->setData($returnData);
            $response->send();
            exit();


        } catch(TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit();
        } catch(PDOException $ex) {
            error_log("Database Query Error -".$ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(405);
            $response->setSuccess(false);
            $response->addMessage("Failed to get all tasks");
            $response->send();
            exit();
        }

    } 
    elseif($_SERVER['REQUEST_METHOD'] === 'POST') {

        try {

            if(isset($_SERVER['CONTENT_TYPE']) && $_SERVER['CONTENT_TYPE'] !== 'application/json') {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Content Type Header is not set to JSON");
                $response->send();
                exit();
            }

            $rawPOSTData = file_get_contents('php://input');
            if(!$jsonData =  json_decode($rawPOSTData)) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Request body is not valid JSON");
                $response->send();
                exit();
            }

            if(!isset($jsonData->title) || !isset($jsonData->completed)) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                !isset($jsonData->title) ? $response->addMessage("Title Field is mandatory.") : false;
                !isset($jsonData->completed) ? $response->addMessage("Completed Field is mandatory.") : false;
                $response->send();
                exit();
            }

            $newTask = new Task(
                null, 
                $jsonData->title,
                (isset($jsonData->description) ? $jsonData->description : null),
                (isset($jsonData->deadline) ? $jsonData->deadline : null),
                $jsonData->completed
            );

            $title = $newTask->getTitle();
            $description = $newTask->getDescription();
            $deadline = $newTask->getDeadline();
            $completed = $newTask->getCompleted();

            $query = $writeDB->prepare('insert into tasks (title, description, deadline, completed, userid) values (:title, :description, STR_TO_DATE(:deadline, \'%d/%m/%Y %H:%i\'), :completed, :userid )');
            $query->bindParam(':title', $title, PDO::PARAM_STR);
            $query->bindParam(':description', $description, PDO::PARAM_STR);
            $query->bindParam(':deadline', $deadline, PDO::PARAM_STR);
            $query->bindParam(':completed', $completed, PDO::PARAM_STR);
            $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
            
            $query->execute();

            $rowCount = $query->rowCount();

            if($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage("Failed to create task");
                $response->send();
                exit();
            }

            $lastTaskID = $writeDB->lastInsertID();
            $query = $writeDB->prepare('select id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed from tasks where id = :taskid and userid = :userid');
            $query->bindParam(':taskid', $lastTaskID, PDO::PARAM_INT);
            $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
            $query->execute();

            $rowCount = $query->rowCount();
            if($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage("Failed to retrieve task after creation");
                $response->send();
                exit();
            }

            $taskArray = array();

            while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                $taskArray[] = $task->returnTasksAsArray();
            }

            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $taskArray;

            $response = new Response();
            $response->setHttpStatusCode(201);
            $response->setSuccess(true);
            $response->setData($returnData);
            $response->send();
            exit();

        }
        catch(TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit();
        }
        catch(PDOException $ex) {
            error_log("Database query error -" . $ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to insert task into database - check submitted data for erorrs");
            $response->send();
            exit();
        }

    }
    else {
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage("Requested Method Not Allowed");
        $response->send();
        exit();
    }



} else {
    $response = new Response();
    $response->setHttpStatusCode(404);
    $response->setSuccess(false);
    $response->addMessage("Endpoint Not Found");
    $response->send();
    exit();
}

