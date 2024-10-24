<?php
include ('../db_connect/db_connect.php'); 

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST['name']);
    $email = trim($_POST['email']);
    $message = trim($_POST['message']);
    $errors = [];

    
    if (empty($username) || !preg_match("/^[a-zA-Z0-9._\s]+$/", $username)) {
        $errors[] = "Invalid username. Only letters, numbers, dots, and underscores are allowed.";
    }

    
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    }

    
    if (empty($message)) {
        $errors[] = "Message cannot be empty.";
    }

    
    if (!$conn) {
        die("Connection error: " . mysqli_connect_error());
    }

    
    if (!empty($errors)) {
        foreach ($errors as $error) {
            echo "<script>alert('" . htmlspecialchars($error) . "');</script>";
        }
    } else {
        
        $sql = "INSERT INTO users (name, email, message) VALUES (?, ?, ?)";
        $stmt = mysqli_prepare($conn, $sql);

        if ($stmt) {
            mysqli_stmt_bind_param($stmt, 'sss', $username, $email, $message);
            if (mysqli_stmt_execute($stmt)) {
                
                header("location:../thank-you_message.html");
                exit(); 
            } else {
                echo "<script>alert('Error executing query: " . mysqli_error($conn) . "');</script>";
            }
            mysqli_stmt_close($stmt);
        } else {
            echo "<script>alert('Error preparing statement: " . mysqli_error($conn) . "');</script>";
        }
    }

    mysqli_close($conn);
}
?>
