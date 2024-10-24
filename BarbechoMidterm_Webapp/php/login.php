<?php
session_start(); 
include '../db_connect/db_connect.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST['email'];
    $password = $_POST['password'];

    
    $check_email = "SELECT id, password FROM user WHERE email = ?";
    $stmt = $conn->prepare($check_email);
    if (!$stmt) {
        die("SQL Error: " . $conn->error);
    }
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows == 0) {
        echo "No account found with that email address.";
    } else {
        
        $stmt->bind_result($user_id, $hashed_password);
        $stmt->fetch();

        
        if (password_verify($password, $hashed_password)) {
            
            $_SESSION['user_id'] = $user_id;
            $_SESSION['email'] = $email;
            echo "Login successful! Welcome!";
            
            header("Location: dashboard.php");
            exit();
        } else {
            echo "Incorrect password.";
        }
    }
    $stmt->close();
}

$conn->close();
?>
