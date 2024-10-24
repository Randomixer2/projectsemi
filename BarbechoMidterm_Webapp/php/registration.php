<?php
include '../db_connect/db_connect.php';  

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $email = $_POST['email'];
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT); 

    
    $check_email = "SELECT email FROM user WHERE email = ?";
    $stmt = $conn->prepare($check_email);

    if (!$stmt) {
        
        die("Error preparing statement: " . $conn->error);
    }

    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        echo "Email is already registered!";
    } else {
        
        $sql = "INSERT INTO user (username, email, password) VALUES (?, ?, ?)";
        $stmt = $conn->prepare($sql);

        if (!$stmt) {
            
            die("Error preparing insert statement: " . $conn->error);
        }

        
        $stmt->bind_param("sss", $username, $email, $password);

        if ($stmt->execute()) {
            echo "Registration successful! You can now <a href='php/login.php'>login</a>";
        } else {
            echo "Error executing statement: " . $stmt->error;  
        }

        $stmt->close();  
    }
}

$conn->close();  
?>
