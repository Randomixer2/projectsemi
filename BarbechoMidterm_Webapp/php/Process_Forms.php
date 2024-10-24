<?php
include ('../db_connect/db_connect.php'); 

    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $username = $_POST['name'];
        $email = $_POST['email'];
        $message = $_POST['message'];


        if (!preg_match("/^[a-zA-Z0-9._\s]*$/", $name)){
            echo"<script>alert('Error')</script>";
        }
        
        if (!$conn)
        {
            die("Connection error: ". mysqli_connect_error());
        }

        $sql = "INSERT INTO users (name, email, message) VALUES (?,?,?)";

        $stmt = mysqli_prepare($conn, $sql);
        if($stmt){
            mysqli_stmt_bind_param($stmt, 'sss', $username, $email, $message);

            mysqli_stmt_execute($stmt);

            mysqli_stmt_close($stmt);

            echo" You have sent {$message} from {$username}";
        }
        
    }
?>
