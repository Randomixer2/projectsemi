<?php 
    include 'includes/db_connect.php';
    
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $name = $_POST['name'];
        $email = $_POST['email'];
        $message = $_POST['message'];

        
        $sql = "INSERT INTO user (name, email, message) VALUES ('$name','$email','$message')";
        
        
        if ($conn->query($sql) === TRUE){
            echo "the data was successfully inserted.";
        }else{
            echo "Error: " . $sql . "<br>" . $conn->error;
        }
        $conn->close();
    }else{
        echo"invalid request method";
    }    

?>
