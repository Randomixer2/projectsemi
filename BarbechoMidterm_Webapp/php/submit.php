<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    
    $name = htmlspecialchars(trim($_POST['name']));
    $email = htmlspecialchars(trim($_POST['email']));
    $message = htmlspecialchars(trim($_POST['message']));

    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "Invalid email format.";
        exit;
    }

    
    $to = "your-email@example.com"; /
    $subject = "Contact Form Submission from $name";
    $body = "Name: $name\nEmail: $email\n\nMessage:\n$message";
    $headers = "From: $email";

    
    if (mail($to, $subject, $body, $headers)) {
        header("Location: thank_you.html"); 
        exit;
    } else {
        echo "There was a problem sending the email.";
    }
} else {
    echo "Invalid request method.";
}
?>
