<?php
session_start();  


if (!isset($_SESSION['user_id'])) {
    header("Location: index.html");  
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard</title>
    <link rel="stylesheet" href="style3.css">
 
</head>
<body>
    <div class="container">
        <h1>Welcome to your Dashboard!</h1>

        <?php
        
        if (isset($_SESSION['email'])) {
            echo "<p>You are logged in as: " . htmlspecialchars($_SESSION['email']) . "</p>";
        } else {
            echo "<p>Error: Email session variable is not set.</p>";
        }
        ?>
        
        <a href="php/logout.php">Logout</a>

    </div>
</body>
</html>
