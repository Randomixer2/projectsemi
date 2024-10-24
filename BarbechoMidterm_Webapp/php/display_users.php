<?php
include '../db_connect/db_connect.php'; 


if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

header('Content-Type: text/html; charset=utf-8');

$sql = "SELECT user_id, name, email, message, created_at FROM users";
$result = mysqli_query($conn, $sql); 

if (!$result) {
    die("Query failed: " . mysqli_error($conn));
}

if (mysqli_num_rows($result) > 0) {
    echo "<table>";
    echo "<tr><th>User ID</th><th>Name</th><th>Email</th><th>Message</th><th>Created At</th></tr>";
    while ($row = mysqli_fetch_assoc($result)) {
        echo "<tr>";
        echo "<td>" . htmlspecialchars($row["user_id"]) . "</td>";
        echo "<td>" . htmlspecialchars($row["name"]) . "</td>";
        echo "<td>" . htmlspecialchars($row["email"]) . "</td>";
        echo "<td>" . htmlspecialchars($row["message"]) . "</td>";
        echo "<td>" . htmlspecialchars($row["created_at"]) . "</td>"; 
        echo "</tr>";              
    }
    echo "</table>";
} else {
    echo "No results found.";
}

mysqli_close($conn);
?>
