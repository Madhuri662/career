<?php
session_start();

// Database connection details
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "prefix2"; // Adjusted to match the new database name

// Create a connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Turn on error reporting (for debugging)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Check if form is submitted for registration
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['register'])) {
    // Get form data
    $name = $_POST['name'] ?? '';  
    $email = $_POST['email'] ?? '';
    $phone = $_POST['phone'] ?? '';
    $password = $_POST['password'] ?? '';

    // Hash the password before storing it
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);

    // Prepare SQL statement to check for email existence
    $stmt = $conn->prepare("SELECT id FROM fix1 WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    // Check if email already exists
    if ($result->num_rows > 0) {
        echo "<script>alert('Email already exists! Please use a different email.'); window.location.href = 'signup.html';</script>";
        exit();
    } else {
        // Insert new user data into the database
        $stmt = $conn->prepare("INSERT INTO fix1 (name, email, phone, password) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $name, $email, $phone, $hashed_password); // Bind parameters correctly

        if ($stmt->execute()) {
            echo "Data inserted successfully!<br>";
            echo '<button onclick="window.location.href=\'login.html\'">Go to Login</button>';
        } else {
            echo "Error executing statement: " . $stmt->error;
        }
        
        $stmt->close();
    }
}

// Close database connection
$conn->close();
?>
