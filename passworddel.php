<?php

  header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
  //ensure that site is accessed via https
  header("Referrer-Policy: strict-origin-when-cross-origin");
  //ensure that the full URL is only sent if the request originates from the same domain
  header("X-Permitted-Cross-Domain-Policies: none");
  //ensure no-cross domain policies are allowed
  header("Content-Security-Policy: frame-ancestors 'none'", false);
  //enusre no external sites are allowed to embed the website
  header('X-Frame-Options: SAMEORIGIN');
  //ensure website can only be embedded on pages with the same origin
  header('X-XSS-Protection: 1; mode=block');
  //ensure it filters XSS attacks and tells the browser to block the page if an XSS attack is detected
  header('X-Frame-Options: DENY');
  //ensure not to allow the website to be embedded in any frame or iframe
  header('X-Content-Type-Options: nosniff');
  //tells the browser not to guess the content type based on the contents of the file and prevent from MIME sniffing attacks
  session_cache_limiter('nocache');
  //ensures that sensitive data is not stored in the browser's cache

session_start();
// Retrieve the number from the form input
$number = $_POST['number'];

// Connect to the MySQL database
$servername = "localhost";
$username = "website";
$password = "Donsenuwan1#";
$dbname = "phplogin";

$conn = mysqli_connect($servername, $username, $password, $dbname);

// Check connection
if (!$conn) {
  die("Connection failed: " . mysqli_connect_error());
}

// Run the delete command on the MySQL table
//$sql = "DELETE FROM password WHERE no = $number";
$stmt = mysqli_prepare($conn, "DELETE FROM password WHERE no = ?");
mysqli_stmt_bind_param($stmt, "i", $number);
if (mysqli_stmt_execute($stmt)) {
$_SESSION['status'] = "Deleted Successfully!";
header('location: home.php');
} else {
$_SESSION['status'] = "Error deleting record!";
header('location: home.php');
}

mysqli_stmt_close($stmt);
mysqli_close($conn);
?>

