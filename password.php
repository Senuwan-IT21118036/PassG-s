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

//Start a new session or resume an existing one
session_start();

// If the user is not logged in redirect to the login page...
if (!isset($_SESSION['loggedin'])) {
    header('Location: login.html.php');
    exit;
}
//connection establishment
$DATABASE_HOST = 'localhost';
$DATABASE_USER = 'website';
$DATABASE_PASS = 'Donsenuwan1#';
$DATABASE_NAME = 'phplogin';

$con = mysqli_connect($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);
if (mysqli_connect_errno()) {
    exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}



// Define the encryption key
$key = "44F4BBE2A8E77367FEEEF9F2D8679";

// Prepare and execute a SQL statement to retrieve the activation code for the current user ID
$stmt = $con->prepare('SELECT activation_code FROM accounts WHERE id = ?');
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();

// Store the result of the query
$stmt->store_result();

// Bind the retrieved activation code to a variable
$stmt->bind_result($piv);
$stmt->fetch();

// Close the statement
$stmt->close();

// Encrypt the activation code using the RC4 algorithm
$encryptedCode = openssl_encrypt($ac, "RC4", $key);


// Retrieve all usernames, passwords, and URLs from the database based on the logged-in user's ID.
$stmt = $con->prepare('SELECT URL, username, password, no FROM password WHERE id = ?');
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($URL, $username, $password, $no);



// Declare arrays to store usernames, passwords, URLs, and numbers.
$usernames = array();
$passwords = array();
$URLs = array();
$nos = array();

// Iterate through the data using a fetch statement.
while ($stmt->fetch()) {
    // Store the URL after decoding it from base64.
    $URLs[] = $URL;

    // Decode the username from base64 and store it.
    $decodedUsername = base64_decode($username);
    $usernames[] = $decodedUsername;

    // Decrypt the password using AES-256-CBC encryption with a given key.
    $decodedPassword = openssl_decrypt($password, "AES-256-CBC", $PassG);
    $passwords[] = $decodedPassword;

    // Store the number directly.
    $nos[] = $no;
}


$stmt->close();

// Display the array of usernames, passwords, and URLs in an HTML table on a new page.
?>
