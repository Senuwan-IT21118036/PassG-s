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

$DATABASE_HOST = 'localhost';
$DATABASE_USER = 'website';
$DATABASE_PASS = 'Donsenuwan1#';
$DATABASE_NAME = 'phplogin';

$con = mysqli_connect($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);
if (mysqli_connect_errno()) {
    exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}
//$stmt = $con->prepare('SELECT URL, username, password FROM password WHERE id = ?');
//$stmt->bind_param('i', $_SESSION['id']);
//$stmt->execute();



// Check if form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

	$errors = array();
    // Validate username
    if (!isset($_POST['username']) || empty($_POST['username'])) {
        //$errors[] = 'Please enter a username';
		        $_SESSION['status'] = "Username must be 6-20 characters long and only contain letters and numbers!";
                        header('location: home.php');
			exit();
//	echo "<script>alert('Please enter a username!'); window.location.href='home.php';</script>";
    } else if (!preg_match('/^[a-zA-Z0-9_]{5,20}$/', $_POST['username'])) {
        //$errors[] = 'Username must be 6-20 characters long and only contain letters and numbers';
	                $_SESSION['status'] = "Username must be 6-20 characters long and only contain letters and numbers!";
                	header('location: home.php');
			exit();
//	echo "<script>alert('Username must be 6-20 characters long and only contain letters and numbers!'); window.location.href='home.php';</script>";
    }

    // Validate URL
    if (!isset($_POST['URL']) || empty($_POST['URL'])) {
        //$errors[] = 'Please enter a URL';
                        $_SESSION['status'] = "Please enter a valid Link!";
                        header('location: home.php');
			exit();

//echo "<script>alert('Please enter a username!'); window.location.href='home.php';</script>";
    } else if (!filter_var($_POST['URL'], FILTER_VALIDATE_URL)) {
        //$errors[] = 'Please enter a valid URL';
                        $_SESSION['status'] = "Please enter a valid Link!";
                        header('location: home.php');
			exit();
    }



    // If there are no errors, process the form
    if (empty($errors)) {
        // Process the form here



// Check if the form has been submitted
//if ($_SERVER['REQUEST_METHOD'] == 'POST') {

    // Retrieve the form data
    $URL = $_POST['URL'];
    $username = $_POST['username'];
    $password = $_POST['password'];
    //$hashed_URL = hash('sha256', $URL);
    //$hashed_password = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);


	//encryption
	$key="44F4BBE2A8E77367FEEEF9F2D8679";

	//activation code
	$stmt = $con->prepare('SELECT activation_code FROM accounts WHERE id = ?');
	$stmt->bind_param('i', $_SESSION['id']);
	$stmt->execute();
	$stmt->store_result();
	$stmt->bind_result($piv);
	$stmt->fetch();
	$stmt->close();
	$ac = $piv;

	//$encrypted_ps = base64_encode($password);
	$e_username = base64_encode($username);
	$PassG = openssl_encrypt($ac, "RC4", $key);


	//encryption test 2.4
	$encrypted_ps = openssl_encrypt($password,"AES-256-CBC",$PassG);
	//$encrypted_ps = mysqli_real_escape_string($conn, $encrypted_ps);


	// Encrypt the URL using AES-256-CBC
	//$e_URL = base64_encode($URL);
	//$encrypted_password = openssl_encrypt($encode_password, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $ac);



    // Insert the new record into the database
   	$stmt = $con->prepare('SELECT URL, username, password FROM password WHERE id = ?');
	$stmt = $con->prepare('INSERT INTO password (id, URL, username, password) VALUES (?, ?, ?, ?)');
	$stmt->bind_param('isss', $_SESSION['id'], $URL, $e_username, $encrypted_ps);
	$stmt->execute();
    	$stmt->close();
	header('Location: home.php');
    	exit();
	}
	}

?>
