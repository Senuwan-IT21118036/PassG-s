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



//connection establishment
$DATABASE_HOST = 'localhost';
$DATABASE_USER = 'website';
$DATABASE_PASS = 'Donsenuwan1#';
$DATABASE_NAME = 'phplogin';

$con = mysqli_connect($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);
if (mysqli_connect_errno()) {
	// If there is an error with the connection, stop the script and display the error.
	//exit('Failed to connect to MySQL: ' . mysqli_connect_error());
	//echo "<script>alert('Connection Error!'); window.location.href='register.html.php';</script>";
	$_SESSION['status'] = "Connection Error!";
        header('location: register.html.php');
        exit();
}
// Now we check if the data was submitted, isset() function will check if the data exists.
if (!isset($_POST['username'], $_POST['password'], $_POST['email'])) {
	// Could not get the data that should have been sent.
	//exit('Please complete the registration form!');
	//echo "<script>alert('Please complete the form!'); window.location.href='register.html.php';</script>";
        $_SESSION['status'] = "Complete the form!";
        header('location: register.html.php');
        exit();
}
// Make sure the submitted registration values are not empty.
if (empty($_POST['username']) || empty($_POST['password']) || empty($_POST['email'])) {
	// One or more values are empty.
	//exit('Please complete the registration form');
	//echo "<script>alert('Please complete the form!'); window.location.href='register.html.php';</script>";
        $_SESSION['status'] = "Please complete the registration form!";
        header('location: register.html.php');
        exit();
}
//Email check
if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
	//exit('Email is not valid!');
	//echo "<script>alert('Email is not valid!'); window.location.href='register.html.php';</script>";
        $_SESSION['status'] = "Email is not valid!";
        header('location: register.html.php');
        exit();
}
//username validation
if (preg_match('/^[a-zA-Z0-9]+$/', $_POST['username']) == 0) {
    //exit('Username is not valid!');
	//echo "<script>alert('Username is not valid!'); window.location.href='register.html.php';</script>";
        $_SESSION['status'] = "Username is not valid!";
        header('location: register.html.php');
        exit();
}
// We need to check if the account with that username exists.
if ($stmt = $con->prepare('SELECT id, password FROM accounts WHERE username = ?')) {
	// Bind parameters (s = string, i = int, b = blob, etc), hash the password using the PHP password_hash function.
	$stmt->bind_param('s', $_POST['username']);
	$stmt->execute();
	$stmt->store_result();
	// Store the result so we can check if the account exists in the database.
	if ($stmt->num_rows > 0) {
		// Username already exists, display error message on registration form
    		 //exit('Username is not valid!');
		//echo "<script>alert('Username already exsists!'); window.location.href='register.html.php';</script>";
        	$_SESSION['status'] = "Username already exsists!";
        	header('location: register.html.php');
        	exit();
	} else {
		// Username doesn't exists, insert new account
if ($stmt = $con->prepare('INSERT INTO accounts (username, password, email, activation_code) VALUES (?, ?, ?, ?)')) {
	// We do not want to expose passwords in our database, so hash the password and use password_verify when a user logs in.
	$password = password_hash($_POST['password'], PASSWORD_DEFAULT);
	$uniqid = uniqid();
	$stmt->bind_param('ssss', $_POST['username'], $password, $_POST['email'], $uniqid);
	$stmt->execute();
	$from    = 'senuwanlolc@gmail.com';
	$subject = 'Account Activation Required';
	$headers = 'From: ' . $from . "\r\n" . 'Reply-To: ' . $from . "\r\n" . 'X-Mailer: PHP/' . phpversion() . "\r\n" . 'MIME-Version: 1.0' . "\r\n" . '	Content-Type: text/html; charset=UTF-8' . "\r\n";
	// Update the activation variable below
	$activate_link = 'http://152.70.161.47/activate.php?email=' . $_POST['email'] . '&code=' . $uniqid;
	$message = '<p>Please click the following link to activate your account: <a href="' . $activate_link . '">' . $activate_link . '</a></p>';
	mail($_POST['email'], $subject, $message, $headers);
	$message = "Please check your email to activate your account!";
		echo "<script>alert('$message');</script>";
	header("Location: login.html.php");
} else {
	// Something is wrong with the SQL statement, so you must check to make sure your accounts table exists with all 3 fields.
	echo 'Could not prepare statement!';
}
	}
	$stmt->close();
} else {
	// Something is wrong with the SQL statement, so you must check to make sure your accounts table exists with all 3 fields.
	echo 'Could not prepare statement!';
}
$con->close();
?>
