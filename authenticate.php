<?php

        //headers
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
if ( mysqli_connect_errno() ) {
	// If there is an error with the connection, stop the script and display the error.
	exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}
// Now we check if the data from the login form was submitted, isset() will check if the data exists.
if ( !isset($_POST['username'], $_POST['password']) ) {
	// Could not get the data that should have been sent.
	exit('Please fill both the username and password fields!');
}
// Prepare our SQL, preparing the SQL statement will prevent SQL injection.
if($_POST['captcha'] === $_SESSION['captcha']) {	
	if ($stmt = $con->prepare('SELECT id, password FROM accounts WHERE username = ?')) {
	// Bind parameters (s = string, i = int, b = blob, etc), in our case the username is a string so we use "s"
	$stmt->bind_param('s', $_POST['username']);
	$stmt->execute();
	// Store the result so we can check if the account exists in the database.
	$stmt->store_result();
	if ($stmt->num_rows > 0) {
	$stmt->bind_result($id, $password);
	$stmt->fetch();
	// Account exists, now we verify the password.
	if (password_verify($_POST['password'], $password)) {
		// Verification success! User has logged-in!
		// Create sessions, so we know the user is logged in, they basically act like cookies but remember the data on the server.
		session_regenerate_id();
		$_SESSION['loggedin'] = TRUE;
		$_SESSION['name'] = $_POST['username'];
		$_SESSION['id'] = $id;
		header('Location: home.php');
	} else {
		// Incorrect password
		//echo "<script>alert('Incorrect username and/or password!'); window.location.href='login.html.php';</script>";
	        $_SESSION['status'] = "Incorrect Username or Password or Invalid Captcha!";
        	header('location: login.html.php');
	}
} else {
	// Incorrect username
	//echo "<script>alert('Incorrect username and/or password!'); window.location.href='login.html.php';</script>";
                $_SESSION['status'] = "Incorrect Username or Password or Invalid Captcha!";
                header('location: login.html.php');
}

	$stmt->close();
}
}
else {
        // CAPTCHA code is incorrect, display error message
                $_SESSION['status'] = "Incorrect Username or Password or Invalid Captcha!";
                header('location: login.html.php');
}
?>
