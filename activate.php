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

//connection establishment
$DATABASE_HOST = 'localhost';
$DATABASE_USER = 'website';
$DATABASE_PASS = 'Donsenuwan1#';
$DATABASE_NAME = 'phplogin';
// Try and connect using the info above.
$con = mysqli_connect($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);
if (mysqli_connect_errno()) {
	// If there is an error with the connection, stop the script and display the error.
	exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}
//by pass the system for now due to buisness account issue and paid versions
// First we check if the email and code exists...
//not working due to email is not configured and this cost a price, so this is bypass using giving a user a activation code assuming he is using his own email
if (isset($_GET['email'], $_GET['code'])) {
	if ($stmt = $con->prepare('SELECT * FROM accounts WHERE email = ? AND activation_code = ?')) {
		$stmt->bind_param('ss', $_GET['email'], $_GET['code']);
		$stmt->execute();
		// Store the result so we can check if the account exists in the database.
		$stmt->store_result();
		if ($stmt->num_rows > 0) {
			// Account exists with the requested email and code.
			if ($stmt = $con->prepare('UPDATE accounts SET activation_code = ? WHERE email = ? AND activation_code = ?')) {
				// Set the new activation code to 'activated', this is how we can check if the user has activated their account.
				$newcode = 'activated';
				$stmt->bind_param('sss', $newcode, $_GET['email'], $_GET['code']);
				$stmt->execute();
				echo 'Your account is now activated! You can now <a href="index.html">login</a>!';
			}
		} else {
			echo 'The account is already activated or doesn\'t exist!';
		}
	}
}

?>
