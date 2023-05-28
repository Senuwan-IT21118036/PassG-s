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
// We don't have the password or email info stored in sessions, so instead, we can get the results from the database.
$stmt = $con->prepare('SELECT password, email FROM accounts WHERE id = ?');
// In this case we can use the account ID to get the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($password, $email);
$stmt->fetch();
$stmt->close();
?>
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<title>Profile Page</title>
		<link href="stylehp.css" rel="stylesheet" type="text/css">
		<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css" integrity="sha512-xh6O/CkQoPOWDdYTDqeRdPCVd1SpvCA9XXcUnZS2FmJNp1coAFzvtCN9BmamE+4aHK8yyUHUSCcJHgXloTyT2A==" crossorigin="anonymous" referrerpolicy="no-referrer">
		<link rel="icon" href="/images/354-3544185_related-wallpapers-security-logo.png" sizes="64x64">
	</head>
	<body class="loggedin">
		<nav class="navtop">
			<div>
				<h1><a href="home.php">PassG's</a></h1>
				<a href="profile.php"><i class="fas fa-user-circle"></i>About</a>
				<a href="logout.php"><i class="fas fa-sign-out-alt"></i>Logout</a>
			</div>
		</nav>
		<div class="content">
			<h2>About Us</h2>

		<div>
<p>
PassG is a leading password manager designed to offer robust and reliable password management services to users looking to protect their online accounts. PassG is a cloud-based password manager that allows users to store their login credentials in a single, secure location, making it easier to access their accounts and websites.
<p>
At PassG, we understand the importance of online security, and we are committed to helping users protect their accounts against cyber threats such as phishing, hacking, and identity theft. Our password manager uses advanced encryption technology to protect user data, and we are constantly updating our security protocols to ensure the highest level of protection for our users.
<p>
Our password manager is designed with simplicity and ease of use in mind, so users can easily store and manage their login credentials without any technical knowledge or hassle. Our interface is user-friendly, and our features are easy to navigate, allowing users to quickly and easily find the information they need.
<p>
PassG offers a range of features designed to make password management easier and more convenient. Users can generate complex and unique passwords using our built-in password generator, eliminating the need to remember multiple passwords. Our auto-fill feature allows users to automatically fill in their login credentials when accessing websites, further streamlining the login process.
<p>
PassG also offers multi-device support, allowing users to access their passwords and login credentials on all their devices, including smartphones, tablets, and laptops. Our password manager also offers backup and sync features, ensuring that users' data is always safe and up-to-date.
<p>
At PassG, we are committed to user privacy and security. We do not share or sell user data to third parties, and all user information is encrypted and protected by advanced security protocols. Our password manager also offers two-factor authentication, providing an extra layer of protection against unauthorized access.
<p>
PassG offers flexible pricing plans to suit the needs and budgets of all users. Our free plan offers basic password management features, while our premium plan offers advanced features such as unlimited password storage, multi-device support, and priority customer support.


                </div>

			<h2>Profile Info</h2>
			<div>
				<p>Your account details are below:</p>
				<table>
					<tr>
						<td>Username:</td>
						<td><?=$_SESSION['name']?></td>
					</tr>
					<tr>
						<td>Password:</td>
						<td><?=$password?></td>
					</tr>
					<tr>
						<td>Email:</td>
						<td><?=$email?></td>
					</tr>
				</table>
			</div>
		</div>
	</body>
</html>
