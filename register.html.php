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
        //Starts the PHP session, allowing the script to access session variables.
?>


<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<title>Register</title>
		<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css" integrity="sha512-xh6O/CkQoPOWDdYTDqeRdPCVd1SpvCA9XXcUnZS2FmJNp1coAFzvtCN9BmamE+4aHK8yyUHUSCcJHgXloTyT2A==" crossorigin="anonymous" referrerpolicy="no-referrer">
		<link href="stylerp.css" rel="stylesheet" type="text/css">
        	<link rel="stylesheet" href="alert.css" type="text/css">
		<link rel="icon" href="/images/354-3544185_related-wallpapers-security-logo.png" sizes="64x64">
	</head>
	<body>

<?php
    if(isset($_SESSION['status'])) //check is status is not null and display the alert
    {
        ?>
            <div class="alert alert-warning alert-dismissible fade show" role="alert">
                <strong>Hey !</strong> <?= $_SESSION['status']; ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></>            </div>
        <?php
        unset($_SESSION['status']);
    }

?>
		<div class="register">
			<img src="/images/354-3544185_related-wallpapers-security-logo.png" width="300px" height="auto">
			<h1>Register</h1>
			<form action="register.php" method="post" autocomplete="off">

				<input type="text" name="username" placeholder="Username" id="username" required>
					//check for user is already on the system
					<?php if (isset($username_error)) { ?>
    						<span class="error"><?php echo $username_error; ?></span>
					<?php } ?>

				<input type="password" name="password" placeholder="Password" id="password" required>

				<input type="email" name="email" placeholder="Email" id="email" required>

				<input type="submit" value="Register">

				<h3>Already have a account? <a href="login.html.php">Login</a></h3>
			<br><br> 
			</form>
		</div>
	</body>
</html>
