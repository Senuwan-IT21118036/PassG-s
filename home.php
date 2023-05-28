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
        //Starts the PHP session, allowing the script to access session variable
// If the user is not logged in redirect to the login page...
if (!isset($_SESSION['loggedin'])) {
	header('Location: login.html.php');
	exit;
}
require 'password.php';
?>
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<title>Home Page</title>
		<script src="script.js"></script>
		<link href="stylehp.css" rel="stylesheet" type="text/css">
		<link href="alert.css" rel="stylesheet" type="text/css">
		<link href="stylepass.css" rel="stylesheet" type="text/css">
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
			<h2>Home Page</h2>
			<p>Welcome back, <?=$_SESSION['name']?>!
</p>


<?php
    session_start();

    if(isset($_SESSION['status']))
    {
        ?>
            <div class="alert alert-warning alert-dismissible fade show" role="alert">
                <strong>Hey !</strong> <?= $_SESSION['status']; ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></>            </div>
        <?php
        unset($_SESSION['status']);
    }

?>


		<div>
			<form action="passwordrg.php" method="post" autocomplete="off">
				<label for="username">
					<i class="fas fa-user"></i>
				</label>
				<input type="text" name="username" placeholder="Username" id="username" required>
				<label for="password">
					<i class="fas fa-lock"></i>
				</label>
				<input type="password" name="password" placeholder="Password" id="password" required>
				<label for="email">
					<i class="fas fa-envelope"></i>
				</label>
				<input type="URL" name="URL" placeholder="Link" id="URL" required>
				<br>
				
				<br>
				<input type="submit" value="Save">
			</form>
		</div>



<?php for ($i = 0; $i < count($usernames); $i++) : ?>
<br>
<p>


<br>Link: <a href="<?=$URLs[$i]?>" target="_blank"><?=$URLs[$i]?></a>
<br>Username: <?=htmlspecialchars($usernames[$i])?>
  <button id="copyBtn<?=$i?>" style="opacity: 0; position: absolute; left: -9999px;"></button>
  <i class="fas fa-clone" onclick="copyUsername('<?=htmlspecialchars($usernames[$i])?>', <?=$i?>)" style="cursor: pointer;"></i>
<br>
	Password: <?=str_repeat("*", strlen($passwords[$i]))?>


	<button id="copyBtn<?=$i?>" style="opacity: 0; position: absolute; left: -9999px;"> </button>
 	<i class="fas fa-clone" onclick="copyUsername('<?=htmlspecialchars($passwords[$i])?>', <?=$i?>)" style="cursor: pointer;"></i>
<br>
<button type="button" onclick="submitForm(<?= $nos[$i] ?>)" style="background:none;border:none;">
<i class="fas fa-trash" style="color:red;"></i>
</button>

</p>
<?php endfor; ?>

<script src="script.js"></script>

		</div>
	</body>
</html>
