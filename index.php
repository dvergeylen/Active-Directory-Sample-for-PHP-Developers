<?php
    if(!isset($_SESSION)) {
        session_start();
    }
    include_once("classes/adfsbridge.php");
    include_once("conf/adfsconf.php");
?>

<!DOCTYPE html>
<html lang="en">
	<head>
		<meta http-equiv="content-type" content="text/html; charset=utf-8" />
        <title>Adfs Minimal example</title>
		<style>
			#container {
				width: 80%;
				margin: auto;
			}
		</style>
	</head>
	<body>
		<div id="container">
			<h1>ADFS Minimal Example</h1>
			<?php if(!isset($_SESSION['AdfsUserDetails'])) : ?>
				<p>
					<strong>You are not logged In!</strong>
				</p>
				<form action="authform.php" method="post" name="login" id="form-login">
					<input type="hidden" name="authaction" value="Login" />
					<input type="submit" name="Submit" class="button" value="Log in" />
				</form>
			<?php else : ?>
				<p>
					<strong>You are logged In!</strong>
				</p>
				<form action="authform.php" method="post" name="login" id="form-logout">
					<input type="hidden" name="authaction" value="Logout" />
					<input type="submit" name="Submit" class="button" value="Log out" />
				</form>
				<?php
					// Show User ID and attributes.
					$userDetails =$_SESSION['AdfsUserDetails'];
					echo '<p>';						
					echo '<b>Name Identifier: </b>'. $userDetails['nameIdentifier'];
					echo '</p>';
					echo '<p>';						
					echo '<b>Name Identifier Format: </b>'. $userDetails['nameIdentifierFormat'];
					echo '</p>';
					
					echo '<h4>Attributes: </h4>';
					echo '<pre>';
					var_dump($userDetails['attributes']);
					echo '</pre>';
				?>
			<?php endif; ?>
		</div>
	</body>
</html>
