<html>
	<head>Authorize</head>
	<body>
		<form method="post">
			<?php foreach ($oauth_params as $k => $v): ?>
				<input type="hidden" name="<?php echo $k ?>" value="<?php echo $v ?>" />
			<?php endforeach; ?>
			<p>Do you authorize the app to do its thing?</p>
			<p>
				<input type="submit" name="accept" value="yes" />
				<input type="submit" name="accept" value="no" />
			</p>
		</form>
	</body>
</html>
