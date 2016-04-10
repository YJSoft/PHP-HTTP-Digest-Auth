<?php
require dirname(__FILE__) . '/HTTP_Digest.php';
use YJSoft\HTTP\HTTP_Digest;

$users = array('user'=>'password');
$Auth = new HTTP_Digest($users);

if(!$Auth->is_auth($_SERVER['PHP_AUTH_DIGEST'])) {
	$Auth->sendAuthHeader('PHP Digest Example');
	echo '<meta charset="utf-8">';
	echo '401 Unauthorized.' . " <br />\n";
	exit;
}

echo 'Authorized.';