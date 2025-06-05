<?php 

// phpinfo();

$curl = curl_init();

curl_setopt_array($curl, array(
    CURLOPT_URL => "https://BASE_URL_FOR_CCP/AIMWebService/api/Accounts?AppID=TestApplication&safe=SAFE-TestApplication;Object=TestApplication-mysqluser",
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSLCERT => "/var/www/cert/client.pem",
    CURLOPT_SSLKEY => "/var/www/cert/cert.key",
    CURLOPT_HTTPHEADER => array(
        "cache-control: no-cache",
        "content-type: application/json"
    )
));

$response = curl_exec($curl);
$response_obj = json_decode($response, true);
$err = curl_error($curl);

curl_close($curl);

echo '<DIV ALIGN="CENTER"><img src="../images/cyberark-image.png" width="320" height="180"><BR/>';


if ($err) {
    echo "cURL Error #:" . $err;
} else {
	if (array_key_exists("database", $response_obj)) {
		$database = $response_obj["database"];
		$username = $response_obj["username"];
		$password = $response_obj["Content"];

		$connection = mysqli_connect("db", $username, $password, $database);
		$statement = mysqli_query($connection,'SELECT message FROM demo');

		$row = mysqli_fetch_assoc($statement);
		echo $row["message"]."</DIV><BR/>";

		mysqli_close($connection);
	} else {
		print_r($response_obj);
	}

}


?>
