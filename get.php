<?php 
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: X-Requested-With, Content-Type, Origin, Cache-Control, Pragma, Authorization,
 Accept, Accept-Encoding");
function str_encryptaesgcm($plaintext, $password, $encoding = null) {
    if ($plaintext != null && $password != null) {
        $keysalt = openssl_random_pseudo_bytes(16);
        $key = hash_pbkdf2("sha512", $password, $keysalt, 20000, 32, true);
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length("aes-256-gcm"));
        $tag = "";
        $encryptedstring = openssl_encrypt($plaintext, "aes-256-gcm", $key, OPENSSL_RAW_DATA, $iv, $tag, "", 16);
        return $encoding == "hex" ? bin2hex($keysalt.$iv.$encryptedstring.$tag) : ($encoding == "base64" ? 
        base64_encode($keysalt.$iv.$encryptedstring.$tag) : $keysalt.$iv.$encryptedstring.$tag);
    }
}

function str_decryptaesgcm($encryptedstring, $password, $encoding = null) {
    if ($encryptedstring != null && $password != null) {
        $encryptedstring = $encoding == "hex" ? hex2bin($encryptedstring) : ($encoding == "base64" ? 
        base64_decode($encryptedstring) : $encryptedstring);
        $keysalt = substr($encryptedstring, 0, 16);
        $key = hash_pbkdf2("sha512", $password, $keysalt, 20000, 32, true);
        $ivlength = openssl_cipher_iv_length("aes-256-gcm");
        $iv = substr($encryptedstring, 16, $ivlength);
        $tag = substr($encryptedstring, -16);
        return openssl_decrypt(substr($encryptedstring, 16 + $ivlength, -16), "aes-256-gcm", $key, 
        OPENSSL_RAW_DATA, $iv, $tag);
    }
}

 $email = $_POST["email"];
 $Masterpassword = $_POST["password"];
 $app = $_POST["application"];
 $conn = mysqli_connect("localhost","root","",port:6969,database:"password_manager"); 
 $vault_key = hash("sha512", $email . $Masterpassword);
 $sql = "select password from passwords where vault_key='$vault_key' and application='$app'";
 $result = mysqli_query($conn,$sql);
 $row = mysqli_fetch_array($result);
 echo str_decryptaesgcm($row["password"],$vault_key);
?>

