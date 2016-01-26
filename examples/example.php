<?php
/***********************************************************/
/* Declare a new instance of AES with the secret key       */
/***********************************************************/
$cipher=new AES("TEST");               //                  */
/***********************************************************/
/* To encrypt a message, call the Encrypt() function from  */
/* the instance with the desired message as the parameter. */
/***********************************************************/
$encrypted=$cipher->Encrypt("Worked!");//                  */
/***********************************************************/
/* To decrypt a message, call the Decrypt() function from  */
/* the instance with the desired message as the parameter. */
/***********************************************************/
$decrypted=$cipher->Decrypt($encrypted);
echo "Key:       ".$cipher->key."\n";
echo "Encrypted: ".$encrypted."\n";
echo "Decrypted: ".$decrypted."\n\n";
echo "The whole source can be found on https://github.com/halitalf/cross-aes\n";

class AES
{
	var $key = "";
	function __construct($SecretKey)
	{
		$this->key=$this->Pass2Key($SecretKey);
	}
	function Pass2Key($SecretKey)
	{
		return substr(base64_encode(pack('H*',hash("sha512", $SecretKey))), 0, 32);
	}
	function Encrypt($string = "")
	{
		return rtrim(base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $this->key, $string, MCRYPT_MODE_CBC, $this->key)));
	}
	function Decrypt($string = "")
	{
		return rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $this->key, base64_decode($string), MCRYPT_MODE_CBC, $this->key));
	}
}
?>
