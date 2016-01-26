<?php
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
