public class AES
{
	private byte[] key;
	public AES(string SecretKey)
	{
		string k = Pass2Key(SecretKey);
		Console.WriteLine("Key:       " + k);
		key = Encoding.UTF8.GetBytes(k);
	}
	
	public string Encrypt(string plainText)
	{
		if (plainText == null || plainText.Length <= 0)
		{
			throw new ArgumentNullException("plainText");
		}
		
		if (key == null || key.Length <= 0)
		{
			throw new ArgumentNullException("key");
		}
		
		byte[] encrypted;
		using (var rijAlg = new RijndaelManaged())
		{
			rijAlg.BlockSize = 256;
			rijAlg.Key = key;
			rijAlg.Mode = CipherMode.CBC;
			rijAlg.Padding = PaddingMode.Zeros;
			rijAlg.IV = key;
			ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);
			using (var msEncrypt = new MemoryStream())
			{
				using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
				{
					using (var swEncrypt = new StreamWriter(csEncrypt))
					{
						swEncrypt.Write(plainText);
					}
					
					encrypted = msEncrypt.ToArray();
				}
			}
		}
		
		return System.Convert.ToBase64String(encrypted);
	}
	
	public string Decrypt(string encrypted)
	{
		byte[] cipherText = System.Convert.FromBase64String(encrypted);
		if (cipherText == null || cipherText.Length <= 0)
		{
			throw new ArgumentNullException("cipherText");
		}
		
		if (key == null || key.Length <= 0)
		{
			throw new ArgumentNullException("key");
		}
		
		string plaintext;
		using (var rijAlg = new RijndaelManaged())
		{
			rijAlg.BlockSize = 256;
			rijAlg.Key = key;
			rijAlg.Mode = CipherMode.CBC;
			rijAlg.Padding = PaddingMode.Zeros;
			rijAlg.IV = key;
			ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);
			using (var msDecrypt = new MemoryStream(cipherText))
			{
				using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
				{
					using (var srDecrypt = new StreamReader(csDecrypt))
					{
						plaintext = srDecrypt.ReadToEnd();
					}
				}
			}
		}
		
		return plaintext;
	}
	
	public string Pass2Key(string SecretKey)
	{
		return System.Convert.ToBase64String((new SHA512CryptoServiceProvider()).ComputeHash(Encoding.UTF8.GetBytes(SecretKey))).Substring(0, 32);
	}
}
