Imports System
Imports System.Text.Encoding
Imports System.Security.Cryptography
Imports System.IO

Public Class AES
    Private key As Byte()

    Public Sub New(SecretKey As String)
        Dim k as String = Pass2Key(SecretKey)
        Console.WriteLine("Key:       " & k)
        key = UTF8.GetBytes(k)
    End Sub

    Public Function Encrypt(plainText As String) As String
        If plainText Is Nothing OrElse plainText.Length <= 0
            Throw New ArgumentNullException("plainText")
        End If

        If key Is Nothing OrElse key.Length <= 0
            Throw New ArgumentNullException("key")
        End If

        Dim encrypted As Byte()
        Using rijAlg = New RijndaelManaged()
            rijAlg.BlockSize = 256
            rijAlg.Key = key
            rijAlg.Mode = CipherMode.CBC
            rijAlg.Padding = PaddingMode.Zeros
            rijAlg.IV = key
            Dim encryptor As ICryptoTransform = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV)
            Using msEncrypt = New MemoryStream()
                Using csEncrypt = New CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write)
                    Using swEncrypt = New StreamWriter(csEncrypt)
                        swEncrypt.Write(plainText)
                    End Using

                    encrypted = msEncrypt.ToArray()
                End Using
            End Using
        End Using

        Return System.Convert.ToBase64String(encrypted)
    End Function

    Public Function Decrypt(encrypted As String) As String
        Dim cipherText As Byte() = System.Convert.FromBase64String(encrypted)
        If cipherText Is Nothing OrElse cipherText.Length <= 0
            Throw New ArgumentNullException("cipherText")
        End If

        If key Is Nothing OrElse key.Length <= 0
            Throw New ArgumentNullException("key")
        End If

        Dim plaintext As String
        Using rijAlg = New RijndaelManaged()
            rijAlg.BlockSize = 256
            rijAlg.Key = key
            rijAlg.Mode = CipherMode.CBC
            rijAlg.Padding = PaddingMode.Zeros
            rijAlg.IV = key
            Dim decryptor As ICryptoTransform = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV)
            Using msDecrypt = New MemoryStream(cipherText)
                Using csDecrypt = New CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read)
                    Using srDecrypt = New StreamReader(csDecrypt)
                        plaintext = srDecrypt.ReadToEnd()
                    End Using
                End Using
            End Using
        End Using

        Return plaintext
    End Function

    Public function Pass2Key(SecretKey as string) as string
        Return System.Convert.ToBase64String((New SHA512CryptoServiceProvider()).ComputeHash(UTF8.GetBytes(SecretKey))).Substring(0, 32)
    end function
End Class
