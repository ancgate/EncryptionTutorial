using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptographyManager
{
    public class CryptographyManager
    {
        public CryptographyManager()
        {

        }

        public enum HashName
        {
            SHA1 = 1,
            MD5 = 2,
            SHA256 = 4,
            SHA384 = 8,
            SHA512 = 16
        }

        #region Encryption methods
        public string Encrypt(string value)
        {
            return Encrypt(value, string.Empty);
        }

        public string Encrypt(string value, string key)
        {
            return Encrypt(value, key, string.Empty);
        }

        public string Encrypt(string value, string key, string iv)
        {
            string encryptValue = string.Empty;

            if (!string.IsNullOrEmpty(value))
            {
                try
                {
                    var encryptor = new AesManaged();
                    
                    var saltBytes = new UTF8Encoding().GetBytes(key);
                    var rfc = new Rfc2898DeriveBytes(key, saltBytes);

                    encryptor.Key = rfc.GetBytes(16);
                    encryptor.IV = rfc.GetBytes(16);
                    encryptor.BlockSize = 128;

                    using (var encryptionStream = new MemoryStream())
                    {
                        using (var encrypt = new CryptoStream(encryptionStream, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            var utfD1 = UTF8Encoding.UTF8.GetBytes(value);
                            encrypt.Write(utfD1, 0, utfD1.Length);
                            encrypt.FlushFinalBlock();
                            encrypt.Close();

                            encryptValue = Convert.ToBase64String(encryptionStream.ToArray());
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error happened: " + ex.Message.ToString());
                }
            }

            return encryptValue;
        }
        #endregion

        #region Decryption methods
        public string Decrypt(string value)
        {
            return Decrypt(value, string.Empty); 
        }

        public string Decrypt(string value, string key)
        {
            return Decrypt(value, key, string.Empty); 
        }

        public string Decrypt(string value, string key, string iv)
        {
            string decrptValue = string.Empty;
            if (!string.IsNullOrEmpty(value))
            {
                value = value.Replace(" ", "+");
                try
                {

                    var decryptor = new AesManaged();
                    
                    byte[] encryptedData = Convert.FromBase64String(value);

                    byte[] saltBytes = new UTF8Encoding().GetBytes(key);
                    var rfc = new Rfc2898DeriveBytes(key, saltBytes);

                    decryptor.Key = rfc.GetBytes(16);
                    decryptor.IV = rfc.GetBytes(16);
                    decryptor.BlockSize = 128;

                    using (var decryptionStream = new MemoryStream())
                    {
                        using (var decrypt = new CryptoStream(decryptionStream, decryptor.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            try
                            {
                                decrypt.Write(encryptedData, 0, encryptedData.Length);
                                decrypt.Flush();
                                decrypt.Close();
                            }
                            catch (Exception innerEx)
                            {
                                Console.WriteLine("Error while decrypting: " + innerEx.Message.ToString());
                            }
                            var decryptedData = decryptionStream.ToArray();
                            decrptValue = UTF8Encoding.UTF8.GetString(decryptedData, 0, decryptedData.Length);
                        }
                    }
                }
                catch (Exception ex)
                {
                    //TODO: write log 
                    Console.WriteLine("Error occurred: " + ex.Message.ToString());
                }
            }
            return decrptValue;
        }
        #endregion
    }
}