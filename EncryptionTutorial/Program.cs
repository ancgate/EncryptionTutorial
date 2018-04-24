using System;
using System.Globalization;
using System.IO;
using System.Text;

namespace EncryptionTutorial
{
    class Program
    {
        static CryptographyManager.CryptographyManager cm = new CryptographyManager.CryptographyManager();
        public const string m_LocalKey = "yourlocalkey";
        public const string encryptionSalt = "yourlocalkey";

        static void Main(string[] args)
        {

            int i = 300000;



            System.Timers.Timer t = new System.Timers.Timer(4000);
            t.Elapsed += (s, e) =>
            {
                var accountId = i;
                var contactId = i;
                string token = EncryptingToken(accountId, contactId);
                DecryptingToken(token, encryptionSalt);
                i += 2;
            };
            t.Start();

            Console.ReadKey(); 
        }

        private static void DecryptingToken(string token, string encryptionSalt)
        {

            if (token != null)
            {
                Console.WriteLine("Token: " + token + Environment.NewLine);
                string replaceToken = token.Replace("-", "/").Replace("_", "+"); 
                    
                    

                int mod4 = replaceToken.Length % 4;
                if (mod4 > 0)
                {
                    
                    replaceToken += new string('=', 4 - mod4);
                }
                else
                {
                    replaceToken = token.Replace("-", "/").Replace("_", "+");
                }

                Console.WriteLine("Replace Token: " + replaceToken + Environment.NewLine);

                Console.WriteLine("Length of the Token: " + replaceToken.Length + Environment.NewLine);
                var uncovered = cm.Decrypt(replaceToken, encryptionSalt);
                Console.WriteLine("Decrypted Result: " + uncovered);


                var split = uncovered.Split(new[] { "Y-Y" }, StringSplitOptions.None);

                var accountId = Convert.ToInt32(split[0]);
                var contactId = Convert.ToInt32(split[1]);
                var dateRequest = DateTime.ParseExact(split[2], "yyyyMMdd HHmmss", CultureInfo.GetCultureInfo("fr-CA"));

                
                
                Console.WriteLine("AccountID: " + accountId);
                Console.WriteLine("ContactID: " + contactId);
                Console.WriteLine("DateRequest: " + dateRequest);
                Console.WriteLine(Environment.NewLine);
                Console.WriteLine(Environment.NewLine);


            }

        }

        private static string EncryptingToken (int accountId, int contactId) {


            var dateNow = DateTime.Now.ToString("yyyyMMdd HHmmss", CultureInfo.GetCultureInfo("fr-CA"));
            string rawToken = accountId.ToString() + "Y-Y" + contactId.ToString() + "Y-Y" + dateNow;

            Console.WriteLine("Raw Token: " + rawToken + Environment.NewLine);
            string token = cm.Encrypt(rawToken, m_LocalKey, encryptionSalt);
            string replaceToken = token.Replace("/", "-").Replace("+","_").Replace("=",String.Empty);

            Console.WriteLine("Encrypted Result: " + token + Environment.NewLine + "Length of Token: " + token.Length + Environment.NewLine);
            Console.WriteLine("Replace Encrypted Result: " + replaceToken + Environment.NewLine + "Length of Token: " + replaceToken.Length + Environment.NewLine);

            return replaceToken;

        }

    }
}