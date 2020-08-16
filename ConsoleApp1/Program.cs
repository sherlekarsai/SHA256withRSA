using SHA256withRSA;
using System;

namespace ConsoleApp1
{
    /// <summary>
    /// Created by Sai Sherlekar 
    /// </summary>
    public class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            var sha256withrsa = new SignAndVerify();

            //Use when you want to generaste key pair
            var keyPair = sha256withrsa.GenerateRandomKeyPair(SignAndVerify.RSASize.Size2048);
            //sha256withrsa.SaveKeys(keyPair, @"E:\sai work\rsa\");

            var privatekey = sha256withrsa.getPrivateKeyFromPemFile(@"E:\sai work\rsa\prirsa.txt");                
            var publickeyRSA = sha256withrsa.getPublicKeyFromPemFile(@"E:\sai work\rsa\pubrsa.txt");
            // content we like to sign
            var textToSign = "sai sherlekar Dombivali east";

            // generates the signature by using the PRIVATE key
            var signature = sha256withrsa.GenerateSignatureHex(textToSign, (Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)privatekey.Private);

            // validates the signature by using the PUBLIC key
            var isSignatureValid = sha256withrsa.VerifySignatureHex(textToSign, signature, publickeyRSA);
            
        }
        
    }

}