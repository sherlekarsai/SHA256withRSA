using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using SHA256withRSA;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp1
{
    /// <summary>
    /// Created by Sai Sherlekar 
    /// </summary>
    public class Program
    {
        //[STAThread]
        //public static void Main(string[] args)
        //{
        //    Dictionary<string, string> keys = RSAWrapper.RSAKeys.GenerateKeys(512);
        //    //Keys is Dictionary<string,string> of public private key - you can read private public key from file 
        //    string publicKey = keys["public"];//This data you can read from file
        //    string privateKey = File.ReadAllText("E:\\AESPrivateKeyPEM.pem");//This data you can read from file

        //    var encdata = RSAWrapper.RSAKeys.Encrypt("Sai Sherlekar", publicKey, true, false,false);
        //    //var encdata = "7A8D4DA2B20DD9E976EA37124B21018E6C1EBE51C0C794B56E16654A642689ECE233A378C714CD3471D17EA9F13E98163A90BCB76E8ADDE703F20589BC89730C";
        //    var cleardata = RSAWrapper.RSAKeys.Decrypt(encdata, privateKey, true, false,false);

        //    var signData = RSAWrapper.RSAKeys.SignDataSHA256("Sai Sherlekar", privateKey, false);
        //    var result = RSAWrapper.RSAKeys.VerifyDataSHA256(publicKey, "Sai Sherlekar", signData, false);


        //}

        [STAThread]
        public static void Main(string[] args)
        {
            Dictionary<string, string> keys = RSAWrapper.RSAKeys.GenerateKeys(512);
            //Keys is Dictionary<string,string> of public private key - you can read private public key from file 
            string publicKey = keys["public"];//This data you can read from file
            string privateKey = keys["private"];//This data you can read from file

            var encdata = RSAWrapper.RSAKeys.Encrypt("Sai Sherlekar", publicKey, true, false, false);
            var cleardata = RSAWrapper.RSAKeys.Decrypt(encdata, privateKey, true, false, false);

            var signData = RSAWrapper.RSAKeys.SignDataSHA256("Sai Sherlekar", privateKey, false);
            var result = RSAWrapper.RSAKeys.VerifyDataSHA256(publicKey, "Sai Sherlekar", signData, false);


        }
        public static void SignAndVerifyMain()
        {
            var sha256withrsa = new SignAndVerify();
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
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