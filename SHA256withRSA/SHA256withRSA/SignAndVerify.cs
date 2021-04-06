using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SHA256withRSA
{
    /// <summary>
    /// Created by Sai Sherlekar 
    /// </summary>
    public class SignAndVerify
    {
       public enum RSASize
        {
            Size512 = 512,
            Size1024 = 1024,
            Size2048 = 2048
        }

        /// <summary>
        /// Generate random keypair - public and private key
        /// </summary>
        /// <returns>key pair</returns>
        public AsymmetricCipherKeyPair GenerateRandomKeyPair(RSASize size)
        {
            var rsaKeyPairGen = new RsaKeyPairGenerator();
            rsaKeyPairGen.Init(new KeyGenerationParameters(new SecureRandom(), Convert.ToInt32(size)));
            return rsaKeyPairGen.GenerateKeyPair(); ;
        }
        /// <summary>
        /// Verify RSA signature 
        /// </summary>
        /// <param name="sourceData">Data used to generate signature</param>
        /// <param name="signature">signature in hex - Internally it converts to yte array</param>
        /// <param name="publicKey">public key</param>
        /// <returns>bool = true means success</returns>
        public bool VerifySignatureHex(string sourceData, string signature, RsaKeyParameters publicKey)
        {
            byte[] tmpSource = Encoding.ASCII.GetBytes(sourceData);

            ISigner signClientSide = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id);
            signClientSide.Init(false, publicKey);
            signClientSide.BlockUpdate(tmpSource, 0, tmpSource.Length);

            return signClientSide.VerifySignature(Hex.Decode(signature));
        }
       /// <summary>
       /// Verify RSA signature 
       /// </summary>
       /// <param name="sourceData">Data used to generate signature</param>
       /// <param name="signature">signature</param>
       /// <param name="publicKey">public key</param>
       /// <returns>bool = true means success</returns>
        public bool VerifySignature(string sourceData, byte[] signature, RsaKeyParameters publicKey)
        {
            byte[] tmpSource = Encoding.ASCII.GetBytes(sourceData);

            ISigner signClientSide = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id);
            signClientSide.Init(false, publicKey);
            signClientSide.BlockUpdate(tmpSource, 0, tmpSource.Length);

            return signClientSide.VerifySignature(signature);
        }
        /// <summary>
        /// Generate signature and return Hex string
        /// </summary>
        /// <param name="sourceData">Data which you wanted to sign</param>
        /// <param name="privateKey">Private key</param>
        /// <returns>Hex string</returns>
        public string GenerateSignatureHex(string sourceData, RsaKeyParameters privateKey)
        {
            byte[] tmpSource = Encoding.ASCII.GetBytes(sourceData);
            ISigner sign = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id);
            sign.Init(true, privateKey);
            sign.BlockUpdate(tmpSource, 0, tmpSource.Length);
            return Hex.ToHexString(sign.GenerateSignature());
        }
        /// <summary>
        /// Generate signature and return bytes
        /// </summary>
        /// <param name="sourceData">Data which you wanted to sign</param>
        /// <param name="privateKey">Private key</param>
        /// <returns>byte array</returns>
        public byte[] GenerateSignature(string sourceData, RsaKeyParameters privateKey)
        {
            byte[] tmpSource = Encoding.ASCII.GetBytes(sourceData);

            ISigner sign = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id);
            sign.Init(true, privateKey);
            sign.BlockUpdate(tmpSource, 0, tmpSource.Length);
            return sign.GenerateSignature();
        }
        /// <summary>
        /// Save public and private keys
        /// </summary>
        /// <param name="keyPair">Generated random key pair</param>
        /// <param name="path">Pass path without filename -eg. c:\sai\</param>
        public void SaveKeys(AsymmetricCipherKeyPair keyPair, string path)
        {
            using (TextWriter textWriter1 = new StringWriter())
            {
                var pemWriter1 = new PemWriter(textWriter1);
                pemWriter1.WriteObject(keyPair.Private);
                pemWriter1.Writer.Flush();

                string privateKey = textWriter1.ToString();
                Console.WriteLine(privateKey);
                File.AppendAllText(path + "prirsa.txt", privateKey);
            }

            using (TextWriter textWriter2 = new StringWriter())
            {
                var pemWriter2 = new PemWriter(textWriter2);
                pemWriter2.WriteObject(keyPair.Public);
                pemWriter2.Writer.Flush();
                string publicKey = textWriter2.ToString();
                Console.WriteLine(publicKey);
                File.AppendAllText(path + "pubrsa.txt", publicKey);
            }
        }

        /// <summary>
        /// Get private key object by RSA private key file data
        /// </summary>
        /// <param name="pemFilename">Pass fileName including path</param>
        /// <returns></returns>
        public AsymmetricCipherKeyPair getPrivateKeyFromPemFile(string pemFilename)
        {

            try
            {
                StreamReader fileStream = System.IO.File.OpenText(pemFilename);
                PemReader pemReader = new PemReader(fileStream);
                var ss = pemReader.ReadObject();
                //AsymmetricKeyParameter keyParameter = (AsymmetricKeyParameter)pemReader.ReadObject();

                return (AsymmetricCipherKeyPair)ss;

            }

            catch (Exception ex)

            {

                return null;

            }

        }
        /// <summary>
        /// Get public key object by RSA public key file data
        /// </summary>
        /// <param name="pemFilename">Pass fileName including path</param>
        /// <returns></returns>
        public Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters getPublicKeyFromPemFile(string pemFilename)
        {

            StreamReader fileStream = System.IO.File.OpenText(pemFilename);

            //PemReader pemReader = new PemReader(fileStream);
            PemReader pemReader = new PemReader(fileStream);
            //var ss = pemReader.ReadObject();
            Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters ss = (Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)pemReader.ReadObject();

            return ss;

        }

        public byte[] DecryptionRSA(byte[] Data, RSAParameters RSAKey, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    RSA.ImportParameters(RSAKey);
                    decryptedData = RSA.Decrypt(Data, DoOAEPPadding);
                }
                return decryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());
                return null;
            }
        }
        public byte[] EncryptionRSA(byte[] Data, RSAParameters RSAKey, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    RSA.ImportParameters(RSAKey);
                    encryptedData = RSA.Encrypt(Data, DoOAEPPadding);
                }
                return encryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }
    }
}