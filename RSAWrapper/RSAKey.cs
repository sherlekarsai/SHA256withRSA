using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
/// <summary>
/// created and updated by Sai Sherlekar 
/// </summary>
namespace RSAWrapper
{
    public static class RSAKeys
    {
        /// <summary>
        /// Import OpenSSH PEM private key string into MS RSACryptoServiceProvider
        /// </summary>
        /// <param name="pem"></param>
        /// <returns></returns>
        private static RSACryptoServiceProvider ImportPrivateKey(string pem, bool IsXml)
        {
            RSAParameters rsaParams;
            if (!IsXml)
            {
                PemReader pr = new PemReader(new StringReader(pem));
                AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
                rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);
            }else
            {
                var sr = new StringReader(pem);
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                rsaParams = (RSAParameters)xs.Deserialize(sr);
            }
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
        }

        /// <summary>
        /// Import OpenSSH PEM public key string into MS RSACryptoServiceProvider
        /// </summary>
        /// <param name="pem"></param>
        /// <returns></returns>
        private static RSACryptoServiceProvider ImportPublicKey(string pem, bool IsXml)
        {
            RSAParameters rsaParams;
            if (!IsXml)
            {
                PemReader pr = new PemReader(new StringReader(pem));
                AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();
                rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKey);
            }
            else
            {
                var sr = new StringReader(pem);
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                rsaParams = (RSAParameters)xs.Deserialize(sr);
            }

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
        }

        /// <summary>
        /// Export private (including public) key from MS RSACryptoServiceProvider into OpenSSH PEM string
        /// slightly modified from https://stackoverflow.com/a/23739932/2860309
        /// </summary>
        /// <param name="csp"></param>
        /// <returns></returns>
        private static string ExportPrivateKey(RSACryptoServiceProvider csp)
        {
            StringWriter outputStream = new StringWriter();
            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
            var parameters = csp.ExportParameters(true);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                    EncodeIntegerBigEndian(innerWriter, parameters.D);
                    EncodeIntegerBigEndian(innerWriter, parameters.P);
                    EncodeIntegerBigEndian(innerWriter, parameters.Q);
                    EncodeIntegerBigEndian(innerWriter, parameters.DP);
                    EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                    EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                // WriteLine terminates with \r\n, we want only \n
                outputStream.Write("-----BEGIN RSA PRIVATE KEY-----\n");
                // Output as Base64 with lines chopped at 64 characters
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                    outputStream.Write("\n");
                }
                outputStream.Write("-----END RSA PRIVATE KEY-----");
            }

            return outputStream.ToString();
        }

        /// <summary>
        /// Export public key from MS RSACryptoServiceProvider into OpenSSH PEM string
        /// slightly modified from https://stackoverflow.com/a/28407693
        /// </summary>
        /// <param name="csp"></param>
        /// <returns></returns>
        private static string ExportPublicKey(RSACryptoServiceProvider csp)
        {
            StringWriter outputStream = new StringWriter();
            var parameters = csp.ExportParameters(false);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, parameters.Modulus); // Modulus
                            EncodeIntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                // WriteLine terminates with \r\n, we want only \n
                outputStream.Write("-----BEGIN PUBLIC KEY-----\n");
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                    outputStream.Write("\n");
                }
                outputStream.Write("-----END PUBLIC KEY-----");
            }

            return outputStream.ToString();
        }

        /// <summary>
        /// https://stackoverflow.com/a/23739932/2860309
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="length"></param>
        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        /// <summary>
        /// https://stackoverflow.com/a/23739932/2860309
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="value"></param>
        /// <param name="forceUnsigned"></param>
        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }
        public static Dictionary<string, string> GenerateKeys(int KeySize)
        {
            RSACryptoServiceProvider initialProvider = new RSACryptoServiceProvider(KeySize);
            String privateKey = RSAKeys.ExportPrivateKey(initialProvider);
            String publicKey = RSAKeys.ExportPublicKey(initialProvider);

            Dictionary<string, string> ObjKeys = new Dictionary<string, string>();
            ObjKeys.Add("private", privateKey);
            ObjKeys.Add("public", publicKey);
            return ObjKeys;
        }
        public static RSACryptoServiceProvider ReadPrivateKey(string key, bool IsXML)
        {
            RSACryptoServiceProvider importedProvider = RSAKeys.ImportPrivateKey(key,IsXML);
            return importedProvider;
        }
        private static RSACryptoServiceProvider ReadPublicKey(string key, bool IsXML)
        {
            RSACryptoServiceProvider importedProvider = RSAKeys.ImportPublicKey(key, IsXML);
            return importedProvider;
        }
        /// <summary>
        /// RSA Encryption 
        /// </summary>
        /// <param name="msg">clear data</param>
        /// <param name="key">Clear key</param>
        /// <param name="OAEP">OAEP apdding</param>
        /// <param name="IsXML">Key is XML or plain text</param>
        /// <param name="IsHex">Hex = false, base64 true</param>
        /// <returns></returns>
        public static string Encrypt(string msg, string key, bool OAEP, bool IsXML, bool IsHex)
        {
            RSACryptoServiceProvider ObjRSA = ReadPublicKey(key,IsXML);
            var strEncdata = ObjRSA.Encrypt(Encoding.UTF8.GetBytes(msg), OAEP);
            if(IsHex)
            return Convert.ToBase64String(strEncdata);
            else
            return Convert.ToBase64String(strEncdata);

        }
        /// <summary>
        /// RSA Decryption 
        /// </summary>
        /// <param name="msg">Encrypted data</param>
        /// <param name="key">Clear key</param>
        /// <param name="OAEP">OAEP apdding</param>
        /// <param name="IsXML">Key is XML or plain text</param>
        /// <param name="IsHex">Hex = false, base64 true</param>
        /// <returns></returns>
        public static string Decrypt(string msg, string key, bool OAEP, bool IsXML, bool IsHex)
        {
            RSACryptoServiceProvider ObjRSA = ReadPrivateKey(key, IsXML);
            byte[] msgbyte;
            if (IsHex)
                msgbyte = Convert.FromBase64String(msg);
            else
                msgbyte = StringToByteArray(msg);
            var strdata = ObjRSA.Decrypt(msgbyte, OAEP);
            return Encoding.UTF8.GetString(strdata);
        }
        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
        /// <summary>
        /// Sign data using RSA 256 SHA
        /// </summary>
        /// <param name="msg">Clear data</param>
        /// <param name="key">Clear private key</param>
        /// <param name="IsXML">Key is XML or plain text</param>
        /// <returns></returns>
        public static string SignDataSHA256(string msg, string key, bool IsXML)
        {
            RSACryptoServiceProvider ObjRSA = ReadPrivateKey(key, IsXML);
            var strEncdata = ObjRSA.SignData(Encoding.UTF8.GetBytes(msg), new SHA256CryptoServiceProvider());
            return Convert.ToBase64String(strEncdata);
        }
        /// <summary>
        /// verify data using RSA 256 SHA
        /// </summary>
        /// <param name="key">Clear public key</param>
        /// <param name="msg">Clear data</param>
        /// <param name="signature">Signed data</param>
        /// <param name="IsXML">public key is XML or plain text</param>
        /// <returns></returns>
        public static bool VerifyDataSHA256(string key, string msg, string signature, bool IsXML)
        {
            RSACryptoServiceProvider ObjRSA = ReadPublicKey(key, IsXML);
            bool res = ObjRSA.VerifyData(Encoding.UTF8.GetBytes(msg), new SHA256CryptoServiceProvider(), Convert.FromBase64String(signature));
            return res;
        }
     
    }
}