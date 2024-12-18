using Org.BouncyCastle.Crypto.Modes;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace VIKSVASignHelper
{
    public class VIKSVASignHelper
    {
        public string SignDigest(string digest, string thumbprint)
        {
            byte[] data = Convert.FromBase64String(digest);

            // Get the certificate from store for the current user.
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            // Find the certificate with the specified thumbprint.
            X509Certificate2Collection certCollection = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
            X509Certificate2 cert  = new X509Certificate2(certCollection.Export(X509ContentType.Pfx));
            
            store.Close();
            RSA privateKey = cert.GetRSAPrivateKey();
            return (Convert.ToBase64String(privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)));
        }
        public string UnSignData(string b64Encrypted, string certbase64, string encryptedKey)
        {
            // Get the certificate from store for the current user.
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            //load certificate from base64
            X509Certificate2 encryptedCert = new X509Certificate2(Convert.FromBase64String(certbase64));

            // Find the certificate with the specified thumbprint.
            X509Certificate2Collection certCollection = store.Certificates.Find(X509FindType.FindByThumbprint, encryptedCert.Thumbprint, false);
            X509Certificate2 cert = new X509Certificate2(certCollection.Export(X509ContentType.Pfx));
            store.Close();

            RSA privateKey = cert.GetRSAPrivateKey();
            byte[] decryptedKey = privateKey.Decrypt(Convert.FromBase64String(encryptedKey), RSAEncryptionPadding.Pkcs1);
            byte[] encryptedWithIV = Convert.FromBase64String(b64Encrypted);

            byte[] encrypted = new byte[encryptedWithIV.Length - 12];
            byte[] iV = new byte[12];

            Array.Copy(encryptedWithIV, iV, 12);
            Array.Copy(encryptedWithIV, 12, encrypted, 0, encrypted.Length);

            IAeadBlockCipher cipher = new GcmBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine());
            cipher.Init(false, new Org.BouncyCastle.Crypto.Parameters.AeadParameters(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(decryptedKey), 128, iV));

            byte[] decrypted = new byte[cipher.GetOutputSize(encrypted.Length)];
            int decryptBytesCount = cipher.ProcessBytes(encrypted, 0, encrypted.Length, decrypted, 0);
            decryptBytesCount += cipher.DoFinal(decrypted, decryptBytesCount);

            Array.Copy(decrypted, decrypted, decryptBytesCount);

            return (Convert.ToBase64String(decrypted));
        }
    }
}
