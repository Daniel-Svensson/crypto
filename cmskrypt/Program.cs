using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography;

namespace cmskrypt
{
    class Program
    {
        public static class Oids
        {
            // 2.16.840.1.101.3.4.1.42 (AES-256-CBC) default since .net 4.8
            public static readonly Oid Aes256CBC = new Oid("2.16.840.1.101.3.4.1.42");
        }
        // https://adamtheautomator.com/new-selfsignedcertificate/#Creating_A_Document_Encryption_Certificate
        // https://stackoverflow.com/questions/43387548/envelopedcms-decryption-does-not-work-with-azure-key-vault
        static void Main(string[] args)
        {

            var encryptCert = new X509Certificate2("Encrypt.pfx", "1234");
            var signCert = new X509Certificate2("Sign.pfx", "1234");

            var file = File.ReadAllBytes("Input.txt");

            var encoded = EncryptAndSign(file, encryptCert, signCert);

            var decoded = DecryptAndVerify(encoded, encryptCert, signCert);
            File.WriteAllBytes("verified.txt", decoded);
        }

        private static byte[] DecryptAndVerify(byte[] encoded, X509Certificate2 encryptCert, X509Certificate2 signCert)
        {
            var envelope = new EnvelopedCms();
            envelope.Decode(encoded);

            var decryptStore = new X509Certificate2Collection(encryptCert);
            envelope.Decrypt(decryptStore);

            var signerStore = new X509Certificate2Collection(signCert);

            var signedCms = new SignedCms();
            signedCms.Decode(envelope.ContentInfo.Content);
            signedCms.CheckSignature(signerStore, verifySignatureOnly: true);

            // signedCms.SignerInfos[0].Certificate.Thumbprint == signCert.Thumbprint
            //            signerStore.Find(X509FindType.FindByThumbprint, signedCms.SignerInfos)

            return signedCms.ContentInfo.Content;

        }

        private static byte[] EncryptAndSign(byte[] file, X509Certificate2 encryptCert, X509Certificate2 signCert)
        {
            var signedCms = new SignedCms(new ContentInfo(file));
            var signer = new CmsSigner(signCert);
           // signer.SignedAttributes.Add(new AsnEncodedData()

            // Sign the message.
            signedCms.ComputeSignature(signer);

            // Encode the message.
            byte[] signedContent = signedCms.Encode();
            File.WriteAllBytes("signed.p7s", signedContent);

            //Oid encryptAlgoOid = new Oid("2.16.840.1.101.3.4.1.46"); // AES-256-GCM
            var envelope = new EnvelopedCms(new ContentInfo(signedContent));
            var recipient = new CmsRecipient(encryptCert/*, RSAEncryptionPadding.OaepSHA256*/);
            envelope.Encrypt(recipient);

            var output = envelope.Encode();
            File.WriteAllBytes("encrypted.p7m", output);
            return output;
        }
    }
}
