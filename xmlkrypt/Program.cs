using System;
using System.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using System.IO;
using System.Linq;

namespace xmlkrypt
{

    class Program
    {
        private const string AzureKey = "test-rsa";

        static void Main(string[] args)
        {
            // Create an XmlDocument object.
            XmlDocument xmlDoc = new XmlDocument();

            // Load an XML file into the XmlDocument object.
            try
            {
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load("test.xml");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            var azureCredentials = new VisualStudioCredential(new VisualStudioCredentialOptions()
            {
                TenantId = "cd793db9-23f9-46d0-b702-d1127a3c018b"
            });
            var client = new KeyClient(vaultUri: new Uri("https://crm-finance-internal.vault.azure.net/"), azureCredentials);

            RSA rsaKey = RSA.Create(2048);
            if (File.Exists("rsa.xml"))
            {
                rsaKey = RSA.Create();
                rsaKey.FromXmlString(File.ReadAllText("rsa.xml"));
            }
            else
            {
                File.WriteAllText("rsa.xml", rsaKey.ToXmlString(true));
                client.ImportKey(AzureKey, new JsonWebKey(rsaKey, includePrivateParameters: true));
            }

            //var credential = new DefaultAzureCredential();
            try
            {
                var azureKey = client.GetKey(AzureKey).Value;
                var cryptoClient = new CryptographyClient(azureKey.Id, azureCredentials);
                // Encrypt the "creditcard" element.
                Encrypt(cryptoClient, xmlDoc, "creditcard", "EncryptedElement1", "rsaKey");

                // Save the XML document.
                xmlDoc.Save("encrypted.xml");

                // Display the encrypted XML to the console.
                Console.WriteLine("Encrypted XML:");
                Console.WriteLine();
                Console.WriteLine(xmlDoc.OuterXml);
                Decrypt(cryptoClient, xmlDoc, rsaKey, "rsaKey", "EncryptedElement1");
                xmlDoc.Save("roundtripped.xml");
                // Display the encrypted XML to the console.
                Console.WriteLine();
                Console.WriteLine("Decrypted XML:");
                Console.WriteLine();
                Console.WriteLine(xmlDoc.OuterXml);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                // Clear the RSA key.
                rsaKey.Clear();
            }

            Console.ReadLine();
        }

        public static void Encrypt(CryptographyClient cryptographyClient, XmlDocument Doc, string ElementToEncrypt, string EncryptionElementID, string XmlKeyName)
        {
            // Check the arguments.
            if (Doc == null)
                throw new ArgumentNullException(nameof(Doc));
            if (ElementToEncrypt == null)
                throw new ArgumentNullException(nameof(ElementToEncrypt));
            if (EncryptionElementID == null)
                throw new ArgumentNullException(nameof(EncryptionElementID));
            if (XmlKeyName == null)
                throw new ArgumentNullException(nameof(XmlKeyName));


            ////////////////////////////////////////////////
            // Find the specified element in the XmlDocument
            // object and create a new XmlElement object.
            ////////////////////////////////////////////////
            XmlElement elementToEncrypt = Doc.GetElementsByTagName(ElementToEncrypt)[0] as XmlElement;

            // Throw an XmlException if the element was not found.
            if (elementToEncrypt == null)
            {
                throw new XmlException("The specified element was not found");
            }

            // Create an AES key.
            Aes sessionKey = Aes.Create();
            sessionKey.KeySize = 256;

            try
            {
                //////////////////////////////////////////////////
                // Create a new instance of the EncryptedXml class
                // and use it to encrypt the XmlElement with the
                // a new random symmetric key.
                //////////////////////////////////////////////////

                EncryptedXml eXml = new EncryptedXml();

                byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, sessionKey, false);

                ////////////////////////////////////////////////
                // Construct an EncryptedData object and populate
                // it with the desired encryption information.
                ////////////////////////////////////////////////

                EncryptedData edElement = new EncryptedData();
                edElement.Type = EncryptedXml.XmlEncElementUrl;
                edElement.Id = EncryptionElementID;
                // Create an EncryptionMethod element so that the
                // receiver knows which algorithm to use for decryption.

                edElement.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);
                
                // Encrypt the session key and add it to an EncryptedKey element.
                var wrapResult = cryptographyClient.WrapKey(KeyWrapAlgorithm.RsaOaep, sessionKey.Key);

                EncryptedKey ek = new EncryptedKey
                {
                    //CipherData = EncryptedXml.EncryptKey(sessionKey.Key, Alg, useOAEP: true);
                    CipherData = new CipherData(wrapResult.EncryptedKey),
                    EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSAOAEPUrl)
                };

                // Create a new DataReference element
                // for the KeyInfo element.  This optional
                // element specifies which EncryptedData
                // uses this key.  An XML document can have
                // multiple EncryptedData elements that use
                // different keys.
                DataReference dRef = new DataReference();

                // Specify the EncryptedData URI.
                dRef.Uri = "#" + EncryptionElementID;

                // Add the DataReference to the EncryptedKey.
                ek.AddReference(dRef);
                // Add the encrypted key to the
                // EncryptedData object.

                // Add the KeyInfoName element to the
                // EncryptedKey object.
                ek.KeyInfo.AddClause(new KeyInfoName(XmlKeyName));
                
                edElement.KeyInfo.AddClause(new KeyInfoEncryptedKey(ek));
                // Set the KeyInfo element to specify the
                // name of the RSA key.

                // Add the encrypted element data to the
                // EncryptedData object.
                edElement.CipherData.CipherValue = encryptedElement;
                ////////////////////////////////////////////////////
                // Replace the element from the original XmlDocument
                // object with the EncryptedData element.
                ////////////////////////////////////////////////////
                EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);
            }
            finally
            {
                if (sessionKey != null)
                {
                    sessionKey.Clear();
                }
            }
        }

        public static void Decrypt(CryptographyClient cryptoClient, XmlDocument Doc, RSA Alg, string KeyName, string ElementToEncrypt)
        {
            // Check the arguments.
            if (Doc == null)
                throw new ArgumentNullException(nameof(Doc));
            if (Alg == null)
                throw new ArgumentNullException(nameof(Alg));
            if (KeyName == null)
                throw new ArgumentNullException(nameof(KeyName));

            // Create a new key using the key client.
            //KeyVaultKey key = client.CreateKey("key-name", KeyType.Rsa);

            XmlElement elementToEncrypt = Doc.DocumentElement.GetElementsByTagName("EncryptedData")[0] as XmlElement;
            // Throw an XmlException if the element was not found.
            if (elementToEncrypt == null)
            {
                throw new XmlException("The specified element was not found");
            }

            // Retrieve a key using the key client.

            var ecd = new EncryptedData();
            ecd.LoadXml(elementToEncrypt);
            // Assert expected encryption type etc
            var clauses = ecd.KeyInfo.Cast<KeyInfoClause>().OfType< KeyInfoEncryptedKey>().ToList();
            //clauses[0].EncryptedKey.

            //    ecd.EncryptionProperties.
            /*
             * 
                edElement.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);

            */
            // Encrypt the session key and add it to an EncryptedKey element.
            var wrapResult = cryptographyClient.WrapKey(KeyWrapAlgorithm.RsaOaep, sessionKey.Key);

            EncryptedKey ek = new EncryptedKey
    {
        //CipherData = EncryptedXml.EncryptKey(sessionKey.Key, Alg, useOAEP: true);
        CipherData = new CipherData(wrapResult.EncryptedKey),
        EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSAOAEPUrl)
    };



// Create a new EncryptedXml object.
EncryptedXml exml = new EncryptedXml(Doc);

// Add a key-name mapping.
// This method can only decrypt documents
// that present the specified key name.
exml.AddKeyNameMapping(KeyName, Alg);


// Decrypt the element.
exml.DecryptDocument();

Doc.Save("dekrypted.xml");
}

// Sign an XML file.
// This document cannot be verified unless the verifying
// code has the key with which it was signed.
public static void SignXml(XmlDocument xmlDoc, RSA rsaKey)
{
// Check arguments.
if (xmlDoc == null)
    throw new ArgumentException(nameof(xmlDoc));
if (rsaKey == null)
    throw new ArgumentException(nameof(rsaKey));

// Create a SignedXml object.
SignedXml signedXml = new SignedXml(xmlDoc);

// Add the key to the SignedXml document.
signedXml.SigningKey = rsaKey;

// Create a reference to be signed.
Reference reference = new Reference();
reference.Uri = "";

// Add an enveloped transformation to the reference.
XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
reference.AddTransform(env);

// Add the reference to the SignedXml object.
signedXml.AddReference(reference);

// Compute the signature.
signedXml.ComputeSignature();

// Get the XML representation of the signature and save
// it to an XmlElement object.
XmlElement xmlDigitalSignature = signedXml.GetXml();

// Append the element to the XML document.
xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
}
}
}
