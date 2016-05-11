using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Windows.UI.Xaml.Media.Animation;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=234238

namespace CryptRunner
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class DoEverythingPage : Page
    {
        private static Brush HappyBrush = new SolidColorBrush(Windows.UI.Colors.ForestGreen);
        private static Brush SadBrush = new SolidColorBrush(Windows.UI.Colors.Red);

        public DoEverythingPage()
        {
            this.InitializeComponent();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            Frame.GoBack(new DrillInNavigationTransitionInfo());
        }

        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);
            ClearStatus();
        }

        private void ClearStatus()
        {
            AesCbcOut.Text = ECDsaOut.Text = RsaEncryptPkcs1Out.Text =
                RsaOaepSha1Out.Text =
                RsaOaepSha256Out.Text =
                RsaSignPkcs1Out.Text =
                RsaPssOut.Text =
                TripleDesCbcOut.Text =
                X509RsaCerOut.Text =
                X509RsaPfxOut.Text =
                X509ECDsaCerOut.Text =
                X509ECDsaPfxOut.Text =
                X509StoreOut.Text = "";
        }

        private async void DoStuff_Click(object sender, RoutedEventArgs e)
        {
            Tuple<Func<string>, TextBlock>[] actions =
            {
                new Tuple<Func<string>, TextBlock>(AesCbc, AesCbcOut),
                new Tuple<Func<string>, TextBlock>(EcDsa, ECDsaOut),
                new Tuple<Func<string>, TextBlock>(RsaEncryptPkcs1, RsaEncryptPkcs1Out),
                new Tuple<Func<string>, TextBlock>(RsaOaepSha1, RsaOaepSha1Out),
                new Tuple<Func<string>, TextBlock>(RsaOaepSha256, RsaOaepSha256Out),
                new Tuple<Func<string>, TextBlock>(RsaSignPkcs1, RsaSignPkcs1Out),
                new Tuple<Func<string>, TextBlock>(RsaPss, RsaPssOut),
                new Tuple<Func<string>, TextBlock>(TripleDesCbc, TripleDesCbcOut),
                new Tuple<Func<string>, TextBlock>(X509RsaCer, X509RsaCerOut),
                new Tuple<Func<string>, TextBlock>(X509RsaPfx, X509RsaPfxOut),
                new Tuple<Func<string>, TextBlock>(X509ECDsaCer, X509ECDsaCerOut),
                new Tuple<Func<string>, TextBlock>(X509ECDsaPfx, X509ECDsaPfxOut),
                new Tuple<Func<string>, TextBlock>(X509StoreFunc, X509StoreOut),

            };

            ClearStatus();

            WorkingRing.Visibility = Visibility.Visible;
            WorkingRing.IsActive = true;

            foreach (var action in actions)
            {
                string msg = await System.Threading.Tasks.Task.Run(() => DoStuff(action.Item1));
                DoUIStuff(msg, action.Item2);
            }

            WorkingRing.IsActive = false;
            WorkingRing.Visibility = Visibility.Collapsed;
        }

        private static string AesCbc()
        {
            using (Aes aes = Aes.Create())
            {
                aes.GenerateKey();
                aes.GenerateIV();

                byte[] plainText = new byte[500];
                byte[] cipherText;
                byte[] clearText;

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    cipherText = encryptor.TransformFinalBlock(plainText, 0, plainText.Length);
                }

                if (cipherText.Length < plainText.Length)
                {
                    return $"Bad cipherLength: {cipherText.Length}";
                }

                if (plainText.SequenceEqual(cipherText))
                {
                    return "Encryption did nothing";
                }

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    clearText = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                }

                if (!plainText.SequenceEqual(clearText))
                {
                    return "Decryption error";
                }

                return null;
            }
        }

        private static string EcDsa()
        {
            using (ECDsa ecdsa = new ECDsaCng(521))
            {
                if (ecdsa.KeySize != 521)
                {
                    return "ctor KeySize not respected";
                }

                ecdsa.KeySize = 384;

                if (ecdsa.KeySize != 384)
                {
                    return "set_KeySize not respected";
                }

                byte[] data = new byte[312];
                byte[] signature = ecdsa.SignData(data, HashAlgorithmName.SHA384);

                if (signature.Length != 96)
                {
                    return $"SigLength {signature.Length}";
                }

                if (!ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA384))
                {
                    return "Legit Verify failed";
                }

                if (ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA512))
                {
                    return "Wrong algo passed";
                }

                if (ecdsa.VerifyData(signature, signature, HashAlgorithmName.SHA384))
                {
                    return "Wrong data passed";
                }

                return null;
            }
        }

        private static string RsaEncryptPkcs1()
        {
            return RsaEncrypt(RSAEncryptionPadding.Pkcs1);
        }

        private static string RsaOaepSha1()
        {
            return RsaEncrypt(RSAEncryptionPadding.OaepSHA1);
        }

        private static string RsaOaepSha256()
        {
            return RsaEncrypt(RSAEncryptionPadding.OaepSHA256);
        }

        private static string RsaEncrypt(RSAEncryptionPadding padding)
        {
            using (RSA rsa = new RSACng(2048 + 64))
            using (RSA rsaPublic = new RSACng())
            {
                rsaPublic.ImportParameters(rsa.ExportParameters(false));

                if (rsaPublic.KeySize != rsa.KeySize)
                {
                    return $"RsaPub.KeySize: {rsaPublic.KeySize}";
                }

                byte[] data = new byte[rsa.KeySize / 16];
                byte[] encrypted = rsaPublic.Encrypt(data, padding);

                if (encrypted.Length * 8 != rsaPublic.KeySize)
                {
                    return $"encrypted.Length: {encrypted.Length}";
                }

                byte[] clear = rsa.Decrypt(encrypted, padding);

                if (!data.SequenceEqual(clear))
                {
                    return "Decrypt mismatch";
                }

                try
                {
                    byte[] wrongPadding = rsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA512);

                    if (data.SequenceEqual(wrongPadding))
                    {
                        return "Data==WrongPadding";
                    }
                }
                catch (CryptographicException)
                {
                }

                try
                {
                    rsaPublic.Decrypt(encrypted, padding);
                    return "RsaPub decrypted";
                }
                catch (CryptographicException)
                {
                }

                return null;
            }
        }

        private static string RsaSignPkcs1()
        {
            return RsaSign(RSASignaturePadding.Pkcs1);
        }

        private static string RsaPss()
        {
            return RsaSign(RSASignaturePadding.Pss);
        }

        private static string RsaSign(RSASignaturePadding padding)
        {
            using (RSA rsa = new RSACng(2048 + 128))
            using (RSA rsaPublic = new RSACng())
            {
                rsaPublic.ImportParameters(rsa.ExportParameters(false));
                
                byte[] data = new byte[8543];
                byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, padding);

                if (signature.Length * 8 != rsa.KeySize)
                {
                    return $"SigLength {signature.Length}";
                }

                try
                {
                    rsaPublic.SignData(data, HashAlgorithmName.SHA256, padding);
                    return "PublicSign succeeded";
                }
                catch (CryptographicException)
                {
                }

                if (!rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, padding))
                {
                    return "Legit PrivVerify failed";
                }

                if (!rsaPublic.VerifyData(data, signature, HashAlgorithmName.SHA256, padding))
                {
                    return "Legit PubVerify failed";
                }

                if (rsaPublic.VerifyData(data, signature, HashAlgorithmName.SHA512, padding))
                {
                    return "Wrong algo passed";
                }

                if (rsaPublic.VerifyData(signature, signature, HashAlgorithmName.SHA256, padding))
                {
                    return "Wrong data passed";
                }

                RSASignaturePadding otherPadding =
                    padding == RSASignaturePadding.Pkcs1 ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;

                if (rsaPublic.VerifyData(signature, signature, HashAlgorithmName.SHA256, otherPadding))
                {
                    return "Wrong padding passed";
                }

                return null;
            }
        }

        private static string TripleDesCbc()
        {
            using (TripleDES aes = TripleDES.Create())
            {
                aes.GenerateKey();
                aes.GenerateIV();

                byte[] plainText = new byte[500];
                byte[] cipherText;
                byte[] clearText;

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    cipherText = encryptor.TransformFinalBlock(plainText, 0, plainText.Length);
                }

                if (cipherText.Length < plainText.Length)
                {
                    return $"Bad cipherLength: {cipherText.Length}";
                }

                if (plainText.SequenceEqual(cipherText))
                {
                    return "Encryption did nothing";
                }

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    clearText = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                }

                if (!plainText.SequenceEqual(clearText))
                {
                    return "Decryption error";
                }

                return null;
            }
        }

        private static string X509RsaCer()
        {
            byte[] helloBytes = TestData.HelloBytes;
            byte[] existingSignature = TestData.RSA1024ExpectedSignature;

            using (var cert = new X509Certificate2(TestData.RSA1024Certificate))
            using (RSA publicKey = cert.GetRSAPublicKey())
            using (RSA privateKey = cert.GetRSAPrivateKey())
            {
                if (privateKey != null)
                {
                    return "PrivKey is not null";
                }

                if (publicKey.KeySize != 1024)
                {
                    return $"Bad KeySize: {publicKey.KeySize}";
                }

                if (!publicKey.VerifyData(helloBytes, existingSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                {
                    return "PubKey Validate Failed";
                }

                try
                {
                    publicKey.SignData(helloBytes, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
                    return "PublicKey is private";
                }
                catch (CryptographicException)
                {
                }
            }

            return null;
        }

        private static string X509RsaPfx()
        {
            byte[] helloBytes = TestData.HelloBytes;
            byte[] existingSignature = TestData.RSA1024ExpectedSignature;

            using (var cert = new X509Certificate2(TestData.RSA1024Pfx, "12345"))
            using (RSA publicKey = cert.GetRSAPublicKey())
            using (RSA privateKey = cert.GetRSAPrivateKey())
            {
                if (publicKey.KeySize != 1024)
                {
                    return $"Bad KeySize: {publicKey.KeySize}";
                }

                if (!publicKey.VerifyData(helloBytes, existingSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                {
                    return "PubKey Validate Failed";
                }

                if (!privateKey.VerifyData(helloBytes, existingSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                {
                    return "PrivKey Validate Failed";
                }

                byte[] newSignature = privateKey.SignData(helloBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

                if (!publicKey.VerifyData(helloBytes, newSignature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
                {
                    return "NewSig Validate Failed";
                }

                try
                {
                    publicKey.SignData(helloBytes, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
                    return "PublicKey is private";
                }
                catch (CryptographicException)
                {
                }
            }

            return null;
        }

        private static string X509ECDsaCer()
        {
            byte[] helloBytes = TestData.HelloBytes;
            byte[] existingSignature = TestData.ECDsaP256_DigitalSignature;

            using (var cert = new X509Certificate2(TestData.ECDsaP256_DigitalSignature_Cer))
            //using (var cert = new X509Certificate2(TestData.ECDsaP256_DigitalSignature_Pfx_Windows, "Test"))
            using (ECDsa publicKey = cert.GetECDsaPublicKey())
            using (ECDsa privateKey = cert.GetECDsaPrivateKey())
            {
                if (privateKey != null)
                {
                    return "PrivKey is not null";
                }

                if (publicKey.KeySize != 256)
                {
                    return $"Bad KeySize: {publicKey.KeySize}";
                }

                if (!publicKey.VerifyData(helloBytes, existingSignature, HashAlgorithmName.SHA256))
                {
                    return "PubKey Validate Failed";
                }

                try
                {
                    publicKey.SignData(helloBytes, HashAlgorithmName.SHA384);
                    return "PublicKey is private";
                }
                catch (CryptographicException)
                {
                }
            }

            return null;
        }

        private static string X509ECDsaPfx()
        {
            byte[] helloBytes = TestData.HelloBytes;
            byte[] existingSignature = TestData.ECDsaP256_DigitalSignature;

            using (var cert = new X509Certificate2(TestData.ECDsaP256_DigitalSignature_Pfx_Windows, "Test"))
            //using (ECDsa publicKey = cert.GetECDsaPublicKey())
            using (ECDsa privateKey = cert.GetECDsaPrivateKey())
            {
                // Workaround for GetECDsaPublicKey not functioning.
                ECDsa publicKey = privateKey;

                if (publicKey.KeySize != 256)
                {
                    return $"Bad KeySize: {publicKey.KeySize}";
                }

                if (!publicKey.VerifyData(helloBytes, existingSignature, HashAlgorithmName.SHA256))
                {
                    return "PubKey Validate Failed";
                }

                if (!privateKey.VerifyData(helloBytes, existingSignature, HashAlgorithmName.SHA256))
                {
                    return "PrivKey Validate Failed";
                }

                byte[] newSignature = privateKey.SignData(helloBytes, HashAlgorithmName.SHA512);

                if (!publicKey.VerifyData(helloBytes, newSignature, HashAlgorithmName.SHA512))
                {
                    return "NewSig Validate Failed";
                }

                if (publicKey != privateKey)
                {
                    try
                    {
                        publicKey.SignData(helloBytes, HashAlgorithmName.SHA384);
                        return "PublicKey is private";
                    }
                    catch (CryptographicException)
                    {
                    }
                }
            }

            return null;
        }

        private static string X509StoreFunc()
        {
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                try
                {
                    store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
                }
                catch (CryptographicException)
                {
                    return "Failed to open";
                }

                int storeCount = store.Certificates.Count;

                using (X509Certificate2 rsaPfx = new X509Certificate2(TestData.RSA1024Pfx, "12345", X509KeyStorageFlags.PersistKeySet))
                using (X509Certificate2 ecdsaPfx = new X509Certificate2(TestData.ECDsaP256_DigitalSignature_Pfx_Windows, "Test", X509KeyStorageFlags.PersistKeySet))
                {
                    store.Add(rsaPfx);
                    store.Add(ecdsaPfx);

                    bool foundRsa = false;
                    bool foundEcdsa = false;

                    foreach (X509Certificate2 cert in store.Certificates)
                    {
                        if (cert.Equals(rsaPfx))
                        {
                            if (foundRsa)
                            {
                                return "Found RSA twice";
                            }

                            if (!cert.HasPrivateKey)
                            {
                                return "RSA clone missing privkey";
                            }

                            foundRsa = true;
                        }
                        else if (cert.Equals(ecdsaPfx))
                        {
                            if (foundEcdsa)
                            {
                                return "Found ECDSA twice";
                            }

                            if (!cert.HasPrivateKey)
                            {
                                return "ECDSA clone missing privkey";
                            }

                            foundEcdsa = true;
                        }
                    }

                    if (!foundRsa)
                    {
                        return "Didn't find RSA";
                    }

                    if (!foundEcdsa)
                    {
                        return "Didn't find ECDSA";
                    }

                    store.Remove(rsaPfx);
                    store.Remove(ecdsaPfx);
                }

                int newCount = store.Certificates.Count;

                if (newCount != storeCount)
                {
                    return $"Expected {storeCount} got {newCount}";
                }
            }

            return null;
        }

        private static string DoStuff(Func<string> action)
        {
            try
            {
                return action();
            }
            catch (Exception e)
            {
                return e.GetType().Name;
            }
        }

        private static void DoUIStuff(string msg, TextBlock output)
        {
            if (msg != null)
            {
                output.Foreground = SadBrush;
                output.Text = msg;
            }
            else
            {
                output.Foreground = HappyBrush;
                output.Text = "OK";
            }
        }
    }

    internal static class TestData
    {
        internal static readonly byte[] HelloBytes = Encoding.ASCII.GetBytes("Hello");

        internal static readonly byte[] RSA1024ExpectedSignature = new byte[]
        {
            0x28, 0x05, 0x5C, 0xFA, 0xF5, 0xAF, 0x5E, 0x03,
            0xD0, 0xFD, 0x8A, 0x7F, 0x73, 0x66, 0x26, 0xEC,
            0x86, 0xF4, 0xBC, 0x3C, 0xA9, 0xBB, 0x9D, 0xDE,
            0xB7, 0xE8, 0xA0, 0x22, 0x16, 0x91, 0x66, 0x6F,
            0x89, 0xAE, 0x69, 0x30, 0xBB, 0xDC, 0x1D, 0x5D,
            0x48, 0xF0, 0x92, 0x44, 0xD9, 0x88, 0xC4, 0xD5,
            0x35, 0x52, 0x6F, 0xA2, 0x04, 0xBA, 0xD6, 0x3E,
            0xB8, 0x02, 0x1D, 0x90, 0x9E, 0x52, 0xB1, 0xD9,
            0x77, 0x99, 0x46, 0xBD, 0x29, 0x1A, 0xA0, 0x79,
            0xBA, 0xF1, 0xF6, 0x38, 0x4F, 0xF4, 0xB6, 0xA0,
            0x0D, 0xB7, 0x58, 0x1D, 0x52, 0xB4, 0x8C, 0xFA,
            0x6A, 0x88, 0xFA, 0xC1, 0x64, 0x51, 0xD1, 0x23,
            0x07, 0x8D, 0xD6, 0xD3, 0x80, 0x2F, 0xBA, 0x25,
            0xBD, 0xE1, 0xA3, 0x28, 0x34, 0xAD, 0xE8, 0x5D,
            0xC4, 0x2D, 0xF5, 0x69, 0xFD, 0x60, 0xC1, 0x74,
            0xB1, 0x00, 0xAA, 0x98, 0x66, 0xA8, 0x78, 0xC7,
        };

        internal static readonly byte[] RSA1024Certificate = (
            "308201E530820152A0030201020210D5B5BC1C458A558845BFF51CB4DFF31C30" +
            "0906052B0E03021D05003011310F300D060355040313064D794E616D65301E17" +
            "0D3130303430313038303030305A170D3131303430313038303030305A301131" +
            "0F300D060355040313064D794E616D6530819F300D06092A864886F70D010101" +
            "050003818D0030818902818100B11E30EA87424A371E30227E933CE6BE0E65FF" +
            "1C189D0D888EC8FF13AA7B42B68056128322B21F2B6976609B62B6BC4CF2E55F" +
            "F5AE64E9B68C78A3C2DACC916A1BC7322DD353B32898675CFB5B298B176D978B" +
            "1F12313E3D865BC53465A11CCA106870A4B5D50A2C410938240E92B64902BAEA" +
            "23EB093D9599E9E372E48336730203010001A346304430420603551D01043B30" +
            "39801024859EBF125E76AF3F0D7979B4AC7A96A1133011310F300D0603550403" +
            "13064D794E616D658210D5B5BC1C458A558845BFF51CB4DFF31C300906052B0E" +
            "03021D0500038181009BF6E2CF830ED485B86D6B9E8DFFDCD65EFC7EC145CB93" +
            "48923710666791FCFA3AB59D689FFD7234B7872611C5C23E5E0714531ABADB5D" +
            "E492D2C736E1C929E648A65CC9EB63CD84E57B5909DD5DDF5DBBBA4A6498B9CA" +
            "225B6E368B94913BFC24DE6B2BD9A26B192B957304B89531E902FFC91B54B237" +
            "BB228BE8AFCDA26476").HexToByteArray();

        internal static readonly byte[] RSA1024Pfx = (
            "3082063A020103308205F606092A864886F70D010701A08205E7048205E33082" +
            "05DF3082035806092A864886F70D010701A08203490482034530820341308203" +
            "3D060B2A864886F70D010C0A0102A08202B6308202B2301C060A2A864886F70D" +
            "010C0103300E04085052002C7DA2C2A6020207D0048202907D485E3BFC6E6457" +
            "C811394C145D0E8A18325646854E4FF0097BC5A98547F5AD616C8EFDA8505AA8" +
            "7564ED4800A3139759497C60C6688B51F376ACAE906429C8771CB1428226B68A" +
            "6297207BCC9DD7F9563478DD83880AAB2304B545759B2275305DF4EFF9FAC24A" +
            "3CC9D3B2D672EFE45D8F48E24A16506C1D7566FC6D1B269FBF201B3AC3309D3E" +
            "BC6FD606257A7A707AA2F790EA3FE7A94A51138540C5319010CBA6DE9FB9D85F" +
            "CDC78DA60E33DF2F21C46FB9A8554B4F82E0A6EDBA4DB5585D77D331D35DAAED" +
            "51B6A5A3E000A299880FB799182C8CA3004B7837A9FEB8BFC76778089993F3D1" +
            "1D70233608AF7C50722D680623D2BF54BD4B1E7A604184D9F44E0AF8099FFA47" +
            "1E5536E7902793829DB9902DDB61264A62962950AD274EA516B2D44BE9036530" +
            "016E607B73F341AEEFED2211F6330364738B435B0D2ED6C57747F6C8230A053F" +
            "78C4DD65DB83B26C6A47836A6CBBAB92CBB262C6FB6D08632B4457F5FA8EABFA" +
            "65DB34157E1D301E9085CC443582CDD15404314872748545EB3FC3C574882655" +
            "8C9A85F966E315775BBE9DA34D1E8B6DADC3C9E120C6D6A2E1CFFE4EB014C3CE" +
            "FBC19356CE33DAC60F93D67A4DE247B0DAE13CD8B8C9F15604CC0EC9968E3AD7" +
            "F57C9F53C45E2ECB0A0945EC0BA04BAA15B48D8596EDC9F5FE9165A5D21949FB" +
            "5FE30A920AD2C0F78799F6443C300629B8CA4DCA19B9DBF1E27AAB7B12271228" +
            "119A95C9822BE6439414BEEAE24002B46EB97E030E18BD810ADE0BCF4213A355" +
            "038B56584B2FBCC3F5EA215D0CF667FFD823EA03AB62C3B193DFB4450AABB50B" +
            "AF306E8088EE7384FA2FDFF03E0DD7ACD61832223E806A94D46E196462522808" +
            "3163F1CAF333FDBBE2D54CA86968867CE0B6DD5E5B7F0633C6FAB4A19CC14F64" +
            "5EC14D0B1436F7623174301306092A864886F70D010915310604040100000030" +
            "5D06092B060104018237110131501E4E004D006900630072006F0073006F0066" +
            "00740020005300740072006F006E0067002000430072007900700074006F0067" +
            "007200610070006800690063002000500072006F007600690064006500723082" +
            "027F06092A864886F70D010706A08202703082026C0201003082026506092A86" +
            "4886F70D010701301C060A2A864886F70D010C0106300E0408E0C117E67A75D8" +
            "EB020207D080820238292882408B31826F0DC635F9BBE7C199A48A3B4FEFC729" +
            "DBF95508D6A7D04805A8DD612427F93124F522AC7D3C6F4DDB74D937F57823B5" +
            "B1E8CFAE4ECE4A1FFFD801558D77BA31985AA7F747D834CBE84464EF777718C9" +
            "865C819D6C9DAA0FA25E2A2A80B3F2AAA67D40E382EB084CCA85E314EA40C3EF" +
            "3ED1593904D7A16F37807C99AF06C917093F6C5AAEBB12A6C58C9956D4FBBDDE" +
            "1F1E389989C36E19DD38D4B978D6F47131E458AB68E237E40CB6A87F21C8773D" +
            "E845780B50995A51F041106F47C740B3BD946038984F1AC9E91230616480962F" +
            "11B0683F8802173C596C4BD554642F51A76F9DFFF9053DEF7B3C3F759FC7EEAC" +
            "3F2386106C4B8CB669589E004FB235F0357EA5CF0B5A6FC78A6D941A3AE44AF7" +
            "B601B59D15CD1EC61BCCC481FBB83EAE2F83153B41E71EF76A2814AB59347F11" +
            "6AB3E9C1621668A573013D34D13D3854E604286733C6BAD0F511D7F8FD6356F7" +
            "C3198D0CB771AF27F4B5A3C3B571FDD083FD68A9A1EEA783152C436F7513613A" +
            "7E399A1DA48D7E55DB7504DC47D1145DF8D7B6D32EAA4CCEE06F98BB3DDA2CC0" +
            "D0564A962F86DFB122E4F7E2ED6F1B509C58D4A3B2D0A68788F7E313AECFBDEF" +
            "456C31B96FC13586E02AEB65807ED83BB0CB7C28F157BC95C9C593C919469153" +
            "9AE3C620ED1D4D4AF0177F6B9483A5341D7B084BC5B425AFB658168EE2D8FB2B" +
            "FAB07A3BA061687A5ECD1F8DA9001DD3E7BE793923094ABB0F2CF4D24CB071B9" +
            "E568B18336BB4DC541352C9785C48D0F0E53066EB2009EFCB3E5644ED12252C1" +
            "BC303B301F300706052B0E03021A04144DEAB829B57A3156AEBC8239C0E7E884" +
            "EFD96E680414E147930B932899741C92D7652268938770254A2B020207D0").HexToByteArray();

        internal static readonly byte[] ECDsaP256_DigitalSignature =
        {
            // r:
            0x60, 0x55, 0x76, 0xFD, 0x7C, 0x7E, 0x28, 0x1D,
            0xCC, 0xAF, 0x00, 0x9F, 0x77, 0x91, 0x16, 0x20,
            0x14, 0x67, 0x76, 0x02, 0xE5, 0xD9, 0x47, 0x92,
            0xF8, 0x7B, 0x7A, 0x8C, 0x5C, 0x6F, 0xB0, 0x28,

            // s:
            0x3C, 0x18, 0xDE, 0x96, 0xFF, 0xB1, 0xCC, 0xD6,
            0xC3, 0x09, 0x03, 0x75, 0xCE, 0xBB, 0x5C, 0x5D,
            0x6D, 0x64, 0x28, 0xE7, 0xAE, 0xF1, 0x1B, 0x9B,
            0x14, 0x64, 0x86, 0x1D, 0xA5, 0x3F, 0x88, 0x28,
        };

        internal static readonly byte[] ECDsaP256_DigitalSignature_Cer = (
            "308201583081FFA003020102021035428F3B3C5107AD49E776D6E74C4DC8300A" +
            "06082A8648CE3D04030230153113301106035504030C0A454344534120546573" +
            "74301E170D3135303530313030333730335A170D313630353031303035373033" +
            "5A30153113301106035504030C0A454344534120546573743059301306072A86" +
            "48CE3D020106082A8648CE3D030107034200047590F69CA114E92927E034C997" +
            "B7C882A8C992AC00CEFB4EB831901536F291E1B515263BCD20E1EA32496FDAC8" +
            "4E2D8D1B703266A9088F6EAF652549D9BB63D5A331302F300E0603551D0F0101" +
            "FF040403020388301D0603551D0E0416041411218A92C5EB12273B3C5CCFB822" +
            "0CCCFDF387DB300A06082A8648CE3D040302034800304502201AFE595E19F1AE" +
            "4B6A4B231E8851926438C55B5DDE632E6ADF13C1023A65898E022100CBDF434F" +
            "DD197D8B594E8026E44263BADE773C2BEBD060CC4109484A498E7C7E").HexToByteArray();

        internal static readonly byte[] ECDsaP256_DigitalSignature_Pfx_Windows = (
            "308204470201033082040306092A864886F70D010701A08203F4048203F03082" +
            "03EC3082016D06092A864886F70D010701A082015E0482015A30820156308201" +
            "52060B2A864886F70D010C0A0102A081CC3081C9301C060A2A864886F70D010C" +
            "0103300E0408EC154269C5878209020207D00481A80BAA4AF8660E6FAB7B050B" +
            "8EF604CFC378652B54FE005DC3C7E2F12E5EFC7FE2BB0E1B3828CAFE752FD64C" +
            "7CA04AF9FBC5A1F36E30D7D299C52BF6AE65B54B9240CC37C04E7E06330C24E9" +
            "6D19A67B7015A6BF52C172FFEA719B930DBE310EEBC756BDFF2DF2846EE973A6" +
            "6C63F4E9130083D64487B35C1941E98B02B6D5A92972293742383C62CCAFB996" +
            "EAD71A1DF5D0380EFFF25BA60B233A39210FD7D55A9B95CD8A440DF666317430" +
            "1306092A864886F70D0109153106040401000000305D06092B06010401823711" +
            "0131501E4E004D006900630072006F0073006F0066007400200053006F006600" +
            "7400770061007200650020004B00650079002000530074006F00720061006700" +
            "65002000500072006F007600690064006500723082027706092A864886F70D01" +
            "0706A0820268308202640201003082025D06092A864886F70D010701301C060A" +
            "2A864886F70D010C0106300E0408175CCB1790C48584020207D080820230E956" +
            "E38768A035D8EA911283A63F2E5B6E5B73231CFC4FFD386481DE24B7BB1B0995" +
            "D614A0D1BD086215CE0054E01EF9CF91B7D80A4ACB6B596F1DFD6CBCA71476F6" +
            "10C0D6DD24A301E4B79BA6993F15D34A8ADB7115A8605E797A2C6826A4379B65" +
            "90B56CA29F7C36997119257A827C3CA0EC7F8F819536208C650E324C8F884794" +
            "78705F833155463A4EFC02B5D5E2608B83F3CAF6C9BB97C1BBBFC6C5584BDCD3" +
            "9C46A3944915B3845C41429C7792EB4FA3A7EDECCD801F31A4B6EF57D808AEEA" +
            "AF3D1F55F378EF8EF9632CED16EDA3EFBE4A9D5C5F608CA90A9AC8D3F86462AC" +
            "219BFFD0B8A87DDD22CF029230369B33FC2B488B5F82702EFC3F270F912EAD2E" +
            "2402D99F8324164C5CD5959F22DEC0D1D212345B4B3F62848E7D9CFCE2224B61" +
            "976C107E1B218B4B7614FF65BCCA388F85D6920270D4C588DEED323C416D014F" +
            "5F648CC2EE941855EB3C889DCB9A345ED11CAE94041A86ED23E5789137A3DE22" +
            "5F4023D260BB686901F2149B5D7E37102FFF5282995892BDC2EAB48BD5DA155F" +
            "72B1BD05EE3EDD32160AC852E5B47CA9AEACE24946062E9D7DCDA642F945C9E7" +
            "C98640DFAC7A2B88E76A560A0B4156611F9BE8B3613C71870F035062BD4E3D9F" +
            "D896CF373CBFBFD31410972CDE50739FFB8EC9180A52D7F5415EBC997E5A4221" +
            "349B4BB7D53614630EEEA729A74E0C0D20726FDE5814321D6C265A7DC6BA24CA" +
            "F2FCE8C8C162733D58E02E08921E70EF838B95C96A5818489782563AE8A2A85F" +
            "64A95EB350FF8EF6D625AD031BCD303B301F300706052B0E03021A0414C8D96C" +
            "ED140F5CA3CB92BEFCA32C690804576ABF0414B59D4FECA9944D40EEFDE7FB96" +
            "196D167B0FA511020207D0").HexToByteArray();
    }

    internal static class ByteUtils
    {
        internal static byte[] HexToByteArray(this string hexString)
        {
            byte[] bytes = new byte[hexString.Length / 2];

            for (int i = 0; i < hexString.Length; i += 2)
            {
                string s = hexString.Substring(i, 2);
                bytes[i / 2] = byte.Parse(s, System.Globalization.NumberStyles.HexNumber, null);
            }

            return bytes;
        }
    }
}
