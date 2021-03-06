using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AddStoreDemo
{
    class Program
    {
        private static bool TryReadNext(string[] args, ref int i, out string read)
        {
            if (i >= args.Length - 1)
            {
                read = null;
                return false;
            }

            i++;
            read = args[i];
            return true;
        }

        private static bool TryParseCommand(
            string[] args,
            out X509Certificate2 leaf,
            out X509Chain chain)
        {
            leaf = null;
            chain = new X509Chain();

            string certPath = null;
            string certPwd = null;
            string modeString = null;
            string verifyTime = null;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-cert":
                        if (certPath != null) return false;
                        if (!TryReadNext(args, ref i, out certPath)) return false;
                        break;
                    case "-pfxpwd":
                    case "-pfxpassword":
                        if (certPwd != null) return false;
                        if (!TryReadNext(args, ref i, out certPwd)) return false;
                        break;
                    case "-mode":
                    {
                        X509RevocationMode mode;

                        if (modeString != null) return false;
                        if (!TryReadNext(args, ref i, out modeString)) return false;
                        if (!Enum.TryParse(modeString, true, out mode)) return false;

                        chain.ChainPolicy.RevocationMode = mode;
                        break;
                    }
                    case "-verifytime":
                    {
                        DateTime when;

                        if (verifyTime != null) return false;
                        if (!TryReadNext(args, ref i, out verifyTime)) return false;
                        if (!DateTime.TryParse(verifyTime, out when)) return false;

                        chain.ChainPolicy.VerificationTime = when;
                        break;
                    }
                    case "-extracert":
                    {
                        string extraPath;

                        if (!TryReadNext(args, ref i, out extraPath)) return false;

                        try
                        {
                            X509Certificate2 extraCert = new X509Certificate2(extraPath);
                            chain.ChainPolicy.ExtraStore.Add(extraCert);
                        }
                        catch (CryptographicException e)
                        {
                            Console.WriteLine(e.Message);
                            return false;
                        }

                        break;
                    }
                    case "-verifyflag":
                    {
                        string flagString;
                        X509VerificationFlags flag;

                        if (!TryReadNext(args, ref i, out flagString)) return false;
                        if (!Enum.TryParse(flagString, true, out flag)) return false;

                        chain.ChainPolicy.VerificationFlags |= flag;
                        break;
                    }
                    case "-?":
                    case "/?":
                    case "-h":
                    case "--help":
                        return false;
                    default:
                    {
                        if (certPath == null)
                        {
                            certPath = args[i];
                            break;
                        }
                            
                        return false;
                    }
                }
            }

            if (certPath == null)
            {
                return false;
            }

            try
            {
                leaf = new X509Certificate2(certPath, certPwd);
                return true;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return false;
            }
        }

        public static void Main(string[] args)
        {
            try
            {
                X509Certificate2 cert;
                X509Chain chain;

                if (!TryParseCommand(args, out cert, out chain))
                {
                    Console.WriteLine("Usage: [options] <cert> [options]");
                    Console.WriteLine();
                    Console.WriteLine(" -cert           For people who don't like bare options");
                    Console.WriteLine(" -pfxpassword    The PFX decryption key");
                    Console.WriteLine(" -pfxpwd         Alias for -pfxpassword");
                    Console.WriteLine(" -mode           X509RevocationMode (Online|Offline|NoCheck)");
                    Console.WriteLine(" -verifytime     VerificationTime, any parsable DateTime (local time)");
                    Console.WriteLine(" -extracert      Path to a cert to add to the resolver chain (multiple allowed)");
                    Console.WriteLine(" -verifyflag     X509VerificationFlag to add to the policy (multiple allowed)");
                    Console.WriteLine();

                    return;
                }

                using (cert)
                {
                    Console.Write("Validating Certificate: ");
                    Console.WriteLine(cert.GetNameInfo(X509NameType.SimpleName, false));
                    Console.WriteLine();

                    bool valid = chain.Build(cert);

                    if (valid)
                    {
                        Console.ForegroundColor = ConsoleColor.DarkGreen;
                        Console.WriteLine("Chain is valid");
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.DarkRed;
                        Console.WriteLine("Chain is NOT valid");
                    }

                    Console.ResetColor();
                    Console.WriteLine();

                    Console.WriteLine("Chain Element Status:");
                    foreach (X509ChainElement element in chain.ChainElements)
                    {
                        Console.Write("  ");
                        Console.WriteLine(element.Certificate.Subject);

                        foreach (X509ChainStatus status in element.ChainElementStatus)
                        {
                            Console.WriteLine("    {0} ({1})", status.Status, status.StatusInformation);
                        }

                        Console.WriteLine();
                    }

                    Console.WriteLine("Chain Summary:");

                    foreach (X509ChainStatus status in chain.ChainStatus)
                    {
                        Console.WriteLine("    {0} ({1})", status.Status, status.StatusInformation);
                    }
                }
            }
            catch (Exception e)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("ERROR!");
                Console.WriteLine(e);
                Console.ResetColor();
            }


            GC.Collect();
            GC.WaitForPendingFinalizers();
        }
    }
}
