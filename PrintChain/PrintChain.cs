using System;
using System.Collections.Concurrent;
using System.Diagnostics.Tracing;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PrintChain
{
    internal static class Program
    {
        private static ConsoleEventListener s_eventListener;

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
#if NET
            string trustModeString = null;
#endif
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
#if NET
                    case "-trustmode":
                    {
                        X509ChainTrustMode trustMode;

                        if (trustModeString != null) return false;
                        if (!TryReadNext(args, ref i, out trustModeString)) return false;
                        if (!Enum.TryParse(trustModeString, true, out trustMode)) return false;

                        chain.ChainPolicy.TrustMode = trustMode;
                        break;
                    }
                    case "-trust":
                    {
                        string trustPath;

                        if (!TryReadNext(args, ref i, out trustPath)) return false;

                        try
                        {
                            X509Certificate2 trustCert = new X509Certificate2(trustPath);
                            chain.ChainPolicy.CustomTrustStore.Add(trustCert);
                        }
                        catch (CryptographicException e)
                        {
                            Console.WriteLine(e.Message);
                            return false;
                        }

                        break;
                    }
#endif
                    case "-verifyflag":
                    {
                        string flagString;
                        X509VerificationFlags flag;

                        if (!TryReadNext(args, ref i, out flagString)) return false;
                        if (!Enum.TryParse(flagString, true, out flag)) return false;

                        chain.ChainPolicy.VerificationFlags |= flag;
                        break;
                    }
                    case "-trace":
                        s_eventListener ??= new ConsoleEventListener();
                        break;
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
#if NET
                    Console.WriteLine(" -trustmode      X509ChainTrustMode (System|CustomRootTrust)");
                    Console.WriteLine(" -trust          Path to a cert to add to the custom trust store (multiple allowed)");
#endif
                    Console.WriteLine(" -verifyflag     X509VerificationFlag to add to the policy (multiple allowed)");
                    Console.WriteLine(" -trace          Show system tracing during the chain build");
                    Console.WriteLine();

                    return;
                }

                using (cert)
                {
                    Console.Write("Validating Certificate: ");
                    Console.WriteLine(cert.GetNameInfo(X509NameType.SimpleName, false));
                    Console.WriteLine();

                    bool valid = chain.Build(cert);

                    if (s_eventListener != null)
                    {
                        Console.WriteLine();
                    }

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

        private sealed class ConsoleEventListener : EventListener
        {
            private static readonly ConcurrentDictionary<(Guid, string), DateTime> s_startTimes = new ConcurrentDictionary<(Guid, string), DateTime>();

            protected override void OnEventSourceCreated(EventSource eventSource)
            {
                if (eventSource.Name.Equals("System.Security.Cryptography.X509Certificates.X509Chain.OpenSsl"))
                {
                    EnableEvents(eventSource, EventLevel.Verbose);
                }
            }

            protected override void OnEventWritten(EventWrittenEventArgs eventData)
            {
                string message = eventData.Message;
                string padding = null;
                string suffix = null;
                string activitySegment = null;

                if (eventData.EventName.EndsWith("Start"))
                {
                    var cacheKey = (eventData.ActivityId, eventData.EventName[0..^5]);
                    var v2 = eventData.TimeStamp;
                    s_startTimes.AddOrUpdate(cacheKey, eventData.TimeStamp, (k, v1) => v1 > v2 ? v1 : v2);
                }
                else if (eventData.EventName.EndsWith("Stop"))
                {
                    var cacheKey = (eventData.ActivityId, eventData.EventName[0..^4]);

                    if (s_startTimes.TryRemove(cacheKey, out DateTime startTime))
                    {
                        double duration = (eventData.TimeStamp - startTime).TotalMilliseconds;
                        suffix = $" - Duration {duration:N3}ms";
                    }
                }

                if (!string.IsNullOrEmpty(message))
                {
                    padding = " - ";

                    if (eventData.Payload?.Count > 0)
                    {
                        message = string.Format(message, System.Linq.Enumerable.ToArray(eventData.Payload));
                    }
                }

                if (eventData.ActivityId != Guid.Empty)
                {
                    activitySegment = $" ({eventData.ActivityId})";
                }

                Console.WriteLine($"{eventData.TimeStamp:yyyy-MM-ddTHH:mm:ss.fffZ}{activitySegment}: {eventData.EventName}{padding}{message}{suffix}");
            }
        }
    }
}
