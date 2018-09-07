using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FiddlerCore;
using Fiddler;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Threading;

namespace fiddlerCapture
{
    class Capture
    {
        private const string sSecureEndpointHostname = "localhost";
        private const int iSecureEndpointPort = 7777;
        private static readonly ICollection<Session> oAllSessions = new List<Session>();
        private static Proxy oSecureEndpoint;

        public Capture()
        {
            // https://stackoverflow.com/questions/37870084/net-core-doesnt-know-about-windows-1252-how-to-fix
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            // This is a workaround for known issue in .NET Core - https://github.com/dotnet/coreclr/issues/12668
            CultureInfo.DefaultThreadCurrentUICulture = new CultureInfo("en-US");

            //
            // It is important to understand that FiddlerCore calls event handlers on session-handling
            // background threads.  If you need to properly synchronize to the UI-thread (say, because
            // you're adding the sessions to a list view) you must call .Invoke on a delegate on the 
            // window handle.
            // 
            // If you are writing to a non-threadsafe data structure (e.g. List<>) you must
            // use a lock or other mechanism to ensure safety.
            //

            FiddlerApplication.Log.OnLogString += (object sender, LogEventArgs oLEA) =>
            {
                Console.WriteLine("** LogString: " + oLEA.LogString);
            };

            FiddlerApplication.BeforeRequest += (Session oS) =>
            {
                // In order to enable response tampering, buffering mode MUST
                // be enabled; this allows FiddlerCore to permit modification of
                // the response in the BeforeResponse handler rather than streaming
                // the response to the client as the response comes in.
                oS.bBufferResponse = false;
                lock (oAllSessions)
                {
                    oAllSessions.Add(oS);
                }

                // Set this property if you want FiddlerCore to automatically authenticate by
                // answering Digest/Negotiate/NTLM/Kerberos challenges itself
                // oS["X-AutoAuth"] = "(default)";

                /* If the request is going to our secure endpoint, we'll echo back the response.
            
                Note: This BeforeRequest is getting called for both our main proxy tunnel AND our secure endpoint, 
                so we have to look at which Fiddler port the client connected to (pipeClient.LocalPort) to determine whether this request 
                was sent to secure endpoint, or was merely sent to the main proxy tunnel (e.g. a CONNECT) in order to *reach* the secure endpoint.
            
                As a result of this, if you run the demo and visit https://localhost:7777 in your browser, you'll see
            
                Session list contains...
            
                    1 CONNECT http://localhost:7777
                    200                                         <-- CONNECT tunnel sent to the main proxy tunnel, port 8877
            
                    2 GET https://localhost:7777/
                    200 text/html                               <-- GET request decrypted on the main proxy tunnel, port 8877
            
                    3 GET https://localhost:7777/               
                    200 text/html                               <-- GET request received by the secure endpoint, port 7777
                */

                if ((oS.oRequest.pipeClient.LocalPort == iSecureEndpointPort) && (oS.hostname == sSecureEndpointHostname))
                {
                    oS.utilCreateResponseAndBypassServer();
                    oS.oResponse.headers.SetStatus(200, "Ok");
                    oS.oResponse["Content-Type"] = "text/html; charset=UTF-8";
                    oS.oResponse["Cache-Control"] = "private, max-age=0";
                    oS.utilSetResponseBody("<html><body>Request for httpS://" + sSecureEndpointHostname + ":" + iSecureEndpointPort.ToString() + " received. Your request was:<br /><plaintext>" + oS.oRequest.headers.ToString());
                }
            };

            // The following event allows you to examine every response buffer read by Fiddler. Note that this isn't useful for the vast majority of
            // applications because the raw buffer is nearly useless; it's not decompressed, it includes both headers and body bytes, etc.
            //
            // This event is only useful for a handful of applications which need access to a raw, unprocessed byte-stream
            // FiddlerApplication.OnReadResponseBuffer += FiddlerApplication_OnReadResponseBuffer;

            /*
            FiddlerApplication.BeforeResponse += (Session oS) =>
            {
                Console.WriteLine($"{oS.id}:HTTP {oS.responseCode} for {oS.fullUrl}");
            
                // Uncomment the following two statements to decompress/unchunk the
                // HTTP response and subsequently modify any HTTP responses to replace 
                // instances of the word "Microsoft" with "Bayden". You MUST also
                // set bBufferResponse = true inside the beforeREQUEST method above.
                //
                // oS.utilDecodeResponse();
                // oS.utilReplaceInResponse("Microsoft", "Bayden");
            };
            */

            FiddlerApplication.AfterSessionComplete += (Session oS) =>
            {
                int count;
                lock (oAllSessions)
                {
                    count = oAllSessions.Count;
                }
                Console.Title = $"Session list contains: {count} sessions";
            };

            // Tell the system console to handle CTRL+C by calling our method that
            // gracefully shuts down the FiddlerCore.
            //
            // Note, this doesn't handle the case where the user closes the window with the close button.
            // See http://geekswithblogs.net/mrnat/archive/2004/09/23/11594.aspx for info on that...
            //
            Console.CancelKeyPress += new ConsoleCancelEventHandler(Console_CancelKeyPress);

            string sSAZInfo = "NoSAZ";
#if SAZ_SUPPORT
            sSAZInfo = Assembly.GetAssembly(typeof(Ionic.Zip.ZipFile)).FullName;

            // Import Transcoders from the BasicFormatsForCore.dll
            // Note that you can provide your own transcoders by implementing either or both of the ISessionImporter and ISessionExporter interfaces.
            // You can load Transcoders from any different assembly if you'd like, using the ImportTranscoders(string AssemblyPath)  overload.
            //string basicFormatsAssemblyPath = CONFIG.GetPath("App") + "BasicFormatsForCore.dll";
            //if (!FiddlerApplication.oTranscoders.ImportTranscoders(basicFormatsAssemblyPath))
            //{
            //    Console.WriteLine("This assembly was not compiled with a SAZ-exporter");
            //}

            DNZSAZProvider.fnObtainPwd = () =>
            {
                Console.WriteLine("Enter the password (or just hit Enter to cancel):");
                string sResult = Console.ReadLine();
                Console.WriteLine();
                return sResult;
            };

            FiddlerApplication.oSAZProvider = new DNZSAZProvider();
#endif

            Console.WriteLine($"Starting {FiddlerApplication.GetVersionString()} ({sSAZInfo})...");

            // For the purposes of this demo, we'll forbid connections to HTTPS 
            // sites that use invalid certificates. Change this from the default only
            // if you know EXACTLY what that implies.
            CONFIG.IgnoreServerCertErrors = false;

            // ... but you can allow a specific (even invalid) certificate by implementing and assigning a callback...
            // FiddlerApplication.OnValidateServerCertificate += CheckCert;

            FiddlerApplication.Prefs.SetBoolPref("fiddler.network.streaming.abortifclientaborts", true);

            // NOTE: In the next line, you can pass 0 for the port (instead of 8877) to have FiddlerCore auto-select an available port
            //ushort iPort = 8877;
            ushort iPort = 0;

            FiddlerCoreStartupSettings startupSettings =
                new FiddlerCoreStartupSettingsBuilder()
                    .ListenOnPort(iPort)
                    .RegisterAsSystemProxy()
                    .DecryptSSL()
                    //.AllowRemoteClients()
                    //.ChainToUpstreamGateway()
                    //.MonitorAllConnections()
                    //.HookUsingPACFile()
                    //.CaptureLocalhostTraffic()
                    //.CaptureFTP()
                    .OptimizeThreadPool()
                    //.SetUpstreamGatewayTo("http=CorpProxy:80;https=SecureProxy:443;ftp=ftpGW:20")
                    .Build();

            FiddlerApplication.Startup(startupSettings);

            FiddlerApplication.Log.LogFormat("Created endpoint listening on port {0}", iPort);

            FiddlerApplication.Log.LogFormat("Gateway: {0}", CONFIG.UpstreamGateway.ToString());

            Console.WriteLine("Hit CTRL+C to end session.");

            // We'll also create a HTTPS listener, useful for when FiddlerCore is masquerading as a HTTPS server
            // instead of acting as a normal CERN-style proxy server.
            oSecureEndpoint = FiddlerApplication.CreateProxyEndpoint(iSecureEndpointPort, true, sSecureEndpointHostname);
            if (null != oSecureEndpoint)
            {
                FiddlerApplication.Log.LogFormat("Created secure endpoint listening on port {0}, using a HTTPS certificate for '{1}'", iSecureEndpointPort, sSecureEndpointHostname);
            }

            bool bDone = false;
            do
            {
                Console.WriteLine(@"
Enter a command [C=Clear; L=List; G=Collect Garbage; W=write SAZ; R=read SAZ;
    S=Toggle Forgetful Streaming; E=Export cert to Desktop; T=Trust cert on Windows;
    D=Shutdown; Q=Quit]:");
                Console.Write(">");
                ConsoleKeyInfo cki = Console.ReadKey();
                Console.WriteLine();
                switch (Char.ToLower(cki.KeyChar))
                {
                    case 'c':
                        lock (oAllSessions)
                        {
                            oAllSessions.Clear();
                        }

                        WriteCommandResponse("Clear...");
                        FiddlerApplication.Log.LogString("Cleared session list.");
                        break;

                    case 'd':
                        FiddlerApplication.Log.LogString("FiddlerApplication::Shutdown.");
                        FiddlerApplication.Shutdown();
                        break;

                    case 'e':
                        X509Certificate2 rootCert = CertMaker.GetRootCertificate();
                        if (rootCert == null)
                        {
                            FiddlerApplication.Log.LogString("Root certificate not found.");
                            break;
                        }

                        byte[] rootCertBytes = rootCert.Export(X509ContentType.Cert);
                        string rootCertPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "FiddlerCoreRoot.cer");
                        File.WriteAllBytes(rootCertPath, rootCertBytes);
                        FiddlerApplication.Log.LogString("Root certificate exported successfully.");
                        break;

                    case 'l':
                        WriteSessionList();
                        break;

                    case 'g':
                        Console.WriteLine("Working Set:\t" + Environment.WorkingSet.ToString("n0"));
                        Console.WriteLine("Begin GC...");
                        GC.Collect();
                        Console.WriteLine("GC Done.\nWorking Set:\t" + Environment.WorkingSet.ToString("n0"));
                        break;

                    case 'q':
                        bDone = true;
                        DoQuit();
                        break;

                    case 'r':
#if SAZ_SUPPORT
                        lock (oAllSessions)
                        {
                            ReadSessions(oAllSessions);
                        }
#else
                        WriteCommandResponse("This demo was compiled without SAZ_SUPPORT defined");
#endif
                        break;

                    case 'w':
#if SAZ_SUPPORT
                        IEnumerable<Session> sessionToWrite;
                        lock (oAllSessions)
                        {
                            sessionToWrite = oAllSessions.ToList();
                        }
                        
                        SaveSessionsToDesktop(sessionToWrite);
#else
                        WriteCommandResponse("This demo was compiled without SAZ_SUPPORT defined");
#endif
                        break;

                    case 't':
                        try
                        {
                            WriteCommandResponse("Result: " + CertMaker.trustRootCert().ToString());
                        }
                        catch (Exception eX)
                        {
                            WriteCommandResponse("Failed: " + eX.ToString());
                        }
                        break;

                    // Forgetful streaming
                    case 's':
                        bool bForgetful = !FiddlerApplication.Prefs.GetBoolPref("fiddler.network.streaming.ForgetStreamedData", false);
                        FiddlerApplication.Prefs.SetBoolPref("fiddler.network.streaming.ForgetStreamedData", bForgetful);
                        Console.WriteLine(bForgetful ? "FiddlerCore will immediately dump streaming response data." : "FiddlerCore will keep a copy of streamed response data.");
                        break;

                }
            } while (!bDone);
        }

        /*
        /// <summary>
        /// This callback allows your code to evaluate the certificate for a site and optionally override default validation behavior for that certificate.
        /// You should not implement this method unless you understand why it is a security risk.
        /// </summary>
        private static void CheckCert(object sender, ValidateServerCertificateEventArgs e)
        {
            if (null != e.ServerCertificate)
            {
                Console.WriteLine($"Certificate for {e.ExpectedCN} was for site {e.ServerCertificate.Subject} and errors were {e.CertificatePolicyErrors}");
        
                if (e.ServerCertificate.Subject.Contains("fiddler2.com"))
                {
                    Console.WriteLine("Got a certificate for fiddler2.com. We'll say this is also good for any other site, like https://fiddlertool.com.");
                    e.ValidityState = CertificateValidity.ForceValid;
                }
            }
        }
        */

        /*
        // This event handler is called on every socket read for the HTTP Response. You almost certainly don't want
        // to add a handler for this event, but the code below shows how you can use it to mess up your HTTP traffic.
        private static void FiddlerApplication_OnReadResponseBuffer(object sender, RawReadEventArgs e)
        {
            // NOTE: arrDataBuffer is a fixed-size array. Only bytes 0 to iCountOfBytes should be read/manipulated.
            //
            // Just for kicks, lowercase every byte. Note that this will obviously break any binary content.
            for (int i = 0; i < e.iCountOfBytes; i++)
            {
                if ((e.arrDataBuffer[i] > 0x40) && (e.arrDataBuffer[i] < 0x5b))
                {
                    e.arrDataBuffer[i] = (byte)(e.arrDataBuffer[i] + (byte)0x20);
                }
            }
            Console.WriteLine($"Read {e.iCountOfBytes} response bytes for session {e.sessionOwner.id}");
        }
        */

        private static void WriteCommandResponse(string s)
        {
            ConsoleColor oldColor = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(s);
            Console.ForegroundColor = oldColor;
        }

        private static void DoQuit()
        {
            WriteCommandResponse("Shutting down...");
            if (null != oSecureEndpoint)
            {
                oSecureEndpoint.Dispose();
                DeletePrivateKeys();
            }

            FiddlerApplication.Shutdown();
            Thread.Sleep(500);
        }

        private static void DeletePrivateKeys()
        {
            ICertificateProvider4 certProvider = CertMaker.oCertProvider as ICertificateProvider4;
            if (certProvider == null)
            {
                return;
            }

            PrivateKeyDeleter privateKeyDeleter = new PrivateKeyDeleter();

            IDictionary<string, X509Certificate2> certs = certProvider.CertCache;
            foreach (X509Certificate2 cert in certs.Values)
            {
                privateKeyDeleter.DeletePrivateKey(cert.PrivateKey);
            }
        }

        private static void WriteSessionList()
        {
            ConsoleColor oldColor = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("Session list contains...");

            lock (oAllSessions)
            {
                foreach (Session oS in oAllSessions)
                {
                    Console.Write($"{oS.id} {oS.oRequest.headers.HTTPMethod} {Ellipsize(oS.fullUrl, 60)}\n{oS.responseCode} {oS.oResponse.MIMEType}\n\n");
                }
            }

            Console.WriteLine();
            Console.ForegroundColor = oldColor;
        }

        private static string Ellipsize(string s, int iLen)
        {
            if (s.Length <= iLen) return s;
            return s.Substring(0, iLen - 3) + "...";
        }

        /// <summary>
        /// When the user hits CTRL+C, this event fires.  We use this to shut down and unregister our FiddlerCore.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            DoQuit();
        }

#if SAZ_SUPPORT
        private static void ReadSessions(ICollection<Session> oAllSessions)
        {
            Session[] oLoaded = Fiddler.Utilities.ReadSessionArchive(Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
                                                           + Path.DirectorySeparatorChar + "ToLoad.saz");

            if ((oLoaded != null) && (oLoaded.Length > 0))
            {
                for (int i = 0; i < oLoaded.Length; i++)
                {
                    oAllSessions.Add(oLoaded[i]);
                }

                WriteCommandResponse("Loaded: " + oLoaded.Length + " sessions.");
            }
        }

        private static void SaveSessionsToDesktop(IEnumerable<Session> oAllSessions)
        {
            try
            {
                string sPassword = null;
                Console.WriteLine("Password Protect this Archive (Y/N)?");
                ConsoleKeyInfo oCKI = Console.ReadKey();
                if ((oCKI.KeyChar == 'y') || (oCKI.KeyChar == 'Y'))
                {
                    Console.WriteLine("\nEnter the password:");
                    sPassword = Console.ReadLine();
                    Console.WriteLine(String.Format("\nEncrypting with Password: '{0}'", sPassword));
                }

                Console.WriteLine();

                string sFilename = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory) +
                    Path.DirectorySeparatorChar + DateTime.Now.ToString("hh-mm-ss") + ".saz";
                bool bSuccess = Fiddler.Utilities.WriteSessionArchive(sFilename, oAllSessions.ToArray(), sPassword);

                WriteCommandResponse(bSuccess ? ("Wrote: " + sFilename) : ("Failed to save: " + sFilename));
            }
            catch (Exception eX)
            {
                Console.WriteLine("Save failed: " + eX.Message);
            }
        }
#endif
    }
}
