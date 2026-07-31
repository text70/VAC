using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Carbon.Plugins;

namespace Carbon.Plugins
{
    [Info("VacIntegrity", "VAC Team", "1.0.0")]
    [Description("Server integrity monitoring, client anti-cheat coordinator, and daemon delivery")]
    public class VacIntegrity : CarbonPlugin
    {
        // -----------------------------------------------------------------------
        // Native imports from libvac_integrity.so
        // -----------------------------------------------------------------------

        [DllImport("libvac_integrity", CallingConvention = CallingConvention.Cdecl)]
        private static extern int vac_init(
            byte[] kyberPk, int kyberPkLen,
            byte[] mldsa65Sk, int mldsa65SkLen,
            byte[] kyberSk, int kyberSkLen,
            byte[] mldsa65Pk, int mldsa65PkLen
        );

        [DllImport("libvac_integrity", CallingConvention = CallingConvention.Cdecl)]
        private static extern int vac_scan(
            uint moduleId, byte[] buffer, ref int len
        );

        [DllImport("libvac_integrity", CallingConvention = CallingConvention.Cdecl)]
        private static extern int vac_decrypt(
            byte[] encrypted, int encryptedLen,
            byte[] kyberSk, int kyberSkLen,
            byte[] mldsa65Pk, int mldsa65PkLen,
            uint[] output, ref int outputDwords
        );

        [DllImport("libvac_integrity", CallingConvention = CallingConvention.Cdecl)]
        private static extern int vac_shutdown();

        [DllImport("libvac_integrity", CallingConvention = CallingConvention.Cdecl)]
        private static extern int vac_server_listener_start(ushort port);

        [DllImport("libvac_integrity", CallingConvention = CallingConvention.Cdecl)]
        private static extern int vac_server_listener_stop();

        [DllImport("libvac_integrity", CallingConvention = CallingConvention.Cdecl)]
        private static extern int vac_server_register_client(
            uint steamIdLo, uint steamIdHi,
            byte[] playerName, int playerNameLen
        );

        [DllImport("libvac_integrity", CallingConvention = CallingConvention.Cdecl)]
        private static extern int vac_server_unregister_client(
            uint steamIdLo, uint steamIdHi
        );

        [DllImport("libvac_integrity", CallingConvention = CallingConvention.Cdecl)]
        private static extern int vac_server_daemon_connected(
            uint steamIdLo, uint steamIdHi
        );

        // -----------------------------------------------------------------------
        // Ring-0 cheat detection callback
        // -----------------------------------------------------------------------

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void CheatDetectedCallback(
            uint steamIdLo, uint steamIdHi, IntPtr reason
        );

        [DllImport("libvac_integrity", CallingConvention = CallingConvention.Cdecl)]
        private static extern int vac_server_set_kick_callback(IntPtr callback);

        // -----------------------------------------------------------------------
        // Plugin state
        // -----------------------------------------------------------------------

        private byte[] _kyberPk;
        private byte[] _kyberSk;
        private byte[] _mldsa65Sk;
        private byte[] _mldsa65Pk;

        private const int ScanBufferSize = 12649;
        private const int MaxUints = 2048;

        private static CheatDetectedCallback _cheatCallback;

        // Enforcement state
        private const int GraceSeconds = 60;
        private const int DownloadPort = 28085;
        private readonly Dictionary<ulong, DateTime> _playerConnectTime = new Dictionary<ulong, DateTime>();

        // HTTP download server hardening
        private const int HttpMaxConcurrent = 16;
        private const int HttpMaxHeaderBytes = 4096;
        private const int HttpStreamBuffer = 65536;
        private const int HttpSocketTimeoutMs = 15000;
        private const int HttpMaxBodyBytes = 512 * 1024 * 1024;
        private static readonly HashSet<string> AllowedInstallers =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "/vac-setup.exe", "/" };

        // HTTP download server
        private Thread _httpServerThread;
        private volatile bool _httpServerRunning;
        private TcpListener _httpListener;
        private readonly SemaphoreSlim _httpSlots = new SemaphoreSlim(HttpMaxConcurrent);

        // -----------------------------------------------------------------------
        // Hook: server initialized
        // -----------------------------------------------------------------------

        private void OnServerInitialized()
        {
            LoadKeyMaterial();

            int result = vac_init(
                _kyberPk, _kyberPk.Length,
                _mldsa65Sk, _mldsa65Sk.Length,
                _kyberSk, _kyberSk.Length,
                _mldsa65Pk, _mldsa65Pk.Length
            );
            if (result != 0)
            {
                Logger.Warn("VacIntegrity: vac_init failed with code " + result);
                return;
            }

            Logger.Log("VacIntegrity: initialized");

            _cheatCallback = new CheatDetectedCallback(OnCheatDetected);
            IntPtr cbPtr = Marshal.GetFunctionPointerForDelegate(_cheatCallback);
            vac_server_set_kick_callback(cbPtr);

            int listenerResult = vac_server_listener_start(28084);
            if (listenerResult != 0)
            {
                Logger.Warn("VacIntegrity: listener start failed with code " + listenerResult);
            }
            else
            {
                Logger.Log("VacIntegrity: daemon listener on port 28084");
            }

            // Start HTTP download server for the Windows client installer
            StartHttpServer();

            // Schedule server-local scans
            timer.Every(60, () => RunScan(1));
            timer.Every(120, () => RunScan(2));
            timer.Every(300, () => RunScan(3));
            timer.Every(600, () => RunScan(4));
            timer.Every(600, () => RunScan(5));
            timer.Every(60, () => RunScan(6));

            // Hard enforcement: check daemon connection every 5 seconds
            timer.Every(5, CheckDaemonEnforcement);
        }

        // -----------------------------------------------------------------------
        // Embedded HTTP download server
        // -----------------------------------------------------------------------

        private void StartHttpServer()
        {
            _httpServerRunning = true;
            _httpServerThread = new Thread(() =>
            {
                string installerPath = Path.Combine(
                    Environment.CurrentDirectory, "carbon", "native", "vac-setup.exe");

                if (!File.Exists(installerPath))
                {
                    Logger.Log("VacIntegrity: no vac-setup.exe found at " + installerPath +
                        "; HTTP download server will serve 404");
                }

                try
                {
                    var listener = new TcpListener(IPAddress.Any, DownloadPort);
                    _httpListener = listener;
                    listener.Start();
                    Logger.Log("VacIntegrity: download server on port " + DownloadPort);

                    while (_httpServerRunning)
                    {
                        TcpClient client;
                        try
                        {
                            client = listener.AcceptTcpClient();
                        }
                        catch
                        {
                            break;
                        }

                        if (!_httpSlots.Wait(0))
                        {
                            client.Close();
                            continue;
                        }

                        ThreadPool.QueueUserWorkItem(_ =>
                        {
                            try
                            {
                                HandleHttpClient(client, installerPath);
                            }
                            finally
                            {
                                _httpSlots.Release();
                            }
                        });
                    }

                    listener.Stop();
                    if (ReferenceEquals(_httpListener, listener))
                        _httpListener = null;
                }
                catch (Exception e)
                {
                    Logger.Warn("VacIntegrity: HTTP server error: " + e.Message);
                }
            })
            { IsBackground = true };
            _httpServerThread.Start();
        }

        private void HandleHttpClient(TcpClient client, string installerPath)
        {
            try
            {
                using (client)
                {
                    client.ReceiveTimeout = HttpSocketTimeoutMs;
                    client.SendTimeout = HttpSocketTimeoutMs;

                    var stream = client.GetStream();
                    byte[] headerBytes = ReadRequestHead(stream);
                    if (headerBytes == null)
                        return;

                    string request = Encoding.ASCII.GetString(headerBytes);
                    int lineEnd = request.IndexOf("\r\n");
                    string requestLine = lineEnd < 0 ? request : request.Substring(0, lineEnd);

                    string[] parts = requestLine.Split(' ');
                    if (parts.Length < 3 || parts[0] != "GET")
                    {
                        WriteResponse(stream, 400, "text/html; charset=utf-8",
                            "<html><body><h2>400 Bad Request</h2></body></html>");
                        return;
                    }

                    string path = parts[1];
                    if (!AllowedInstallers.Contains(path))
                    {
                        WriteResponse(stream, 404, "text/html; charset=utf-8",
                            "<html><body><h2>404 Not Found</h2></body></html>");
                        return;
                    }

                    if (path == "/")
                    {
                        string index = "<html><body>" +
                            "<h2>VAC Anti-Cheat Client</h2>" +
                            "<p><a href='/vac-setup.exe'>Download Windows Client</a></p>" +
                            "<p><small>Install and run to play on this server.</small></p>" +
                            "</body></html>";
                        WriteResponse(stream, 200, "text/html; charset=utf-8", index);
                        return;
                    }

                    if (!File.Exists(installerPath))
                    {
                        WriteResponse(stream, 404, "text/html; charset=utf-8",
                            "<html><body><h2>404 vac-setup.exe not available</h2></body></html>");
                        return;
                    }

                    var info = new FileInfo(installerPath);
                    if (info.Length <= 0 || info.Length > HttpMaxBodyBytes)
                    {
                        WriteResponse(stream, 404, "text/html; charset=utf-8",
                            "<html><body><h2>404 vac-setup.exe unavailable</h2></body></html>");
                        return;
                    }

                    string header = "HTTP/1.1 200 OK\r\n" +
                        "Content-Type: application/octet-stream\r\n" +
                        "Content-Disposition: attachment; filename=vac-setup.exe\r\n" +
                        "Content-Length: " + info.Length + "\r\n" +
                        "Cache-Control: no-store\r\n" +
                        "Connection: close\r\n\r\n";
                    byte[] headerBytes2 = Encoding.ASCII.GetBytes(header);
                    stream.Write(headerBytes2, 0, headerBytes2.Length);

                    using (var fs = new FileStream(installerPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        var buffer = new byte[HttpStreamBuffer];
                        int read;
                        while (_httpServerRunning && (read = fs.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            stream.Write(buffer, 0, read);
                        }
                    }
                }
            }
            catch (IOException)
            {
                // client aborted mid-transfer — expected, no log spam
            }
            catch (SocketException)
            {
                // client aborted/reset mid-transfer — expected
            }
            catch (Exception e)
            {
                Logger.Warn("VacIntegrity: HTTP client error: " + e.Message);
            }
        }

        private static byte[] ReadRequestHead(Stream stream)
        {
            var buffer = new byte[HttpMaxHeaderBytes];
            int total = 0;
            while (total < HttpMaxHeaderBytes)
            {
                int read = stream.Read(buffer, total, HttpMaxHeaderBytes - total);
                if (read <= 0)
                    return null;

                total += read;
                if (ContainsHeaderEnd(buffer, total))
                    return buffer;
            }
            return null;
        }

        private static bool ContainsHeaderEnd(byte[] buf, int len)
        {
            for (int i = 0; i <= len - 4; i++)
            {
                if (buf[i] == (byte)'\r' && buf[i + 1] == (byte)'\n' &&
                    buf[i + 2] == (byte)'\r' && buf[i + 3] == (byte)'\n')
                    return true;
            }
            return false;
        }

        private static void WriteResponse(NetworkStream stream, int status, string contentType, string body)
        {
            byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
            string header = "HTTP/1.1 " + status + " " + StatusText(status) + "\r\n" +
                "Content-Type: " + contentType + "\r\n" +
                "Content-Length: " + bodyBytes.Length + "\r\n" +
                "Cache-Control: no-store\r\n" +
                "Connection: close\r\n\r\n";
            byte[] headerBytes = Encoding.ASCII.GetBytes(header);
            stream.Write(headerBytes, 0, headerBytes.Length);
            stream.Write(bodyBytes, 0, bodyBytes.Length);
        }

        private static string StatusText(int status)
        {
            switch (status)
            {
                case 200: return "OK";
                case 400: return "Bad Request";
                case 404: return "Not Found";
                default: return "Error";
            }
        }

        // -----------------------------------------------------------------------
        // Hard enforcement: kick players without connected daemon
        // -----------------------------------------------------------------------

        private void CheckDaemonEnforcement()
        {
            foreach (var kvp in _playerConnectTime)
            {
                ulong steamId = kvp.Key;
                DateTime connectedAt = kvp.Value;

                if ((DateTime.UtcNow - connectedAt).TotalSeconds < GraceSeconds)
                    continue;

                uint lo = (uint)(steamId & 0xFFFFFFFF);
                uint hi = (uint)((steamId >> 32) & 0xFFFFFFFF);

                int connected = vac_server_daemon_connected(lo, hi);
                if (connected == 0)
                {
                    BasePlayer player = BasePlayer.FindByID(steamId);
                    if (player != null && player.IsConnected)
                    {
                        string serverIp = GetServerIp();
                        string url = $"http://{serverIp}:{DownloadPort}/";
                        player.Kick("VAC client required. Download and install from: " + url);
                        Logger.Log("VacIntegrity: Kicked " + player.displayName +
                            " (no daemon after " + GraceSeconds + "s)");
                    }
                }
            }
        }

        private string GetServerIp()
        {
            try
            {
                string host = ConVar.Server.ip;
                if (string.IsNullOrEmpty(host) || host == "0.0.0.0")
                {
                    var addr = System.Net.NetworkInformation.NetworkInterface
                        .GetAllNetworkInterfaces()
                        .Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up)
                        .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                        .FirstOrDefault(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                            && !System.Net.IPAddress.IsLoopback(a.Address));
                    if (addr != null)
                        return addr.Address.ToString();
                }
                return host;
            }
            catch { return "127.0.0.1"; }
        }

        // -----------------------------------------------------------------------
        // Ring-0 cheat callback
        // -----------------------------------------------------------------------

        private static void OnCheatDetected(uint steamIdLo, uint steamIdHi, IntPtr reasonPtr)
        {
            ulong steamId = ((ulong)steamIdHi << 32) | steamIdLo;
            string reason = Marshal.PtrToStringAnsi(reasonPtr) ?? "Unknown";

            Console.WriteLine($"[VacIntegrity] CHEAT DETECTED steam_id={steamId}: {reason}");

            BasePlayer player = BasePlayer.FindByID(steamId);
            if (player != null && player.IsConnected)
            {
                player.Kick("VAC: " + reason);
                Console.WriteLine($"[VacIntegrity] Kicked {player.displayName} ({steamId}): {reason}");

                ServerUsers.Set(
                    steamId,
                    ServerUsers.UserGroup.Banned,
                    player.displayName,
                    "VAC: " + reason
                );
                Console.WriteLine($"[VacIntegrity] Banned {player.displayName} ({steamId}): {reason}");
            }
            else
            {
                ServerUsers.Set(
                    steamId,
                    ServerUsers.UserGroup.Banned,
                    "unknown",
                    "VAC: " + reason
                );
                Console.WriteLine($"[VacIntegrity] Banned steam_id={steamId} (offline): {reason}");
            }
        }

        // -----------------------------------------------------------------------
        // Hook: player connected
        // -----------------------------------------------------------------------

        private void OnPlayerConnected(BasePlayer player)
        {
            Logger.Log("VacIntegrity: player " + player.displayName +
                " connected (steamid=" + player.UserIDString + ")");

            ulong steamId = player.userID;
            uint lo = (uint)(steamId & 0xFFFFFFFF);
            uint hi = (uint)((steamId >> 32) & 0xFFFFFFFF);
            byte[] nameBytes = Encoding.UTF8.GetBytes(player.displayName ?? "");
            vac_server_register_client(lo, hi, nameBytes, nameBytes.Length);

            string serverIp = GetServerIp();
            string url = $"http://{serverIp}:{DownloadPort}/";
            player.SendChatMessage("VAC", "Download the VAC client: " + url);

            _playerConnectTime[steamId] = DateTime.UtcNow;
        }

        // -----------------------------------------------------------------------
        // Hook: player disconnected
        // -----------------------------------------------------------------------

        private void OnPlayerDisconnected(BasePlayer player, string reason)
        {
            ulong steamId = player.userID;
            uint lo = (uint)(steamId & 0xFFFFFFFF);
            uint hi = (uint)((steamId >> 32) & 0xFFFFFFFF);
            vac_server_unregister_client(lo, hi);
            _playerConnectTime.Remove(steamId);
        }

        // -----------------------------------------------------------------------
        // Key material loading
        // -----------------------------------------------------------------------

        private void LoadKeyMaterial()
        {
            string nativeDir = Path.Combine(
                Environment.CurrentDirectory,
                "carbon", "native");

            _kyberPk   = File.ReadAllBytes(Path.Combine(nativeDir, "kyber_public.der"));
            _kyberSk   = File.ReadAllBytes(Path.Combine(nativeDir, "kyber_secret.der"));
            _mldsa65Sk = File.ReadAllBytes(Path.Combine(nativeDir, "mldsa65_secret.der"));
            _mldsa65Pk = File.ReadAllBytes(Path.Combine(nativeDir, "mldsa65_public.der"));

            Logger.Log("VacIntegrity: loaded key material from " + nativeDir);
        }

        // -----------------------------------------------------------------------
        // Scan execution
        // -----------------------------------------------------------------------

        private void RunScan(uint moduleId)
        {
            byte[] buffer = new byte[ScanBufferSize];
            int len = ScanBufferSize;

            int result = vac_scan(moduleId, buffer, ref len);
            if (result != 0)
            {
                Logger.Warn("VacIntegrity: module " + moduleId + " scan failed with code " + result);
                return;
            }

            Logger.Log("VacIntegrity: module " + moduleId + " scan complete (" + len + " bytes sealed)");

            byte[] sealedData = new byte[len];
            Array.Copy(buffer, sealedData, len);

            AnalyzeScanResult(sealedData, moduleId);
        }

        // -----------------------------------------------------------------------
        // Scan result analysis
        // -----------------------------------------------------------------------

        private void AnalyzeScanResult(byte[] sealedData, uint moduleId)
        {
            uint[] output = new uint[MaxUints];
            int outDwords = MaxUints;

            int status = vac_decrypt(
                sealedData, sealedData.Length,
                _kyberSk, _kyberSk.Length,
                _mldsa65Pk, _mldsa65Pk.Length,
                output, ref outDwords
            );

            if (status == 1)
            {
                Logger.Warn("VacIntegrity: module " + moduleId + " scan result has INVALID SIGNATURE");
                return;
            }
            if (status == 2)
            {
                Logger.Warn("VacIntegrity: module " + moduleId + " scan result DECRYPTION FAILED");
                return;
            }
            if (status < 0)
            {
                Logger.Warn("VacIntegrity: module " + moduleId + " vac_decrypt error code " + status);
                return;
            }

            bool flagged = false;
            string reason = "";

            switch (moduleId)
            {
                case 1:
                    if (output.Length > 27 && (output[23] & 1) == 1)
                    {
                        flagged = true;
                        reason = "Kernel debugger detected";
                    }
                    break;

                case 2:
                    if (output.Length > 6 && output[6] > 0)
                    {
                        flagged = true;
                        reason = "Suspicious processes detected: " + output[6] + " flagged";
                    }
                    break;

                case 3:
                    if (output.Length > 7 && output[7] > 0)
                    {
                        flagged = true;
                        reason = "Suspicious libraries loaded: " + output[7] + " flagged";
                    }
                    break;

                default:
                    break;
            }

            if (flagged)
            {
                Logger.Warn("VacIntegrity: MODULE " + moduleId + " FLAGGED: " + reason);
            }
        }

        // -----------------------------------------------------------------------
        // Hook: server shutdown
        // -----------------------------------------------------------------------

        private void OnServerShutdown()
        {
            _httpServerRunning = false;

            var listener = _httpListener;
            if (listener != null)
            {
                try { listener.Stop(); }
                catch { }
                _httpListener = null;
            }

            vac_server_listener_stop();
            vac_shutdown();
            Logger.Log("VacIntegrity: shutdown complete");
        }
    }
}