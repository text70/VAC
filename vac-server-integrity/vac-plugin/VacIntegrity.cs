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
            byte[] playerName, int playerNameLen,
            byte[] token, int tokenLen
        );

        [DllImport("libvac_integrity", CallingConvention = CallingConvention.Cdecl)]
        private static extern int vac_server_ensure_client_token(
            uint steamIdLo, uint steamIdHi,
            byte[] outBuf, int outCap
        );

        [DllImport("libvac_integrity", CallingConvention = CallingConvention.Cdecl)]
        private static extern int vac_server_client_token(
            uint steamIdLo, uint steamIdHi,
            byte[] outBuf, int outCap
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
        // Daemon connections idle between scan rounds and can blip on reconnect;
        // require the daemon to be absent this long before kicking.
        private const int DisconnectToleranceSeconds = 30;
        // Warn once when this many seconds of the grace window remain.
        private const int GraceWarningSeconds = 30;
        private const int DownloadPort = 28085;
        private readonly Dictionary<ulong, DateTime> _playerConnectTime = new Dictionary<ulong, DateTime>();
        private readonly Dictionary<ulong, DateTime> _lastDaemonSeen = new Dictionary<ulong, DateTime>();
        private readonly HashSet<ulong> _graceWarned = new HashSet<ulong>();

        // HTTP download server hardening
        private const int HttpMaxConcurrent = 16;
        private const int HttpMaxHeaderBytes = 4096;
        private const int HttpStreamBuffer = 65536;
        private const int HttpSocketTimeoutMs = 15000;
        private const int HttpMaxBodyBytes = 512 * 1024 * 1024;

        // HTTP download server
        private Thread _httpServerThread;
        private volatile bool _httpServerRunning;
        private TcpListener _httpListener;
        private readonly SemaphoreSlim _httpSlots = new SemaphoreSlim(HttpMaxConcurrent);
        private readonly Dictionary<ulong, string> _playerNames = new Dictionary<ulong, string>();

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
                PrintWarning("VacIntegrity: vac_init failed with code " + result);
                return;
            }

            Puts("VacIntegrity: initialized");

            _cheatCallback = new CheatDetectedCallback(OnCheatDetected);
            IntPtr cbPtr = Marshal.GetFunctionPointerForDelegate(_cheatCallback);
            vac_server_set_kick_callback(cbPtr);

            int listenerResult = vac_server_listener_start(28084);
            if (listenerResult != 0)
            {
                PrintWarning("VacIntegrity: listener start failed with code " + listenerResult);
            }
            else
            {
                Puts("VacIntegrity: daemon listener on port 28084");
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
                    Puts("VacIntegrity: no vac-setup.exe found at " + installerPath +
                        "; HTTP download server will serve 404");
                }

                try
                {
                    var listener = new TcpListener(IPAddress.Any, DownloadPort);
                    _httpListener = listener;
                    listener.Start();
                    Puts("VacIntegrity: download server on port " + DownloadPort);

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
                                HandleHttpClient(client);
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
                    PrintWarning("VacIntegrity: HTTP server error: " + e.Message);
                }
            })
            { IsBackground = true };
            _httpServerThread.Start();
        }

        private void HandleHttpClient(TcpClient client)
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

                    string rawPath = parts[1];
                    int qIdx = rawPath.IndexOf('?');
                    string route = qIdx >= 0 ? rawPath.Substring(0, qIdx) : rawPath;
                    string query = qIdx >= 0 ? rawPath.Substring(qIdx + 1) : "";

                    // Host + User-Agent headers (Host for baking the daemon
                    // address; User-Agent to serve the right client binary).
                    string hostHeader = ExtractHeader(request, "Host:");
                    string userAgent = ExtractHeader(request, "User-Agent:");

                    switch (route.ToLowerInvariant())
                    {
                        case "/":
                            WriteResponse(stream, 200, "text/html; charset=utf-8",
                                "<html><body>" +
                                "<h2>VAC Anti-Cheat Client</h2>" +
                                "<p>Use the download link from the in-game chat message.</p>" +
                                "<p><a href='/vac-setup.exe'>Download installer only (manual setup)</a></p>" +
                                "</body></html>");
                            return;

                        case "/vac-setup.exe":
                            ServeInstaller(stream);
                            return;

                        case "/vac-daemon":
                            ServeLinuxDaemon(stream);
                            return;

                        case "/setup":
                        case "/vac-setup.zip":
                            ServeSetupBundle(stream, query, hostHeader, userAgent);
                            return;

                        case "/vac/status":
                            ServeStatusJson(stream);
                            return;

                        case "/vac/status.html":
                        case "/vac/status/page":
                            ServeStatusHtml(stream);
                            return;

                        default:
                            WriteResponse(stream, 404, "text/html; charset=utf-8",
                                "<html><body><h2>404 Not Found</h2></body></html>");
                            return;
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
                PrintWarning("VacIntegrity: HTTP client error: " + e.Message);
            }
        }

        private static string ExtractHeader(string request, string headerName)
        {
            foreach (string line in request.Split(new[] { "\r\n" }, StringSplitOptions.None))
            {
                if (line.StartsWith(headerName, StringComparison.OrdinalIgnoreCase))
                {
                    return line.Substring(headerName.Length).Trim();
                }
            }
            return "";
        }

        private static bool IsValidToken(string token)
        {
            if (string.IsNullOrEmpty(token) || token.Length != 32)
                return false;
            foreach (char c in token)
            {
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                    return false;
            }
            return true;
        }

        private static string GetQueryParam(string query, string key)
        {
            foreach (string pair in query.Split('&'))
            {
                int eq = pair.IndexOf('=');
                if (eq > 0 && string.Equals(pair.Substring(0, eq), key, StringComparison.OrdinalIgnoreCase))
                {
                    return pair.Substring(eq + 1);
                }
            }
            return "";
        }

        /// GET /setup?t=<token>
        /// Serves the right client package for the requesting OS:
        ///  - Windows User-Agent  -> vac-setup.zip (installer + preload ini)
        ///  - Linux/Proton UA     -> vac-linux.zip (vac-daemon + preload ini)
        private void ServeSetupBundle(NetworkStream stream, string query, string hostHeader, string userAgent)
        {
            string token = GetQueryParam(query, "t");
            if (!IsValidToken(token))
            {
                WriteResponse(stream, 400, "text/plain",
                    "Missing or invalid access code. Use the link from the in-game chat message.");
                return;
            }

            string daemonHost = hostHeader;
            if (string.IsNullOrEmpty(daemonHost))
                daemonHost = GetServerIp() + ":" + 28084;
            // Strip any explicit port the user browsed on; daemon uses 28084.
            int colon = daemonHost.LastIndexOf(':');
            if (colon > 0 && daemonHost.IndexOf(':') == colon && !daemonHost.Contains("]"))
                daemonHost = daemonHost.Substring(0, colon);

            string preloadIni = "# VAC client configuration (auto-generated)\r\n" +
                "server=" + daemonHost + ":28084\r\n" +
                "token=" + token + "\r\n";

            byte[] zip;
            string fileName;

            if (IsLinuxAgent(userAgent))
            {
                zip = BuildLinuxZip(preloadIni);
                fileName = "vac-linux.zip";
            }
            else
            {
                zip = BuildWindowsZip(preloadIni);
                fileName = "vac-setup.zip";
            }

            if (zip == null)
            {
                WriteResponse(stream, 404, "text/plain",
                    "Client package not available yet. Try again shortly.");
                return;
            }

            string header = "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/zip\r\n" +
                "Content-Disposition: attachment; filename=" + fileName + "\r\n" +
                "Content-Length: " + zip.Length + "\r\n" +
                "Cache-Control: no-store\r\n" +
                "Connection: close\r\n\r\n";
            byte[] headerBytes = Encoding.ASCII.GetBytes(header);
            stream.Write(headerBytes, 0, headerBytes.Length);
            stream.Write(zip, 0, zip.Length);
        }

        /// Rough OS detection from the HTTP User-Agent. Windows returns false;
        /// Linux/Proton (or any UA with a *nix marker) returns true.
        private static bool IsLinuxAgent(string userAgent)
        {
            if (string.IsNullOrEmpty(userAgent)) return false;
            string ua = userAgent.ToLowerInvariant();
            if (ua.Contains("windows") || ua.Contains("win32")) return false;
            return ua.Contains("linux") || ua.Contains("x11") || ua.Contains("darwin")
                || ua.Contains("macintosh") || ua.Contains("proton");
        }

        /// Zip with the Linux daemon binary + preload ini (token/server baked in).
        private byte[] BuildLinuxZip(string preloadIni)
        {
            string daemonPath = Path.Combine(
                Environment.CurrentDirectory, "carbon", "native", "vac-daemon");
            if (!File.Exists(daemonPath))
                return null;

            byte[] daemonBytes;
            try { daemonBytes = File.ReadAllBytes(daemonPath); }
            catch { return null; }

            return ZipBuilder.BuildZip(new[]
            {
                new ZipBuilder.Entry { Name = "vac-daemon", Data = daemonBytes },
                new ZipBuilder.Entry { Name = "vac-preload.ini", Data = Encoding.ASCII.GetBytes(preloadIni) },
            });
        }

        /// Zip with the Windows installer + preload ini.
        private byte[] BuildWindowsZip(string preloadIni)
        {
            string installerPath = Path.Combine(
                Environment.CurrentDirectory, "carbon", "native", "vac-setup.exe");
            if (!File.Exists(installerPath))
                return null;

            byte[] exeBytes;
            try { exeBytes = File.ReadAllBytes(installerPath); }
            catch { return null; }

            return ZipBuilder.BuildZip(new[]
            {
                new ZipBuilder.Entry { Name = "vac-setup.exe", Data = exeBytes },
                new ZipBuilder.Entry { Name = "vac-preload.ini", Data = Encoding.ASCII.GetBytes(preloadIni) },
            });
        }

        private void ServeInstaller(NetworkStream stream)
        {
            string installerPath = Path.Combine(
                Environment.CurrentDirectory, "carbon", "native", "vac-setup.exe");

            var info = new FileInfo(installerPath);
            if (!File.Exists(installerPath) || info.Length <= 0 || info.Length > HttpMaxBodyBytes)
            {
                WriteResponse(stream, 404, "text/html; charset=utf-8",
                    "<html><body><h2>404 vac-setup.exe not available</h2></body></html>");
                return;
            }

            string header = "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/octet-stream\r\n" +
                "Content-Disposition: attachment; filename=vac-setup.exe\r\n" +
                "Content-Length: " + info.Length + "\r\n" +
                "Cache-Control: no-store\r\n" +
                "Connection: close\r\n\r\n";
            byte[] headerBytes = Encoding.ASCII.GetBytes(header);
            stream.Write(headerBytes, 0, headerBytes.Length);

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

        /// GET /vac-daemon — Linux client daemon binary (built from this repo,
        /// staged as carbon/native/vac-daemon). Lets Linux clients fetch the
        /// daemon straight from the server.
        private void ServeLinuxDaemon(NetworkStream stream)
        {
            string daemonPath = Path.Combine(
                Environment.CurrentDirectory, "carbon", "native", "vac-daemon");

            var info = new FileInfo(daemonPath);
            if (!File.Exists(daemonPath) || info.Length <= 0 || info.Length > HttpMaxBodyBytes)
            {
                WriteResponse(stream, 404, "text/html; charset=utf-8",
                    "<html><body><h2>404 vac-daemon not available</h2></body></html>");
                return;
            }

            string header = "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/octet-stream\r\n" +
                "Content-Disposition: attachment; filename=vac-daemon\r\n" +
                "Content-Length: " + info.Length + "\r\n" +
                "Cache-Control: no-store\r\n" +
                "Connection: close\r\n\r\n";
            byte[] headerBytes = Encoding.ASCII.GetBytes(header);
            stream.Write(headerBytes, 0, headerBytes.Length);

            using (var fs = new FileStream(daemonPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                var buffer = new byte[HttpStreamBuffer];
                int read;
                while (_httpServerRunning && (read = fs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    stream.Write(buffer, 0, read);
                }
            }
        }

        /// GET /vac/status — machine-readable state for admin dashboards.
        /// Read-only: never includes tokens or key material.
        private void ServeStatusJson(NetworkStream stream)
        {
            var sb = new StringBuilder("{\"players\":[");
            bool first = true;
            lock (_playerNames)
            {
                foreach (var kvp in _playerNames)
                {
                    ulong steamId = kvp.Key;
                    uint lo = (uint)(steamId & 0xFFFFFFFF);
                    uint hi = (uint)((steamId >> 32) & 0xFFFFFFFF);
                    int connected = vac_server_daemon_connected(lo, hi);
                    int enrolled = vac_server_client_token(lo, hi, null, 0); // -1 = none
                    if (!first) sb.Append(',');
                    first = false;
                    string name = kvp.Value ?? "";
                    sb.Append("{\"steamid\":\"").Append(steamId).Append("\",\"name\":")
                      .Append(JsonEscape(name)).Append(",\"daemon_connected\":")
                      .Append(connected == 1 ? "true" : "false")
                      .Append(",\"enrolled\":").Append(enrolled >= 0 ? "true" : "false").Append('}');
                }
            }
            sb.Append("],\"generated\":\"").Append(DateTime.UtcNow.ToString("o")).Append("\"}");

            byte[] body = Encoding.UTF8.GetBytes(sb.ToString());
            string header = "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/json\r\n" +
                "Content-Length: " + body.Length + "\r\n" +
                "Cache-Control: no-store\r\n" +
                "Connection: close\r\n\r\n";
            byte[] hb = Encoding.ASCII.GetBytes(header);
            stream.Write(hb, 0, hb.Length);
            stream.Write(body, 0, body.Length);
        }

        /// GET /vac/status.html — minimal auto-refreshing page suitable for
        /// embedding as a Carbon dashboard custom tab (iframe).
        private void ServeStatusHtml(NetworkStream stream)
        {
            var sb = new StringBuilder();
            sb.Append("<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"10\">");
            sb.Append("<title>VAC Status</title><style>");
            sb.Append("body{background:#15181e;color:#d7dae0;font-family:monospace;margin:24px}");
            sb.Append("table{border-collapse:collapse;width:100%}");
            sb.Append("th,td{padding:6px 12px;border-bottom:1px solid #2a2f3a;text-align:left}");
            sb.Append(".ok{color:#7ec97e}.bad{color:#e06c75}.warn{color:#e5c07b}");
            sb.Append("</style></head><body><h2>VAC Anti-Cheat Status</h2><table>");
            sb.Append("<tr><th>Player</th><th>Steam ID</th><th>Daemon</th><th>Enrolled</th></tr>");
            lock (_playerNames)
            {
                foreach (var kvp in _playerNames)
                {
                    ulong steamId = kvp.Key;
                    uint lo = (uint)(steamId & 0xFFFFFFFF);
                    uint hi = (uint)((steamId >> 32) & 0xFFFFFFFF);
                    int connected = vac_server_daemon_connected(lo, hi);
                    int enrolled = vac_server_client_token(lo, hi, null, 0);
                    sb.Append("<tr><td>").Append(HtmlEncode(kvp.Value ?? "?"));
                    sb.Append("</td><td>").Append(steamId).Append("</td>");
                    sb.Append("<td class='").Append(connected == 1 ? "ok'>CONNECTED" : "warn'>waiting…").Append("</td>");
                    sb.Append("<td class='").Append(enrolled >= 0 ? "ok'>yes" : "bad'>no").Append("</td></tr>");
                }
            }
            sb.Append("</table><p style='color:#5c6370'>Auto-refreshes every 10s · tokens are never shown</p></body></html>");

            byte[] body = Encoding.UTF8.GetBytes(sb.ToString());
            string header = "HTTP/1.1 200 OK\r\n" +
                "Content-Type: text/html; charset=utf-8\r\n" +
                "Content-Length: " + body.Length + "\r\n" +
                "Cache-Control: no-store\r\n" +
                "Connection: close\r\n\r\n";
            byte[] hb = Encoding.ASCII.GetBytes(header);
            stream.Write(hb, 0, hb.Length);
            stream.Write(body, 0, body.Length);
        }

        private static string JsonEscape(string s)
        {
            if (s == null) return "\"\"";
            var sb = new StringBuilder("\"");
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.AppendFormat("\\u{0:x4}", (int)c);
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }

        private static string HtmlEncode(string s)
        {
            if (s == null) return "";
            return s.Replace("&", "&amp;").Replace("<", "&lt;")
                    .Replace(">", "&gt;").Replace("\"", "&quot;");
        }

        // -------------------------------------------------------------------
        // Minimal store-only ZIP writer (no compression, no external deps).
        // Used to bundle vac-setup.exe + vac-preload.ini for the magic link.
        // -------------------------------------------------------------------
        private static class ZipBuilder
        {
            public struct Entry
            {
                public string Name;
                public byte[] Data;
            }

            public static byte[] BuildZip(Entry[] entries)
            {
                // two passes: need total size first? Not necessary — build with lists.
                var central = new List<byte[]>();
                using (var ms = new MemoryStream())
                {
                    foreach (var e in entries)
                    {
                        uint entryCrc = Crc32(e.Data);
                        int offset = (int)ms.Position;
                        byte[] nameBytes = Encoding.ASCII.GetBytes(e.Name);

                        // Local file header
                        WriteLE32(ms, 0x04034b50);
                        WriteLE16(ms, 20);          // version needed
                        WriteLE16(ms, 0);           // flags
                        WriteLE16(ms, 0);           // method: stored
                        WriteLE16(ms, 0);           // mod time
                        WriteLE16(ms, 0x21);        // mod date (1980-01-01)
                        WriteLE32(ms, entryCrc);
                        WriteLE32(ms, (uint)e.Data.Length);
                        WriteLE32(ms, (uint)e.Data.Length);
                        WriteLE16(ms, (ushort)nameBytes.Length);
                        WriteLE16(ms, 0);           // extra len
                        ms.Write(nameBytes, 0, nameBytes.Length);
                        ms.Write(e.Data, 0, e.Data.Length);

                        // Central directory record
                        var cd = new MemoryStream();
                        WriteLE32(cd, 0x02014b50);
                        WriteLE16(cd, 20);          // version made by
                        WriteLE16(cd, 20);          // version needed
                        WriteLE16(cd, 0);
                        WriteLE16(cd, 0);
                        WriteLE16(cd, 0);
                        WriteLE16(cd, 0x21);
                        WriteLE32(cd, entryCrc);
                        WriteLE32(cd, (uint)e.Data.Length);
                        WriteLE32(cd, (uint)e.Data.Length);
                        WriteLE16(cd, (ushort)nameBytes.Length);
                        WriteLE16(cd, 0);           // extra
                        WriteLE16(cd, 0);           // comment
                        WriteLE16(cd, 0);           // disk number
                        WriteLE16(cd, 0);           // internal attrs
                        WriteLE32(cd, 0);           // external attrs
                        WriteLE32(cd, (uint)offset);
                        cd.Write(nameBytes, 0, nameBytes.Length);
                        central.Add(cd.ToArray());
                    }

                    uint cdOffset = (uint)ms.Position;
                    uint cdSize = 0;
                    foreach (var rec in central)
                    {
                        ms.Write(rec, 0, rec.Length);
                        cdSize += (uint)rec.Length;
                    }

                    // EOCD
                    WriteLE32(ms, 0x06054b50);
                    WriteLE16(ms, 0);
                    WriteLE16(ms, 0);
                    WriteLE16(ms, (ushort)entries.Length);
                    WriteLE16(ms, (ushort)entries.Length);
                    WriteLE32(ms, cdSize);
                    WriteLE32(ms, cdOffset);
                    WriteLE16(ms, 0);

                    return ms.ToArray();
                }
            }

            private static void WriteLE16(Stream s, ushort v)
            {
                s.WriteByte((byte)(v & 0xFF));
                s.WriteByte((byte)((v >> 8) & 0xFF));
            }

            private static void WriteLE32(Stream s, uint v)
            {
                s.WriteByte((byte)(v & 0xFF));
                s.WriteByte((byte)((v >> 8) & 0xFF));
                s.WriteByte((byte)((v >> 16) & 0xFF));
                s.WriteByte((byte)((v >> 24) & 0xFF));
            }

            private static uint Crc32(byte[] data)
            {
                uint crc = 0xFFFFFFFFu;
                foreach (byte b in data)
                {
                    crc ^= b;
                    for (int i = 0; i < 8; i++)
                    {
                        bool bit = (crc & 1) != 0;
                        crc >>= 1;
                        if (bit) crc ^= 0xEDB88320u;
                    }
                }
                return ~crc;
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
            // Iterate a snapshot so OnPlayerDisconnected (which removes from
            // _playerConnectTime) can't mutate the collection mid-enumeration
            // and kill the 5s timer.
            var players = new List<KeyValuePair<ulong, DateTime>>(_playerConnectTime);
            foreach (var kvp in players)
            {
                ulong steamId = kvp.Key;
                DateTime connectedAt = kvp.Value;

                if ((DateTime.UtcNow - connectedAt).TotalSeconds < GraceSeconds)
                    continue;

                uint lo = (uint)(steamId & 0xFFFFFFFF);
                uint hi = (uint)((steamId >> 32) & 0xFFFFFFFF);

                int connected = vac_server_daemon_connected(lo, hi);
                if (connected == 1)
                {
                    _lastDaemonSeen[steamId] = DateTime.UtcNow;
                    _graceWarned.Remove(steamId);
                    continue;
                }

                DateTime lastSeen;
                bool everSeen = _lastDaemonSeen.TryGetValue(steamId, out lastSeen);
                bool absentLongEnough = !everSeen ||
                    (DateTime.UtcNow - lastSeen).TotalSeconds >= DisconnectToleranceSeconds;

                BasePlayer player = BasePlayer.FindByID(steamId);
                if (player == null || !player.IsConnected)
                    continue;

                // Half-grace warning: nudge once per connect while the daemon
                // is still missing so the kick doesn't come as a surprise.
                double remaining = GraceSeconds - (DateTime.UtcNow - connectedAt).TotalSeconds;
                if (!absentLongEnough && remaining <= GraceWarningSeconds &&
                    _graceWarned.Add(steamId))
                {
                    player.ChatMessage("VAC: daemon not connected — " + (int)remaining +
                        "s left before kick. Press F1: your access code is in the console.");
                    string warnTok = EnsureToken(lo, hi);
                    if (warnTok != null)
                        SendTokenConsole(player, steamId, warnTok);
                }

                if (absentLongEnough)
                {
                    string serverIp = GetServerIp();
                    string url = $"http://{serverIp}:{DownloadPort}/";
                    // Hand the credentials to the only copyable surface the
                    // game has BEFORE kicking — the kick dialog itself is not
                    // selectable, but F1 console history survives it.
                    string kickTok = EnsureToken(lo, hi);
                    if (kickTok != null)
                        SendTokenConsole(player, steamId, kickTok);
                    player.Kick("VAC client required — reopen F1 at the main menu: "
                        + "your steamid + access code are in the console. Download: " + url);
                    Puts("VacIntegrity: Kicked " + player.displayName +
                        " (no daemon after " + GraceSeconds + "s)");
                }
            }
        }

        // -----------------------------------------------------------------------
        // Console handoff: the F1 console is the only copyable text surface the
        // game gives players (chat and the kick dialog are not selectable).
        // Echo the SteamID, access code and a ready-to-paste daemon command
        // line there so nobody has to hand-type a 32-char token. Console
        // history survives a kick — the player can reopen F1 at the main menu
        // and copy everything.
        // -----------------------------------------------------------------------
        private void SendTokenConsole(BasePlayer player, ulong steamId, string token)
        {
            string serverIp = GetServerIp();
            try
            {
                string[] lines =
                {
                    "----------------------------------------------------------",
                    "VAC setup — select a line, then Ctrl+C to copy:",
                    "  steamid64: " + steamId,
                    "  access code: " + token,
                    "  daemon command: ./vac-daemon " + serverIp + ":28084 " + steamId + " " + token,
                    "  magic link: http://" + serverIp + ":" + DownloadPort + "/setup?t=" + token,
                    "----------------------------------------------------------"
                };
                foreach (string line in lines)
                    ConsoleNetwork.SendClientCommand(player.net.connection, "echo", new object[] { line });
            }
            catch (Exception ex)
            {
                PrintWarning("VacIntegrity: console handoff failed for " + steamId + ": " + ex.Message);
            }
        }

        private string GetServerIp()
        {
            // Explicit override wins — inside containers, interface enumeration
            // returns the bridge IP which LAN clients cannot reach.
            try
            {
                string publicIp = Environment.GetEnvironmentVariable("VAC_PUBLIC_IP");
                if (!string.IsNullOrEmpty(publicIp))
                    return publicIp;
            }
            catch { }

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
            Puts("VacIntegrity: player " + player.displayName +
                " connected (steamid=" + player.UserIDString + ")");

            ulong steamId = player.userID;
            uint lo = (uint)(steamId & 0xFFFFFFFF);
            uint hi = (uint)((steamId >> 32) & 0xFFFFFFFF);
            byte[] nameBytes = Encoding.UTF8.GetBytes(player.displayName ?? "");

            // Register (name-only; preserves any existing enrollment token),
            // then ensure enrollment: stable per-player token persisted by the
            // native lib — installed daemons survive relogs AND server restarts.
            vac_server_register_client(lo, hi, nameBytes, nameBytes.Length, null, 0);
            string token = EnsureToken(lo, hi);
            if (token == null)
            {
                PrintWarning("VacIntegrity: failed to ensure token for " + steamId);
                return;
            }

            // Magic link: serves the OS-appropriate client package (Windows
            // installer zip, or Linux/Proton daemon zip) + a preload ini with
            // server address and access code already baked in.
            string serverIp = GetServerIp();
            string url = $"http://{serverIp}:{DownloadPort}/setup?t={token}";
            player.ChatMessage("VAC protection required: download " + url);
            player.ChatMessage("Windows: extract and run vac-setup.exe. "
                + "Linux/Proton: extract vac-linux.zip and run ./vac-daemon (use the access code below).");
            player.ChatMessage("Your access code: " + token);
            player.ChatMessage("Issues or feedback? https://github.com/text70/VAC/issues");

            // The chat lines above cannot be copied — repeat the credentials
            // into the F1 console, where text is selectable.
            SendTokenConsole(player, steamId, token);

            _graceWarned.Remove(steamId);
            _playerConnectTime[steamId] = DateTime.UtcNow;
            lock (_playerNames)
            {
                _playerNames[steamId] = player.displayName ?? steamId.ToString();
            }
        }

        private string EnsureToken(uint lo, uint hi)
        {
            byte[] buf = new byte[128];
            int n = vac_server_ensure_client_token(lo, hi, buf, buf.Length);
            if (n <= 0 || n > buf.Length)
                return null;
            return Encoding.UTF8.GetString(buf, 0, n);
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
            _graceWarned.Remove(steamId);
            lock (_playerNames)
            {
                _playerNames.Remove(steamId);
            }
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

            Puts("VacIntegrity: loaded key material from " + nativeDir);
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
                PrintWarning("VacIntegrity: module " + moduleId + " scan failed with code " + result);
                return;
            }

            Puts("VacIntegrity: module " + moduleId + " scan complete (" + len + " bytes sealed)");

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
                PrintWarning("VacIntegrity: module " + moduleId + " scan result has INVALID SIGNATURE");
                return;
            }
            if (status == 2)
            {
                PrintWarning("VacIntegrity: module " + moduleId + " scan result DECRYPTION FAILED");
                return;
            }
            if (status < 0)
            {
                PrintWarning("VacIntegrity: module " + moduleId + " vac_decrypt error code " + status);
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
                PrintWarning("VacIntegrity: MODULE " + moduleId + " FLAGGED: " + reason);
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
            Puts("VacIntegrity: shutdown complete");
        }
    }
}