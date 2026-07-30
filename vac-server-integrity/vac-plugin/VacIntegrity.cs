using System;
using System.IO;
using System.Runtime.InteropServices;
using Carbon.Plugins;

namespace Carbon.Plugins
{
    [Info("VacIntegrity", "VAC Team", "1.0.0")]
    [Description("Server integrity monitoring and client anti-cheat coordinator")]
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

        // -----------------------------------------------------------------------
        // Ring-0 cheat detection callback (set by vac_server_set_kick_callback)
        // -----------------------------------------------------------------------

        // Delegate matching the C function pointer signature:
        //   void callback(uint32_t steam_id_lo, uint32_t steam_id_hi, const char* reason)
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void CheatDetectedCallback(
            uint steamIdLo, uint steamIdHi, IntPtr reason
        );

        [DllImport("libvac_integrity", CallingConvention = CallingConvention.Cdecl)]
        private static extern int vac_server_set_kick_callback(IntPtr callback);

        [DllImport("libvac_integrity", CallingConvention = CallingConvention.Cdecl)]
        private static extern int vac_server_listener_register_client_scan_event(IntPtr callback);

        // -----------------------------------------------------------------------
        // Plugin state
        // -----------------------------------------------------------------------

        private byte[] _kyberPk;
        private byte[] _kyberSk;
        private byte[] _mldsa65Sk;
        private byte[] _mldsa65Pk;

        private const int ScanBufferSize = 12617;
        private const int MaxUints = 2048;

        // Keep the delegate alive so the GC doesn't collect it
        private static CheatDetectedCallback _cheatCallback;

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

            // Register the ring-0 cheat detection callback
            _cheatCallback = new CheatDetectedCallback(OnCheatDetected);
            IntPtr cbPtr = Marshal.GetFunctionPointerForDelegate(_cheatCallback);
            vac_server_set_kick_callback(cbPtr);

            // Start daemon TCP listener on port 28084
            int listenerResult = vac_server_listener_start(28084);
            if (listenerResult != 0)
            {
                Logger.Warn("VacIntegrity: listener start failed with code " + listenerResult);
            }
            else
            {
                Logger.Log("VacIntegrity: daemon listener on port 28084");
            }

            // Schedule scans at configurable intervals
            timer.Every(60, () => RunScan(1));
            timer.Every(120, () => RunScan(2));
            timer.Every(300, () => RunScan(3));
            timer.Every(600, () => RunScan(4));
            timer.Every(600, () => RunScan(5));
            timer.Every(60, () => RunScan(6));
        }

        // -----------------------------------------------------------------------
        // Ring-0 cheat detection callback (called from Rust via FFI)
        // -----------------------------------------------------------------------

        // This is decorated so Rust's FFI can call it directly.
        // The signature must match CheatDetectedCallback.
        private static void OnCheatDetected(uint steamIdLo, uint steamIdHi, IntPtr reasonPtr)
        {
            ulong steamId = ((ulong)steamIdHi << 32) | steamIdLo;
            string reason = Marshal.PtrToStringAnsi(reasonPtr) ?? "Unknown";

            Console.WriteLine($"[VacIntegrity] CHEAT DETECTED steam_id={steamId}: {reason}");

            // Find the player by Steam ID and enforce ban
            BasePlayer player = BasePlayer.FindByID(steamId);
            if (player != null && player.isConnected)
            {
                // Kick
                player.Kick("VAC: " + reason);
                Console.WriteLine($"[VacIntegrity] Kicked {player.displayName} ({steamId}): {reason}");

                // Ban via server users
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
                // Player may have already disconnected — ban by Steam ID anyway
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

            // Register with daemon listener
            ulong steamId = player.userID;
            uint lo = (uint)(steamId & 0xFFFFFFFF);
            uint hi = (uint)((steamId >> 32) & 0xFFFFFFFF);
            byte[] nameBytes = System.Text.Encoding.UTF8.GetBytes(player.displayName ?? "");
            vac_server_register_client(lo, hi, nameBytes, nameBytes.Length);
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

            // Trim buffer to actual data written
            byte[] sealedData = new byte[len];
            Array.Copy(buffer, sealedData, len);

            // Decrypt and verify locally
            AnalyzeScanResult(sealedData, moduleId);
        }

        // -----------------------------------------------------------------------
        // Scan result analysis + kick/ban enforcement
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

            // Analyze based on module type
            bool flagged = false;
            string reason = "";

            switch (moduleId)
            {
                case 1: // SystemInfo
                    if (output.Length > 27 && (output[23] & 1) == 1)
                    {
                        flagged = true;
                        reason = "Kernel debugger detected";
                    }
                    break;

                case 2: // ProcessHandleList
                    if (output.Length > 6 && output[6] > 0)
                    {
                        flagged = true;
                        reason = "Suspicious processes detected: " + output[6] + " flagged";
                    }
                    break;

                case 3: // ProcessMonitor
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
            vac_server_listener_stop();
            vac_shutdown();
            Logger.Log("VacIntegrity: shutdown complete");
        }
    }
}
