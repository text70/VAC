// Compile-time stub for the Carbon-runtime game assembly (Assembly-CSharp.dll).
//
// The real Assembly-CSharp.dll is generated at runtime by Carbon when
// DeveloperMode is enabled in carbon/config.json (publicized game assembly).
// It cannot be shipped or downloaded. This stub only mirrors the members
// VacIntegrity.cs actually uses, so the plugin compiles locally for linting.
//
// Rebuild the stub with:
//   mcs -target:library -out:refs/Assembly-CSharp.dll refs/Assembly-CSharpStub.cs

using System;

namespace ConVar
{
    public static class Server
    {
        public static string ip = "0.0.0.0";
    }
}

public class BasePlayer
{
    public ulong userID;
    public string UserIDString = "";
    public string displayName = "";
    public bool IsConnected = false;

    public void Kick(string reason) { }
    public void ChatMessage(string message) { }

    public static BasePlayer FindByID(ulong userId)
    {
        return null;
    }
}

public class ServerUsers
{
    public enum UserGroup
    {
        Owner,
        Moderator,
        Banned,
        SkipQueue
    }

    public static void Set(ulong steamid, UserGroup group, string name, string reason) { }
}
