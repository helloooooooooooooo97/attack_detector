/*
 * Behinder (ice scorpion) webshell artifact rules.
 *
 * These scan the SERVER-SIDE artifacts (the deployed JSP webshell and the
 * memory-shell injection template), not the encrypted traffic. They were
 * derived from the official client source (MountCloud/BehinderClientSource)
 * and the default AES shell shipped with Behinder v4.0.7.
 *
 * Evasion notes:
 *  - the AES key e45e329feb5d925b is md5("rebeyond")[:16]; changing the
 *    password changes the key, so rules on the fixed key can be bypassed.
 *  - the class-loader + reflection skeleton is the more stable part.
 */

rule Behinder_DefaultAES_JSP_Webshell
{
    meta:
        description = "Behinder default AES JSP webshell (file-based)"
        author      = "lab"
        date        = "2026-08-10"
        reference   = "https://www.viewintech.com/detail?id=208"
        severity    = "high"
    strings:
        $a = "e45e329feb5d925b" ascii
        $b = "AES/ECB/PKCS5Padding" ascii
        $c = "super.defineClass" ascii
        $d = "request.getMethod().equals(\"POST\")" ascii
        $e = "java.util.Base64" ascii
    condition:
        // JSP files start with <%@
        filesize < 200KB and uint16(0) == 0x253C and 3 of them
}

rule Behinder_MemoryShell_JavaTemplate
{
    meta:
        description = "Behinder memory-shell injection template (JVM Agent as Servlet/Filter/Listener)"
        author      = "lab"
        date        = "2026-08-10"
        reference   = "Constants.shellCode in Behinder client source"
        severity    = "high"
    strings:
        $a = "pathPattern" ascii
        $b = "session.putValue(\"u\",k)" ascii
        $c = "defineMethod.setAccessible(true)" ascii
        $d = "e45e329feb5d925b" ascii
        $e = "getSystemClassLoader" ascii
        $f = "request.getRequestURI().matches(pathPattern)" ascii
    condition:
        4 of them
}

rule Behinder_ClientPayload_ClassBytes
{
    meta:
        description = "Behinder runtime payload class bytecode (sent over the wire, visible in memory dumps / fileless artifacts)"
        author      = "lab"
        date        = "2026-08-10"
        severity    = "medium"
    strings:
        $a = { CA FE BA BE }                 // class magic
        $b = "whatever" ascii
        $c = "e45e329feb5d925b" ascii
    condition:
        $a at 0 and filesize < 64KB and 2 of them
}
