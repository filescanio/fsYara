rule vjw0rm
{
    meta:
        author = "OPSWAT"
        description = "Identify JavaScript-based malware (vjw0rm)"
        vetted_family = "vjw0rm"
        score = 75

    strings:
        $signature = "Coded by v_B01" nocase
        $mutex = "HKCU\\\\vjw0rm" nocase
        $c2_ping = /(POST|GET)/ // X.open('POST','<c2>' + C, false);
        $c2_command = /=== "[a-zA-Z0-9]{2}"/ // if (P[0] === "Ex") {

    condition:
        filesize < 10KB and any of ($signature,$mutex) and $c2_ping and #c2_command > 3
}