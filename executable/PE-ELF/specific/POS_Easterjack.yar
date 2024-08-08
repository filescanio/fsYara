//source: https://github.com/Yara-Rules/rules/blob/master/malware/POS_Easterjack.yar
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
rule easterjackpos {
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-09-02"
        description = "Identify JackPOS"
        score = 70
	strings:
	    $s1 = "updateinterval="
        $s2 = "cardinterval="
        $s3 = "{[!17!]}{[!18!]}"
    condition:
        all of them
}
