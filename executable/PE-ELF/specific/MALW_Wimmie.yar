// source: https://github.com/Yara-Rules/rules/blob/0f93570194a80d2f2032869055808b0ddcdfb360/malware/MALW_Wimmie.yar

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule WimmieShellcode : Wimmie Family 
{
    meta:
        description = "Wimmie code features"
        author = "Seth Hardy"
        last_modified = "2014-07-17"
        vetted_family = "Wimmie"
        
    strings:
        // decryption loop
        $ = { 49 30 24 39 83 F9 00 77 F7 8D 3D 4D 10 40 00 B9 0C 03 00 00 }
        $xordecrypt = {B9 B4 1D 00 00 [8] 49 30 24 39 83 F9 00 }
        
    condition:
        any of them
}

rule WimmieStrings : Wimmie Family
{
    meta:
        description = "Strings used by Wimmie"
        author = "Seth Hardy"
        last_modified = "2014-07-17"
        vetted_family = "Wimmie"
        
    strings:
        $ = "\x00ScriptMan"
        $ = "C:\\WINDOWS\\system32\\sysprep\\cryptbase.dll" wide ascii
        $ = "ProbeScriptFint" wide ascii
        $ = "ProbeScriptKids"
        
    condition:
        any of them
}


//rule Wimmie : Family
//{
//    meta:
//        description = "Wimmie family"
//        author = "Seth Hardy"
//        last_modified = "2014-07-17"
//        vetted_family = "Wimmie"
//
//    condition:
//        WimmieShellcodes or WimmieStrings
//
//}
