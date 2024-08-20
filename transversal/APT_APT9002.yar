// source: https://github.com/Yara-Rules/rules/blob/0f93570194a80d2f2032869055808b0ddcdfb360/malware/APT_APT9002.yar

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

private rule APT9002Code 
{
    
    meta:
        description = "9002 code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        // start code block
        $ = { B9 7A 21 00 00 BE ?? ?? ?? ?? 8B F8 ?? ?? ?? F3 A5 }
        // decryption from other variant with multiple start threads
        $ = { 8A 14 3E 8A 1C 01 32 DA 88 1C 01 8B 54 3E 04 40 3B C2 72 EC }

    condition:
        any of them
}

private rule APT9002Strings
{
    
    meta:
        description = "9002 Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "POST http://%ls:%d/%x HTTP/1.1"
        $ = "%%TEMP%%\\%s_p.ax" wide ascii
        $ = "%TEMP%\\uid.ax" wide ascii
        $ = "%%TEMP%%\\%s.ax" wide ascii
        // also triggers on surtr $ = "mydll.dll\x00DoWork"
        $ = "sysinfo\x00sysbin01"
        $ = "\\FlashUpdate.exe"

    condition:
       any of them
}

rule APT9002 
{
    
    meta:
        description = "9002"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        score = 50
        
    condition:
        APT9002Code or APT9002Strings
}

rule FE_APT_9002
{
    
    meta:
        Author      = "FireEye Labs"
        Date        = "2013/11/10"
        Description = "Strings inside"
        Reference   = "Useful link"
        score = 50
        
    strings:
        $mz = { 4d 5a }
        $a = "rat_UnInstall" wide ascii

    condition:
        ($mz at 0) and $a
}
