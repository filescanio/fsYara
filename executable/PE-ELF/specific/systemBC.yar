
import "pe"


rule main_fn {
  meta:
        description = "Detects SystemBC initialization"
        author = "thespis"
        date = "2022-11-18"
        score = 60
  strings:
    $asm_0 = { 55 8B EC 81 C4 F4 FB FF FF 8D 4D 00 2B CC 51 8D 44 24 04 50 ?? ?? ?? ?? ?? 6A 00 6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 6A 00 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 68 00 00 10 00 ?? ?? ?? ?? ?? 89 85 F8 FB FF FF 68 ?? ?? ?? ?? 6A 00 6A 00 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? 85 C0 }
    $asm_1 = { 83 BD F8 FB FF FF 00 }
    $asm_2 = { 6A 00 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3D 00 10 00 00 }
    $asm_3 = { 68 00 01 00 00 8D 85 00 FC FF FF 50 6A 00 ?? ?? ?? ?? ?? 6A 01 6A 00 68 ?? ?? ?? ?? 8D 85 00 FC FF FF 50 6A 00 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? }
    $asm_4 = { 68 60 EA 00 00 ?? ?? ?? ?? ?? 33 C0 C9 C2 10 00 }
    $mutexname_startparam = {77 6F 77 36 34 00 73 74 61 72 74 00}
  condition:
    all of them
}


rule Mal_Backdoor_Win32_SystemBC_2021
{
    meta:
        description = "Detects Win32 SystemBC RAT"
        author = " Blackberry Threat Research team "
        date = "2021-01-06"
	score = 40
    strings:         

       $x1 = "(\"inconsistent IOB fields\", stream->_ptr - stream->_base >= 0)"
       $x2 = "f:\\vs70builds\\3077\\vc\\crtbld\\crt\\src\\sprintf.c"
       $x3 = "y:\\test4\\e93\\Debug\\e93.pdb"
       $x4 = "7 56 756 7567 5"        

    condition:
        uint16(0) == 0x5a4d and
        pe.imphash() == "18c64388b1cd2a51505e0d24460c1ed7" and
        pe.number_of_sections == 6 and
        filesize < 800KB and
        3 of ($x*)
}


/*
rule systemBC_packers
{
    meta:
        author = "thespis"
        date = "2022-11-18"
    strings:
        $hhtpreq = {70 6F 77 65 72 73 68 65 6C 6C 00 2D 57 69 6E 64 6F 77 53 74 79 6C 65 20 48 69 64 64 65 6E 20 2D 65 70 20 62 79 70 61 73 73 20 2D 66 69 6C 65 20 22 00 6E 74 64 6C 6C 2E 64 6C 6C 00 4C 64 72 4C 6F 61 64 44 6C 6C 00 47 45 54 20 25 73 20 48 54 54 50 2F 31 2E 30 0D 0A 48 6F 73 74 3A 20 25 73 0D 0A 55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 31 3B 20 57 69 6E 36 34 3B 20 78 36 34 3B 20 72 76 3A 36 36 2E 30 29 20 47 65 63 6B 6F 2F 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6F 78 2F 36 36 2E 30 0D 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 63 6C 6F 73 65}
        //$corolina = "corolina17" ascii wide
        $obfuscation_maybe = "Puvehocusegaw nomexu dawovegubiteyeg" ascii wide
        $obfuscation_maybe2 = "cimojudozuwelam" ascii wide
        $test = "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0" ascii wide
    condition:
        any of them
}
*/


rule MiniTor // modify
{
    meta:
        id = "2kfngTvJBttBM67MLYYyil"
        fingerprint = "035c4826400ab70d1fa44a6452e1c738851994d3215e8d944f33b9aa2d409fe0"
        version = "1.0"
        creation_date = "2021-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies MiniTor implementation as seen in SystemBC and Parallax RAT."
        category = "MALWARE"
        malware_type = "RAT"
        reference = "https://news.sophos.com/en-us/2020/12/16/systembc/"


    strings:
        $code1 = {55 8b ec 81 c4 f0 fd ff ff 51 57 56 8d ?? f4 2b cc 51 8d ?? ?4 10 50 e8 ?? ?? ?? 
        ?? 6a 0f 8d ?? 00 fe ff ff 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d ?? 0f fe ff ff 50 6a 14 ff 
        7? ?? e8 ?? ?? ?? ?? 8d ?? fc fd ff ff 50 8d ?? 00 fe ff ff 50 ff 7? ?? ff 7? ?? e8 ?? ?? 
        ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b b? ?? ?? ?? ?? 89 8? ?? ?? ?? ?? 68 ?? ?? ?? ?? ff b? ?? 
        ?? ?? ?? 57 e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 2b c7 03 f8 29 8? ?? ?? ?? ?? 68 ?? ?? 
        ?? ?? ff b? ?? ?? ?? ?? 57 e8 ?? ?? ?? ?? 85 c0 74 ?? 2b c7 03 f8 29 8? ?? ?? ?? ?? 68 ?? 
        ?? ?? ?? ff b? ?? ?? ?? ?? 57 e8 ?? ?? ?? ?? 85 c0 74 ?? 8b f7 83 c6 1e 8d ?? 00 fe ff ff c6}
        $code2 = {55 8b ec 81 c4 78 f8 ff ff 53 57 56 8d ?? f4 2b cc 51 8d ?? ?4 10 50 e8 ?? ?? ?? 
        ?? 68 00 00 00 f0 6a 0d 68 ?? ?? ?? ?? 6a 00 8d ?? fc 50 e8 ?? ?? ?? ?? 6a 00 6a 00 8d 05 
        ?? ?? ?? ?? 5? 8d ?? f8 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 
        ff d0 6a 00 6a 00 8d 05 ?? ?? ?? ?? 5? 8d ?? f4 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? 
        ?? ?? 50 e8 ?? ?? ?? ?? ff d0 6a 00 6a 00 8d 05 ?? ?? ?? ?? 5? 8d ?? f0 50 68 ?? ?? ?? ?? 
        e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? ff d0 6a 00 6a 20 8d 05 ?? ?? ?? ?? 5? 8d 
        05 ?? ?? ?? ?? 5? ff 7? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50}
    condition:
        any of them
}




rule SystemBC_Socks
{
    meta:
        id = "6zIY8rmud3SM6CWLPwxaky"
        fingerprint = "09472e26edd142cd68a602f1b6e31abbd4c8ec90c36d355a01692d44ef02a14f"
        score = 40
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies SystemBC RAT, Socks proxy version."
        category = "MALWARE"
        malware = "SYSTEMBC"
        malware_type = "RAT"

    strings:
        $code1 = { 68 10 27 00 00 e8 ?? ?? ?? ?? 8d ?? 72 fe ff ff 50 68 02 02 00 00 e8 ?? ?? 
    ?? ?? 85 c0 75 ?? c7 8? ?? ?? ?? ?? ?? ?? ?? ?? 8d ?? 60 fe ff ff 50 6a ff 68 ?? ?? 
    ?? ?? e8 ?? ?? ?? ?? 8d ?? 60 fe ff ff 50 e8 ?? ?? ?? ?? 89 8? ?? ?? ?? ?? ff b? ?? 
    ?? ?? ?? ff b? ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 75 ?? 81 b? ?? ?? ?? ?? ?? ?? ?? ?? 
    75 ?? c7 8? ?? ?? ?? ?? ?? ?? ?? ?? eb ?? }
        $code2 = { 55 8b ec 81 c4 d0 fe ff ff 53 57 56 8d ?? f4 2b cc 51 8d ?? ?4 10 50 e8 
    ?? ?? ?? ?? 6a 06 6a 01 6a 02 e8 ?? ?? ?? ?? 89 4? ?? 6a 04 ff 7? ?? 8d ?? fc 50 e8 
    ?? ?? ?? ?? c7 8? ?? ?? ?? ?? 01 00 00 00 6a 04 8d ?? d4 fe ff ff 50 6a 01 6a 06 ff 
    7? ?? e8 ?? ?? ?? ?? 8d ?? d8 fe ff ff 50 6a ff ff 7? ?? e8 ?? ?? ?? ?? 6a 02 8d ?? 
    d8 fe ff ff 50 e8 ?? ?? ?? ?? 89 4? ?? 8b 4? ?? 3d 00 00 01 00 76 ?? 50 e8 ?? ?? ?? ?? }
    condition:
        any of them
}

rule SystemBC_cleartext_Config
{
    meta:
        description = "Detects SystemBC Config in cleartext"
        author = "thespis"
        date = "2022-11-18"
        score = 70

    strings:
        $ = "BEGINDATA" ascii wide fullword
        $ = "HOST1:" ascii wide fullword
        $ = "HOST2:" ascii wide fullword
        $ = "PORT1:" ascii wide fullword
        $ = "TOR:" ascii wide fullword
        $ = "-WindowStyle Hidden -ep bypass -file" ascii wide
    condition:
        3 of them
}




rule win_systembc_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-12-22"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.systembc"
        malpedia_rule_date = "20201222"
        malpedia_hash = "30354d830a29f0fbd3714d93d94dea941d77a130"
        malpedia_version = "20201023"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 7408 03bd1cf4ffff ebc1 2bbd20f4ffff }
            // n = 4, score = 800
            //   7408                 | je                  0xa
            //   03bd1cf4ffff         | add                 edi, dword ptr [ebp - 0xbe4]
            //   ebc1                 | jmp                 0xffffffc3
            //   2bbd20f4ffff         | sub                 edi, dword ptr [ebp - 0xbe0]

        $sequence_1 = { eb08 8b543078 8b4c307c 8955ec }
            // n = 4, score = 800
            //   eb08                 | jmp                 0xa
            //   8b543078             | mov                 edx, dword ptr [eax + esi + 0x78]
            //   8b4c307c             | mov                 ecx, dword ptr [eax + esi + 0x7c]
            //   8955ec               | mov                 dword ptr [ebp - 0x14], edx

        $sequence_2 = { 64a130000000 8b400c 8b700c 8b5810 8b36 8b7e30 33c9 }
            // n = 7, score = 800
            //   64a130000000         | mov                 eax, dword ptr fs:[0x30]
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   8b700c               | mov                 esi, dword ptr [eax + 0xc]
            //   8b5810               | mov                 ebx, dword ptr [eax + 0x10]
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   8b7e30               | mov                 edi, dword ptr [esi + 0x30]
            //   33c9                 | xor                 ecx, ecx

        $sequence_3 = { 50 6805000020 ffb530f4ffff 68???????? e8???????? }
            // n = 5, score = 800
            //   50                   | push                eax
            //   6805000020           | push                0x20000005
            //   ffb530f4ffff         | push                dword ptr [ebp - 0xbd0]
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_4 = { 8bcf 8dbd68feffff f3a4 c647ff00 8d8568feffff 50 e8???????? }
            // n = 7, score = 800
            //   8bcf                 | mov                 ecx, edi
            //   8dbd68feffff         | lea                 edi, [ebp - 0x198]
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   c647ff00             | mov                 byte ptr [edi - 1], 0
            //   8d8568feffff         | lea                 eax, [ebp - 0x198]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_5 = { 68???????? 50 e8???????? ffd0 6a00 }
            // n = 5, score = 800
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   ffd0                 | call                eax
            //   6a00                 | push                0

        $sequence_6 = { e8???????? ffd0 6a00 6a00 6a00 6a00 ffb530f4ffff }
            // n = 7, score = 800
            //   e8????????           |                     
            //   ffd0                 | call                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ffb530f4ffff         | push                dword ptr [ebp - 0xbd0]

        $sequence_7 = { 50 ffd2 8b85bcfbffff 8b08 8b5108 50 ffd2 }
            // n = 7, score = 800
            //   50                   | push                eax
            //   ffd2                 | call                edx
            //   8b85bcfbffff         | mov                 eax, dword ptr [ebp - 0x444]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b5108               | mov                 edx, dword ptr [ecx + 8]
            //   50                   | push                eax
            //   ffd2                 | call                edx

        $sequence_8 = { 55 8bec 53 57 56 ff7508 }
            // n = 6, score = 800
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   53                   | push                ebx
            //   57                   | push                edi
            //   56                   | push                esi
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_9 = { 8b45f8 8b08 8b9180000000 50 }
            // n = 4, score = 800
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b9180000000         | mov                 edx, dword ptr [ecx + 0x80]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 57344
}
