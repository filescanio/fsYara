private rule win_amadey_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.amadey."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.amadey"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { ebb0 b8???????? 83c410 5b }
            // n = 4, score = 700
            //   ebb0                 | jmp                 0xffffffb2
            //   b8????????           |
            //   83c410               | add                 esp, 0x10
            //   5b                   | pop                 ebx

        $sequence_1 = { e8???????? 89c2 8b45f4 89d1 ba00000000 f7f1 }
            // n = 6, score = 700
            //   e8????????           |
            //   89c2                 | mov                 edx, eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   89d1                 | mov                 ecx, edx
            //   ba00000000           | mov                 edx, 0
            //   f7f1                 | div                 ecx

        $sequence_2 = { c744240805000000 c744240402000000 890424 e8???????? }
            // n = 4, score = 700
            //   c744240805000000     | mov                 dword ptr [esp + 8], 5
            //   c744240402000000     | mov                 dword ptr [esp + 4], 2
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |

        $sequence_3 = { c9 c3 55 89e5 81ecc8010000 }
            // n = 5, score = 700
            //   c9                   | leave
            //   c3                   | ret
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   81ecc8010000         | sub                 esp, 0x1c8

        $sequence_4 = { c70424???????? e8???????? 8b45fc 89442408 c7442404???????? 8b4508 890424 }
            // n = 7, score = 700
            //   c70424????????       |
            //   e8????????           |
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   c7442404????????     |
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   890424               | mov                 dword ptr [esp], eax

        $sequence_5 = { c744240800020000 8d85f8fdffff 89442404 891424 e8???????? 83ec20 }
            // n = 6, score = 700
            //   c744240800020000     | mov                 dword ptr [esp + 8], 0x200
            //   8d85f8fdffff         | lea                 eax, [ebp - 0x208]
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   891424               | mov                 dword ptr [esp], edx
            //   e8????????           |
            //   83ec20               | sub                 esp, 0x20

        $sequence_6 = { c70424???????? e8???????? 890424 e8???????? 84c0 7407 c745fc05000000 }
            // n = 7, score = 700
            //   c70424????????       |
            //   e8????????           |
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |
            //   84c0                 | test                al, al
            //   7407                 | je                  9
            //   c745fc05000000       | mov                 dword ptr [ebp - 4], 5

        $sequence_7 = { 83ec04 8945f4 837df400 7454 8b4508 890424 }
            // n = 6, score = 700
            //   83ec04               | sub                 esp, 4
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   837df400             | cmp                 dword ptr [ebp - 0xc], 0
            //   7454                 | je                  0x56
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   890424               | mov                 dword ptr [esp], eax

        $sequence_8 = { 83fa10 722f 8b8d78feffff 42 }
            // n = 4, score = 600
            //   83fa10               | cmp                 edx, 0x10
            //   722f                 | jb                  0x31
            //   8b8d78feffff         | mov                 ecx, dword ptr [ebp - 0x188]
            //   42                   | inc                 edx

        $sequence_9 = { 8b8d78feffff 42 8bc1 81fa00100000 7214 8b49fc }
            // n = 6, score = 600
            //   8b8d78feffff         | mov                 ecx, dword ptr [ebp - 0x188]
            //   42                   | inc                 edx
            //   8bc1                 | mov                 eax, ecx
            //   81fa00100000         | cmp                 edx, 0x1000
            //   7214                 | jb                  0x16
            //   8b49fc               | mov                 ecx, dword ptr [ecx - 4]

        $sequence_10 = { 68???????? e8???????? 8d4dcc e8???????? 83c418 }
            // n = 5, score = 600
            //   68????????           |
            //   e8????????           |
            //   8d4dcc               | lea                 ecx, [ebp - 0x34]
            //   e8????????           |
            //   83c418               | add                 esp, 0x18

        $sequence_11 = { 68???????? e8???????? 8d4db4 e8???????? 83c418 }
            // n = 5, score = 500
            //   68????????           |
            //   e8????????           |
            //   8d4db4               | lea                 ecx, [ebp - 0x4c]
            //   e8????????           |
            //   83c418               | add                 esp, 0x18

        $sequence_12 = { 52 6a02 6a00 51 ff75f8 ff15???????? ff75f8 }
            // n = 7, score = 500
            //   52                   | push                edx
            //   6a02                 | push                2
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |
            //   ff75f8               | push                dword ptr [ebp - 8]

        $sequence_13 = { 8bce e8???????? e8???????? 83c418 e8???????? e9???????? 52 }
            // n = 7, score = 500
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |
            //   e8????????           |
            //   83c418               | add                 esp, 0x18
            //   e8????????           |
            //   e9????????           |
            //   52                   | push                edx

        $sequence_14 = { c705????????0c000000 eb31 c705????????0d000000 eb25 83f901 750c }
            // n = 6, score = 500
            //   c705????????0c000000     |
            //   eb31                 | jmp                 0x33
            //   c705????????0d000000     |
            //   eb25                 | jmp                 0x27
            //   83f901               | cmp                 ecx, 1
            //   750c                 | jne                 0xe

        $sequence_15 = { 50 68???????? 83ec18 8bcc 68???????? e8???????? }
            // n = 6, score = 500
            //   50                   | push                eax
            //   68????????           |
            //   83ec18               | sub                 esp, 0x18
            //   8bcc                 | mov                 ecx, esp
            //   68????????           |
            //   e8????????           |

        $sequence_16 = { 8bcc 68???????? e8???????? 8d8d78feffff e8???????? 83c418 }
            // n = 6, score = 500
            //   8bcc                 | mov                 ecx, esp
            //   68????????           |
            //   e8????????           |
            //   8d8d78feffff         | lea                 ecx, [ebp - 0x188]
            //   e8????????           |
            //   83c418               | add                 esp, 0x18

        $sequence_17 = { c78584fdffff0f000000 c68570fdffff00 83fa10 722f 8b8d58fdffff 42 }
            // n = 6, score = 400
            //   c78584fdffff0f000000     | mov    dword ptr [ebp - 0x27c], 0xf
            //   c68570fdffff00       | mov                 byte ptr [ebp - 0x290], 0
            //   83fa10               | cmp                 edx, 0x10
            //   722f                 | jb                  0x31
            //   8b8d58fdffff         | mov                 ecx, dword ptr [ebp - 0x2a8]
            //   42                   | inc                 edx

        $sequence_18 = { c78520fdffff00000000 c78524fdffff0f000000 c68510fdffff00 83fa10 722f }
            // n = 5, score = 400
            //   c78520fdffff00000000     | mov    dword ptr [ebp - 0x2e0], 0
            //   c78524fdffff0f000000     | mov    dword ptr [ebp - 0x2dc], 0xf
            //   c68510fdffff00       | mov                 byte ptr [ebp - 0x2f0], 0
            //   83fa10               | cmp                 edx, 0x10
            //   722f                 | jb                  0x31

        $sequence_19 = { 51 e8???????? 83c408 8b950cfdffff c78520fdffff00000000 c78524fdffff0f000000 }
            // n = 6, score = 400
            //   51                   | push                ecx
            //   e8????????           |
            //   83c408               | add                 esp, 8
            //   8b950cfdffff         | mov                 edx, dword ptr [ebp - 0x2f4]
            //   c78520fdffff00000000     | mov    dword ptr [ebp - 0x2e0], 0
            //   c78524fdffff0f000000     | mov    dword ptr [ebp - 0x2dc], 0xf

    condition:
        7 of them and filesize < 529408
}

private rule Amadey
 {
    meta:
        author = "kevoreilly"
        description = "Amadey Payload"
        cape_type = "Amadey Payload"
        hash = "988258716d5296c1323303e8fe4efd7f4642c87bfdbe970fe9a3bb3f410f70a4"
    strings:
        $decode1 = {8B D1 B8 FF FF FF 7F D1 EA 2B C2 3B C8 76 07 BB FF FF FF 7F EB 08 8D 04 0A 3B D8 0F 42 D8}
        $decode2 = {33 D2 8B 4D ?? 8B C7 F7 F6 8A 84 3B [4] 2A 44 0A 01 88 87 [4] 47 8B 45 ?? 8D 50 01}
        $decode3 = {8A 04 02 88 04 0F 41 8B 7D ?? 8D 42 01 3B CB 7C}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

private rule Amadey2 {
    meta:
        author = "ditekSHen"
        description = "Amadey downloader payload"
        cape_type = "Amadey Payload"
    strings:
        $s1 = "_ZZ14aGetProgramDirvE11UsersDirRes" fullword ascii
        $s2 = "_libshell32_a" ascii
        $s3 = "_ShellExecuteExA@4" ascii
        $s4 = "aGetTempDirvE10TempDirRes" ascii
        $s5 = "aGetHostNamevE7InfoBuf" ascii
        $s6 = "aCreateProcessPc" ascii
        $s7 = "aGetHostNamev" ascii
        $s8 = "aGetSelfDestinationiE22aGetSelfDestinationRes" ascii
        $s9 = "aGetSelfPathvE15aGetSelfPathRes" ascii
        $s10 = "aResolveHostPcE15aResolveHostRes" ascii
        $s11 = "aUrlMonDownloadPcS" ascii
        $s12 = "aWinSockPostPcS_S_" ascii
        $s13 = "aCreateProcessPc" ascii

        $v1 = "hii^" fullword ascii
        $v2 = "plugins/" fullword ascii
        $v3 = "ProgramData\\" fullword ascii
        $v4 = "&unit=" fullword ascii
        $v5 = "runas" fullword ascii wide
        $v6 = "Microsoft Internet Explorer" fullword wide
        $v7 = "stoi argument" ascii

        $av1 = "AVAST Software" fullword ascii
        $av2 = "Avira" fullword ascii
        $av3 = "Kaspersky Lab" fullword ascii
        $av4 = "ESET" fullword ascii
        $av5 = "Panda Security" fullword ascii
        $av6 = "Doctor Web" fullword ascii
        $av7 = "360TotalSecurity" fullword ascii
        $av8 = "Bitdefender" fullword ascii
        $av9 = "Norton" fullword ascii
        $av10 = "Sophos" fullword ascii
        $av11 = "Comodo" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or (6 of ($v*) and 2 of ($av*)))
}

private rule Windows_Trojan_Amadey_7abb059b {
    meta:
        author = "Elastic Security"
        id = "7abb059b-4001-4eec-8185-1e0497e15062"
        fingerprint = "686ae7cf62941d7db051fa8c45f0f7a27440fa0fdc5f0919c9667dfeca46ca1f"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Amadey"
        reference_sample = "33e6b58ce9571ca7208d1c98610005acd439f3e37d2329dae8eb871a2c4c297e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 18 83 78 14 10 72 02 8B 00 6A 01 6A 00 6A 00 6A 00 6A 00 56 }
    condition:
        all of them
}

private rule Windows_Trojan_Amadey_c4df8d4a {
    meta:
        author = "Elastic Security"
        id = "c4df8d4a-01f4-466f-8225-7c7f462b29e7"
        fingerprint = "4623c591ea465e23f041db77dc68ddfd45034a8bde0f20fd5fbcec060851200c"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Amadey"
        reference_sample = "9039d31d0bd88d0c15ee9074a84f8d14e13f5447439ba80dd759bf937ed20bf2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "D:\\Mktmp\\NL1\\Release\\NL1.pdb" fullword
    condition:
        all of them
}

private rule win_amadey_a9f4 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-11-17"
        description               = "matches unpacked Amadey samples"
        hash_md5                  = "25cfcfdb6d73d9cfd88a5247d4038727"
        hash_sha1                 = "912d1ef61750bc622ee069cdeed2adbfe208c54d"
        hash_sha256               = "03effd3f94517b08061db014de12f8bf01166a04e93adc2f240a6616bb3bd29a"
        malpedia_family           = "win.amadey"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "25cfcfdb6d73d9cfd88a5247d4038727"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "a9f41cd4-3f67-42fc-b310-e9b251c95fe4"

    strings:
        $pdb  = "\\Amadey\\Release\\Amadey.pdb"
        /*  Amadey uses multiple hex strings to decrypt the strings, C2 traffic
            and as identification. The preceeding string 'stoi ...' is added to
            improve performance.
        */
        $keys = /stoi argument out of range\x00\x00[a-f0-9]{32}\x00{1,16}[a-f0-9]{32}\x00{1,4}[a-f0-9]{6}\x00{1,4}[a-f0-9]{32}\x00/

    condition:
        uint16(0) == 0x5A4D and
        (
            $pdb or $keys
        )
}



private rule PWS_Win32_Amadey_GG_MTB {
	meta:
		description = "PWS:Win32/Amadey.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 09 00 00 0a 00 "

	strings :
		$a_80_0 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 55 70 6c 6f 61 64 6f 72 } //User-Agent: Uploador  01 00
		$a_80_1 = {73 63 72 3d 75 70 } //scr=up  01 00
		$a_80_2 = {78 25 2e 32 78 25 2e 32 78 25 2e 32 78 25 2e 32 78 25 2e 32 78 25 2e 32 78 } //x%.2x%.2x%.2x%.2x%.2x%.2x  01 00
		$a_80_3 = {6e 61 6d 65 3d 22 64 61 74 61 22 } //name="data"  01 00
		$a_80_4 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 } //Content-Disposition: form-data  01 00
		$a_80_5 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6f 63 74 65 74 2d 73 74 72 65 61 6d } //Content-Type: application/octet-stream  01 00
		$a_80_6 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 6d 75 6c 74 69 70 61 72 74 2f 66 6f 72 6d 2d 64 61 74 61 } //Content-Type: multipart/form-data  01 00
		$a_80_7 = {43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65 } //Connection: Keep-Alive  01 00
		$a_80_8 = {43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a } //Content-Length:  00 00
	condition:
		any of ($a_*)

}
private rule PWS_Win32_Amadey_GG_MTB_2 {
	meta:
		description = "PWS:Win32/Amadey.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0e 00 00 01 00 "

	strings :
		$a_80_0 = {4f 75 74 6c 6f 6f 6b } //Outlook  01 00
		$a_80_1 = {49 4d 41 50 20 50 61 73 73 77 6f 72 64 } //IMAP Password  01 00
		$a_80_2 = {50 4f 50 33 20 50 61 73 73 77 6f 72 64 } //POP3 Password  01 00
		$a_80_3 = {3c 70 61 73 73 77 6f 72 64 3e } //<password>  01 00
		$a_80_4 = {3c 50 61 73 73 20 65 6e 63 6f 64 69 6e 67 3d 22 62 61 73 65 36 34 22 3e } //<Pass encoding="base64">  01 00
		$a_80_5 = {50 69 64 67 69 6e } //Pidgin  01 00
		$a_80_6 = {5c 46 69 6c 65 5a 69 6c 6c 61 5c 73 69 74 65 6d 61 6e 61 67 65 72 2e 78 6d 6c } //\FileZilla\sitemanager.xml  01 00
		$a_80_7 = {5c 2e 70 75 72 70 6c 65 5c 61 63 63 6f 75 6e 74 73 2e 78 6d 6c } //\.purple\accounts.xml  01 00
		$a_80_8 = {5c 57 63 78 5f 66 74 70 2e 69 6e 69 } //\Wcx_ftp.ini  01 00
		$a_80_9 = {5c 77 69 6e 73 63 70 2e 69 6e 69 } //\winscp.ini  01 00
		$a_80_10 = {52 65 61 6c 56 4e 43 } //RealVNC  01 00
		$a_80_11 = {54 69 67 68 74 56 4e 43 } //TightVNC  01 00
		$a_80_12 = {50 61 73 73 77 6f 72 64 3d } //Password=  01 00
		$a_80_13 = {43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a } //Content-Length:  00 00
	condition:
		any of ($a_*)

}
private rule PWS_Win32_Amadey_GG_MTB_3 {
	meta:
		description = "PWS:Win32/Amadey.GG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "

	strings :
		$a_01_0 = {89 95 ec fe ff ff 8b 95 ec fe ff ff 0f b6 84 15 f8 fe ff ff 8b 8d f0 fe ff ff 0f b6 94 0d f8 fe ff ff 33 d0 89 95 d8 fd ff ff 8b 85 f0 fe ff ff 8a 8d d8 fd ff ff 88 8c 05 f8 fe ff ff 0f b6 95 d8 fd ff ff 8b 85 ec fe ff ff 0f b6 8c 05 f8 fe ff ff 33 ca 89 8d d4 fd ff ff 8b 95 ec fe ff ff 8a 85 d4 fd ff ff 88 84 15 f8 fe ff ff 0f b6 8d d4 fd ff ff 8b 95 f0 fe ff ff 0f b6 84 15 f8 fe ff ff 33 c1 8b 8d f0 fe ff ff 88 84 0d f8 fe ff ff e9 } //00 00
	condition:
		any of ($a_*)

}


private rule win_amadey_bytecodes_oct_2023
 {
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/10/15"
		description = "Detects bytecodes present in Amadey Bot malware"
		sha256 = "4165190e60ad5abd437c7768174b12748d391b8b97c874b5bdf8d025c5e17f43"

	strings:
		$s1 = {8b ?? fc 83 c1 23 2b c2 83 c0 fc 83 f8 1f 77}
		$s2 = {80 ?? ?? ?? 3d 75 }
		$s3 = {8b c1 c1 f8 10 88 ?? ?? 8b c1 c1 f8 08}

	condition:

		$s1 and $s2 and $s3


}


rule fsAmadey {
    meta:
        description = "FsYARA - Malware Trends"
        vetted_family = "amadey"

    condition:
        win_amadey_auto or Amadey or Amadey2 or Windows_Trojan_Amadey_7abb059b or Windows_Trojan_Amadey_c4df8d4a or win_amadey_a9f4 or PWS_Win32_Amadey_GG_MTB or PWS_Win32_Amadey_GG_MTB_2 or PWS_Win32_Amadey_GG_MTB_3 or win_amadey_bytecodes_oct_2023
}
