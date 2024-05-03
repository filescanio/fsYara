private rule win_risepro_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.risepro."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.risepro"
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
        $sequence_0 = { 0fb645ff 50 8b4de8 e8???????? 8b4dec 83c901 894dec }
            // n = 7, score = 100
            //   0fb645ff             | movzx               eax, byte ptr [ebp - 1]
            //   50                   | push                eax
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   e8????????           |
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   83c901               | or                  ecx, 1
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx

        $sequence_1 = { e8???????? 8945c8 8d4d0c e8???????? 8945cc 8d45d7 50 }
            // n = 7, score = 100
            //   e8????????           |
            //   8945c8               | mov                 dword ptr [ebp - 0x38], eax
            //   8d4d0c               | lea                 ecx, [ebp + 0xc]
            //   e8????????           |
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   8d45d7               | lea                 eax, [ebp - 0x29]
            //   50                   | push                eax

        $sequence_2 = { 8bec 83ec0c 8955f8 894dfc 8b4dfc e8???????? 8bc8 }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   83ec0c               | sub                 esp, 0xc
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   e8????????           |
            //   8bc8                 | mov                 ecx, eax

        $sequence_3 = { 894214 8b4df8 e8???????? 8945d4 837de010 }
            // n = 5, score = 100
            //   894214               | mov                 dword ptr [edx + 0x14], eax
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   e8????????           |
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   837de010             | cmp                 dword ptr [ebp - 0x20], 0x10

        $sequence_4 = { 8bcc 8965bc 8d552c 52 e8???????? 8945b8 c645fc04 }
            // n = 7, score = 100
            //   8bcc                 | mov                 ecx, esp
            //   8965bc               | mov                 dword ptr [ebp - 0x44], esp
            //   8d552c               | lea                 edx, [ebp + 0x2c]
            //   52                   | push                edx
            //   e8????????           |
            //   8945b8               | mov                 dword ptr [ebp - 0x48], eax
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4

        $sequence_5 = { 33c0 8885eafeffff 33c9 888de9feffff }
            // n = 4, score = 100
            //   33c0                 | xor                 eax, eax
            //   8885eafeffff         | mov                 byte ptr [ebp - 0x116], al
            //   33c9                 | xor                 ecx, ecx
            //   888de9feffff         | mov                 byte ptr [ebp - 0x117], cl

        $sequence_6 = { 6800000080 680000cf00 68???????? 68???????? 6800020000 ff15???????? 89859cfeffff }
            // n = 7, score = 100
            //   6800000080           | push                0x80000000
            //   680000cf00           | push                0xcf0000
            //   68????????           |
            //   68????????           |
            //   6800020000           | push                0x200
            //   ff15????????         |
            //   89859cfeffff         | mov                 dword ptr [ebp - 0x164], eax

        $sequence_7 = { 6886e4fa74 6829895415 e8???????? 8b4dfc 894108 89510c }
            // n = 6, score = 100
            //   6886e4fa74           | push                0x74fae486
            //   6829895415           | push                0x15548929
            //   e8????????           |
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   894108               | mov                 dword ptr [ecx + 8], eax
            //   89510c               | mov                 dword ptr [ecx + 0xc], edx

        $sequence_8 = { 33c5 8945ec 56 50 8d45f4 64a300000000 894da8 }
            // n = 7, score = 100
            //   33c5                 | xor                 eax, ebp
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   56                   | push                esi
            //   50                   | push                eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   894da8               | mov                 dword ptr [ebp - 0x58], ecx

        $sequence_9 = { 85ff 780f 3b3d???????? 7307 }
            // n = 4, score = 100
            //   85ff                 | test                edi, edi
            //   780f                 | js                  0x11
            //   3b3d????????         |
            //   7307                 | jae                 9

    condition:
        7 of them and filesize < 280576
}


private rule Trojan_Win32_RisePro_DB_ {
	meta:
		description = "Trojan:Win32/RisePro.DB!!Risepro.gen!MTB,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "

	strings :
		$a_81_0 = {54 65 6c 65 67 72 61 6d 3a 20 68 74 74 70 73 3a 2f 2f 74 2e 6d 65 2f 52 69 73 65 50 72 6f 53 55 50 50 4f 52 54 } //01 00  Telegram: https://t.me/RiseProSUPPORT
		$a_81_1 = {69 70 69 6e 66 6f 2e 69 6f } //01 00  ipinfo.io
		$a_81_2 = {6d 61 78 6d 69 6e 64 2e 63 6f 6d 2f 65 6e 2f 6c 6f 63 61 74 65 2d 6d 79 2d 69 70 2d 61 64 64 72 65 73 73 } //00 00  maxmind.com/en/locate-my-ip-address
	condition:
		any of ($a_*)

}

import "hash"
private rule RiseProStealer {
    meta:
    author = "Kerime Gencay"
    description = "RisePro Stealer Rule"
    file_name = "RAIDXpert2.exe"
    hash = "7d907dfb44d87310fcd5d7725166491e"
strings:
    $str1 = "StealerClient.exe"
    //$str2 = "InitCommonControls"
    $str3 = "ihwlqgah"
    $str4 = "NTA0dJ"
    $str5 = "F0d2(9k"

    $opc1 = {69 68 77 6C 71 67 61 68}
    $opc2 = {61 74 01 74 24 E4 47 5C 06 7B 3E 6C 33 2B 02 53}

condition:
    uint16(0) == 0x5A4D and (2 of ($str*,$opc*))
}

private rule risepro {
    meta:
        author      = "c3rb3ru5d3d53c"
        description = "Detects RisePro"
        hash        = "2cd2f077ca597ad0ef234a357ea71558d5e039da9df9958d0b8bd0efa92e74c9"
        created     = "2023-06-18"
        os          = "windows"
        tlp         = "white"
        rev         = 1
    strings:
        $trait_0 = {
            8b ff 55 8b ec 83 ec 28 8d 4d ?? 56 57 6a 00 e8
            d6 f5 ff ff 8d 45 ?? 50 ff 75 ?? e8 b7 f9 ff ff
            59 59 8d 4d ?? 8b f0 8b fa e8 04 f6 ff ff 8b d7
            8b c6 5f 5e c9 c3}
        $trait_2 = {
            8b c7 83 ff 40 99 89 46 ?? 6a 3f 58 0f 4d f8 89
            56 ?? 8b 55 ?? 33 c0 33 c9 0f ab f8 83 ff 20 0f
            43 c8 33 c1 83 ff 40 0f 43 c8 09 44 1a ?? 09 4c
            1a ?? 66 83 4e ?? ?? 5f 8b c6 5e 5b c9 c3}
        $trait_4 = {
            8b 45 ?? 0f b7 c0 8d 04 48 0f b6 4c 1f ?? 89 45
            ?? 8b 45 ?? 0f b7 c0 83 c0 fc 66 c1 e1 08 89 45
            ?? 0f b6 44 1f ?? 66 0b c8 0f b6 44 1f ?? 66 03
            45 ?? 0f b7 c9 0f b7 d0 66 85 c9 74 69}
        $trait_5 = {
            8b 43 ?? 56 0f b7 73 ?? 2b d6 0f b7 48 ?? 8b c2
            33 d2 83 e9 04 f7 f1 0f b7 43 ?? 03 d6 3b d0 6a
            04 0f 47 d6 59 03 d1 5e 2b 7d ?? 03 d7 3b d1 5f
            0f 42 d1 66 8b c2 5b c9 c3}
        $trait_6 = {
            8a 4d ?? 8a 45 ?? 8a 55 ?? 8b 7d ?? c0 e9 04 80
            e1 03 c0 e0 02 02 c8 8a 45 ?? 88 4d ?? 8a ca c0
            e9 02 80 e1 0f c0 e0 04 c0 e2 06 02 c8 02 55 ??
            4b 88 4d ?? 88 55 ?? 85 db 7e 24}
        $trait_7 = {
            89 75 ?? ff 75 ?? e8 9b 0d 00 00 59 89 75 ?? ff
            75 ?? ff 75 ?? e8 c1 00 00 00 59 59 8b f0 89 75
            ?? c7 45 ?? ?? ?? ?? ?? e8 15 00 00 00 8b c6 8b
            4d ?? 64 89 0d 00 00 00 00 59 5f 5e 5b c9 c3}
        $trait_8 = {
            b6 45 f8 88 4d ?? c1 e9 08 03 c8 0f b6 45 ?? 88
            4d ?? c1 e9 08 03 c8 0f b6 45 ?? 88 4d ?? c1 e9
            08 03 c8 88 4d ?? c1 e9 08 00 4d ?? 83 c6 c0 8b
            c6 83 d7 ff 83 c3 40 85 ff 77 88}
        $trait_9 = {
            56 b2 2e 8b f1 e8 13 00 00 00 85 c0 74 03 40 eb
            02 8b c6 b2 2f 8b c8 5e e9 00 00 00 00 53 8a da
            eb 0d 3a c3 74 13 51 ff 15 ?? ?? ?? ?? 8b c8 8a
            01 84 c0 75 ed 33 c0 5b c3}
        $trait_10 = {
            56 8b f1 8b 4e ?? e8 3a 01 00 00 8b 4e ?? 8a d0
            85 c9 74 06 5e e9 24 00 00 00 b8 00 10 00 00 66
            85 46 ?? 74 0c 8b 46 ?? 8b 00 8b 48 ?? 8b 09 eb
            e3 6a 62 59 84 d2 0f b6 c2 5e 0f 44 c1 c3}
        $trait_11 = {
            56 8b f1 85 d2 74 34 53 8a 5a ?? f6 c3 04 75 2a
            83 7e ?? ?? 74 08 8b 02 f6 40 ?? ?? 74 1c 8b 4a
            ?? 80 cb 04 88 5a ?? 85 c9 78 0f 8b 42 ?? 6b d1
            28 03 50 ?? 80 6a ?? ?? 74 ce 5b 5e c3}
        $trait_12 = {
            56 8b f1 0f b7 46 ?? a9 60 24 00 00 74 2e a9 00
            20 00 00 74 0f 8b 16 e8 3a 00 00 00 8b ce 5e e9
            b0 ff ff ff a9 00 04 00 00 74 13 8b 4e ?? 85 c9
            74 0c ff 76 ?? ff d1 83 66 ?? ?? 59 5e c3}
        $trait_13 = {
            56 8b 71 ?? 57 6a 05 58 c7 06 40 42 0f 00 8b 51
            ?? eb 04 89 04 96 4a 3b d0 7d f8 33 ff 47 eb 09
            6a 0b 58 2b c2 89 04 96 4a 3b d7 7d f3 80 79 ??
            ?? 74 06 8b 41 ?? 89 3c 86 5f 5e c3}
        $trait_14 = {
            55 8b ec 8b 41 ?? 56 85 c0 74 14 ff 75 ?? ff 75
            ?? ff 75 ?? 52 ff 71 ?? ff d0 83 c4 14 eb 1d 8b
            45 ?? 33 f6 3b 75 ?? 75 10 ff 75 ?? 50 52 ff 71
            ?? ff 51 ?? 83 c4 10 eb 03 83 c8 ff 5e 5d c3}
        $trait_15 = {
            55 8b ec 83 ec 58 53 56 57 8b 7d ?? 33 db 89 4d
            ?? 33 f6 0f 57 c0 89 55 ?? 8b 0f 89 4d ?? 8a 41
            ?? 88 45 ?? 8b 01 89 45 ?? 33 c0 21 45 ?? 66 89
            45 ?? 8a 02 66 0f 13 45 ?? 3c 80 73 07}
        $trait_16 = {
            55 8b ec 83 ec 24 56 8d 75 ?? eb 1e 85 d2 74 1e
            8b 41 ?? 3b 42 ?? 73 0a 89 4e ?? 8b f1 8b 49 ??
            eb 08 89 56 ?? 8b f2 8b 52 ?? 85 c9 75 de 85 c9
            0f 44 ca 89 4e ?? 8b 45 ?? 5e c9 c3}
        $trait_17 = {
            8d 45 ?? 50 8d 45 ?? 50 8d 45 ?? 50 e8 b7 0a ff
            ff 8d 45 ?? 50 8d 45 ?? 50 e8 8a 14 ff ff 83 c4
            14 be 09 00 00 00 ?? ?? 8d 45 ?? 50 50 e8 76 14
            ff ff 83 c4 08 83 ee 01 75 ee}
        $trait_18 = {
            55 8b ec 83 e4 f8 51 56 8b f1 83 7e ?? ?? 75 23
            80 7e ?? ?? 72 1d a1 ?? ?? ?? ?? 85 c0 74 02 ff
            d0 8b ce e8 f8 df ff ff a1 ?? ?? ?? ?? 85 c0 74
            02 ff d0 8b ce e8 18 00 00 00 5e 8b e5 5d c3}
        $trait_19 = {
            55 8b ec 53 8b 5d ?? 56 57 8b 7d ?? 8d 47 ?? 50
            57 53 e8 b9 fd fe ff 8d 77 ?? 56 8d 47 ?? 50 8d
            43 ?? 50 e8 a8 fd fe ff 8d 47 ?? 50 8d 43 ?? 56
            50 e8 9a fd fe ff 83 c4 24 5f 5e 5b 5d c3}
        $trait_20 = {
            55 8b ec 51 56 8b 71 ?? 57 8b fa eb 22 3b 75 ??
            74 1a 85 ff 74 05 39 7e ?? 75 11 80 7e ?? ?? 75
            0b 8b ce e8 12 00 00 00 85 c0 75 09 8b 76 ?? 85
            f6 75 da 33 c0 5f 5e 59 5d c3}
        $trait_21 = {
            55 8b ec 51 56 57 8b fa 8b f1 eb 28 8b 4e ?? e8
            92 01 00 00 85 c0 75 19 3b 7e ?? 73 14 ff 75 ??
            8b d7 8b ce e8 14 00 00 00 59 85 c0 74 03 89 46
            ?? 8b 76 ?? 85 f6 75 d4 5f 5e 59 5d c3}
        $trait_22 = {
            55 8b ec 51 56 57 6a 01 8d 45 ?? 8b f1 50 8b fa
            57 ff 76 ?? ff 56 ?? 83 c4 10 83 f8 01 75 0d 8b
            45 ?? 0f b6 4d ?? 89 08 33 c0 eb 0d 57 ff 76 ??
            ff 56 ?? f7 d8 59 59 1b c0 5f 5e c9 c3}
        $trait_23 = {
            55 8b ec 51 51 53 56 8b 75 ?? 57 8b 46 ?? 8b 4e
            ?? 83 c0 fb 3b c1 0f 46 c8 8b 06 89 4d ?? 33 ff
            8b 40 ?? 89 45 ?? 8b 86 ?? ?? ?? ?? 8b 16 83 c0
            2a c1 f8 03 8b 5a ?? 3b d8 0f 82 04 01 00 00}
        $trait_24 = {
            53 8b dc 83 ec 08 83 e4 f0 83 c4 04 55 8b 6b ??
            89 6c 24 ?? 8b ec 83 ec 28 a1 ?? ?? ?? ?? 33 c5
            89 45 ?? 8b 4b ?? 8b 53 ?? 56 33 f6 89 55 ?? 57
            8b 7b ?? 81 f9 e0 00 00 00 0f 82 15 01 00 00}
        $trait_25 = {
            8d 45 ?? 50 8d 45 ?? 50 8d 45 ?? 50 e8 1d 0a ff
            ff 8d 45 ?? 50 8d 45 ?? 50 e8 f0 13 ff ff 83 c4
            14 be 31 00 00 00 8d 45 ?? 50 50 e8 de 13 ff ff
            83 c4 08 83 ee 01 75 ee}
        $trait_26 = {
            13 c0 03 d1 8b 4d ?? 83 d0 00 23 5d ?? 0b 5d ??
            c1 e3 08 c1 e9 12 0b d9 8b 4d ?? 03 d8 8b 45 ??
            51 03 59 ?? 89 38 89 70 ?? 89 50 ?? 89 58 ?? e8
            82 f8 ff ff 83 c4 08 5f 5e 5b 8b e5 5d c3}
        $trait_27 = {
            0f b6 47 ?? 0f b6 0f 83 c7 02 c1 e0 08 03 c8 8b
            c2 83 e2 3f 25 c0 03 00 00 83 c2 40 81 e1 ff 03
            00 00 03 d0 c1 e2 0a 03 d1 8b 4d ?? 8d 46 ?? 89
            45 ?? 81 fa 80 00 00 00 73 06}
        $trait_28 = {
            0f b6 0f 0f b6 47 ?? 83 c7 02 c1 e1 08 03 c8 8b
            c2 83 e2 3f 25 c0 03 00 00 83 c2 40 81 e1 ff 03
            00 00 03 d0 c1 e2 0a 03 d1 8b 4d ?? 8d 46 ?? 89
            45 ?? 81 fa 80 00 00 00 73 06}
    condition:
        uint16(0) == 0x5a4d and
        uint32(uint32(0x3c)) == 0x00004550 and
        7 of them
}

private rule RisePro
 {
    meta:
        author = "kevoreilly"
        //cape_options = "br0=$decode1-49,action1=string:eax,count=1,bp2=$decode2+25,action2=string:eax"
        cape_options = "bp0=$c2+15,action0=string:edx,bp1=$c2+41,action1=string:ecx,count=1"
        hash = "1b69a1dd5961241b926605f0a015fa17149c3b2759fb077a30a22d4ddcc273f6"
    strings:
        $decode1 = {8A 06 46 84 C0 75 F9 2B F1 B8 FF FF FF 7F 8B 4D ?? 8B 51 ?? 2B C2 3B C6 72 38 83 79 ?? 10 72 02 8B 09 52 51 56 53 51 FF 75 ?? 8B CF E8}
        $decode2 = {8B D9 81 FF FF FF FF 7F 0F [2] 00 00 00 C7 43 ?? 0F 00 00 00 83 FF 10 73 1A 57 FF 75 ?? 89 7B ?? 53 E8 [4] 83 C4 0C C6 04 1F 00 5F 5B 5D C2 08 00}
        $c2 = {FF 75 30 83 3D [4] 10 BA [4] B9 [4] 0F 43 15 [4] 83 3D [4] 10 0F 43 0D [4] E8 [4] A3}
    condition:
        uint16(0) == 0x5A4D and any of them
}




private rule RisePro2 {
	meta:
		author = "ANY.RUN"
		description = "Detects RisePro (stealer version)"
		date = "2023-11-27"
		reference = "https://any.run/cybersecurity-blog/risepro-malware-communication-analysis/"
	strings:
		$ = { 74 2e 6d 65 2f 52 69 73 65 50 72 6f 53 55 50 50 4f 52 54 }
	condition:
		any of them
}


private rule RisePro3 {
    meta:
        author = "ditekShen"
        description = "Detects RisePro infostealer"
        cape_type = "RisePro Payload"
    strings:
        $x1 = "t.me/riseprosupport" ascii wide nocase
        $s1 = "failed readpacket" fullword wide
        $s2 = "faield sendpacket" fullword wide
        $s3 = "PersistWal" fullword wide
        $s4 = /CRED_ENUMERATE_(ALL|SESSION)_CREDENTIALS/ fullword ascii
        $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36" fullword wide
        $s6 = { 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00
                74 00 61 [10] 57 00 65 00 62 00 20 00 44 00 61 00
                74 00 61 [2] 48 00 69 00 73 00 74 00 6f 00 72 00
                79 [21] 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 }
        $s7 = { 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00
                69 00 6f 00 6e 00 2f 00 78 00 2d 00 77 00 77 00
                77 00 2d 00 66 00 6f 00 72 00 6d 00 2d 00 75 00
                72 00 6c 00 65 00 6e 00 63 00 6f 00 64 00 65 00
                64 00 3b 00 20 00 63 00 68 00 61 00 72 00 73 00
                65 00 74 00 3d 00 75 00 74 00 66 00 2d 00 38 00
                42 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74
                00 69 00 6f 00 6e 00 2f 00 6a 00 73 00 6f 00 6e
                00 2c 00 20 00 74 00 65 00 78 00 74 00 2f 00 70
                00 6c 00 61 00 69 00 6e 00 2c 00 20 00 2a 00 2f
                00 2a }
        $s8 = /_(SET|GET)_(GRABBER|LOADER)/ wide
        $s9 = /catch (save )?(windows cred|screen|pluginscrypto|historyCC|autofill|cookies|passwords|passwords sql|autofills sql|dwnlhistory sql|discordToken|quantum|isDropped)/ fullword wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($x*) or 6 of ($s*))
}

import "pe"
private rule EXE_Stealer_RisePro_Jan2024 {
    meta:
        Description = "Detects Rise Pro Stealer samples based on properties in the resources, manifest settings and PE Rich Header"
        Author = "RustyNoob619"
        Reference = "https://bazaar.abuse.ch/browse/signature/RiseProStealer/"
        Hash = "957ca1ae2bbb01a37d1108b314160716643933ec9ef9072a4c50c39b224662df"
        SampleSize = "Tested against 3 RisePro samples and wider malware collection"
    strings:
        $s1 = "'1.0' encoding"
        $s2 = "'UTF-8' standalone"
        $s3 = "'yes'?"
        $s4 = "'urn:schemas-microsoft-com:asm.v1' manifestVersion"
        $s5 = "trustInfo xmlns"
        $s6 = "urn:schemas-microsoft-com:asm.v3"
        $s7 = "security"
        $s8 = "requestedPrivileges"
        $s9 = "requestedExecutionLevel level"
        $s10 = "'asInvoker' uiAccess"
        $s11 = "'false' /"
// The above strings need to be adjusted to only pick dynamic XML parameters
    condition:
       pe.rich_signature.key== 3099257863  //can be removed for broader matching
       and pe.RESOURCE_TYPE_ICON == 3
       and for 5 i in (0..pe.number_of_resources - 1) : (
                   pe.resources[i].language == 1049 // Checking for Russian Language related resources
               )
       and pe.resources[pe.number_of_resources-1].type == 24 // Searching for XML Manifest Type
       and all of them
 }


rule fsRisePro {
    meta:
        description = "FsYARA - Malware Trends"
        vetted_family = "risepro"

    condition:
        win_risepro_auto or Trojan_Win32_RisePro_DB_ or RiseProStealer or risepro or RisePro or EXE_Stealer_RisePro_Jan2024 or RisePro2 or RiseProStealer or RisePro3
}
