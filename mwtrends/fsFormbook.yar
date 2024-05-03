////////////////////////////////////////////////////////
// YARA ruleset: Formbook.yar
// license: GNU GENERAL PUBLIC LICENSE
// repository: kevoreilly/CAPEv2
// url: https://github.com/kevoreilly/CAPEv2/blob/3cff06445d2f56ba1cea2846e79a7df06ac39c46/data/yara/CAPE/Formbook.yar

// original YARA name: Formbook
private rule Formbook0 {
    meta:
        author = "kevoreilly"
        description = "Formbook Payload"
        cape_type = "Formbook Payload"
        packed = "9e38c0c3c516583da526016c4c6a671c53333d3d156562717db79eac63587522"
        packed = "2379a4e1ccdd7849ad7ea9e11ee55b2052e58dda4628cd4e28c3378de503de23"
    strings:
        $remap_ntdll = {33 56 0? 8D 86 [2] 00 00 68 F0 00 00 00 50 89 56 ?? E8 [4] 8B [1-5] 6A 00 6A 04 8D 4D ?? 51 6A 07 52 56 E8 [4] 8B 45 ?? 83 C4 20 3B}
        $rc4dec = {F7 E9 C1 FA 03 8B C2 C1 E8 1F 03 C2 8D 04 80 03 C0 03 C0 8B D1 2B D0 8A 04 3A 88 8C 0D [4] 88 84 0D [4] 41 81 F9 00 01 00 00 7C}
        $decrypt = {8A 50 01 28 10 48 49 75 F7 83 FE 01 76 14 8B C7 8D 4E FF 8D 9B 00 00 00 00 8A 50 01 28 10 40 49 75 F7}
        $string = {33 C0 66 39 01 74 0B 8D 49 00 40 66 83 3C 41 00 75 F8 8B 55 0C 8D 44 00 02 50 52 51 E8}
        $mutant = {64 A1 18 00 00 00 8B 40 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 8B E5 5D C3}
        $postmsg = {8B 7D 0C 6A 00 6A 00 68 11 01 00 00 57 FF D6 85 C0 75 ?? 50}
    condition:
        2 of them
}
////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: Windows_Trojan_Formbook.yar
// license: Elastic License 2.0
// repository: elastic/protections-artifacts
// url: https://github.com/elastic/protections-artifacts/blob/f98777756fcfbe5ab05a296388044a2dbb962557/yara/rules/Windows_Trojan_Formbook.yar

// original YARA name: Windows_Trojan_Formbook_1112e116
private rule Formbook1 {
    meta:
        author = "Elastic Security"
        id = "1112e116-dee0-4818-a41f-ca5c1c41b4b8"
        fingerprint = "b8b88451ad8c66b54e21455d835a5d435e52173c86e9b813ffab09451aff7134"
        creation_date = "2021-06-14"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Formbook"
        reference = "https://www.elastic.co/security-labs/formbook-adopts-cab-less-approach"
        reference_sample = "6246f3b89f0e4913abd88ae535ae3597865270f58201dc7f8ec0c87f15ff370a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 3C 30 50 4F 53 54 74 09 40 }
        $a2 = { 74 0A 4E 0F B6 08 8D 44 08 01 75 F6 8D 70 01 0F B6 00 8D 55 }
        $a3 = { 1A D2 80 E2 AF 80 C2 7E EB 2A 80 FA 2F 75 11 8A D0 80 E2 01 }
        $a4 = { 04 83 C4 0C 83 06 07 5B 5F 5E 8B E5 5D C3 8B 17 03 55 0C 6A 01 83 }
    condition:
        any of them
}

// original YARA name: Windows_Trojan_Formbook_772cc62d
private rule Formbook2 {
    meta:
        author = "Elastic Security"
        id = "772cc62d-345c-42d8-97ab-f67e447ddca4"
        fingerprint = "3d732c989df085aefa1a93b38a3c078f9f0c3ee214292f6c1e31a9fc1c9ae50e"
        creation_date = "2022-05-23"
        last_modified = "2022-07-18"
        threat_name = "Windows.Trojan.Formbook"
        reference = "https://www.elastic.co/security-labs/formbook-adopts-cab-less-approach"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko"
        $a2 = "signin"
        $a3 = "persistent"
        $r1 = /.\:\\Users\\[^\\]{1,50}\\AppData\\Roaming\\[a-zA-Z0-9]{8}\\[a-zA-Z0-9]{3}log\.ini/ wide
    condition:
        2 of ($a*) and $r1
}

// original YARA name: Windows_Trojan_Formbook_5799d1f2
private rule Formbook3 {
    meta:
        author = "Elastic Security"
        id = "5799d1f2-4d4f-49d6-b010-67d2fbc04824"
        fingerprint = "b262c4223e90c539c73831f7f833d25fe938eaecb77ca6d2e93add6f93e7d75d"
        creation_date = "2022-06-08"
        last_modified = "2022-09-29"
        threat_name = "Windows.Trojan.Formbook"
        reference = "https://www.elastic.co/security-labs/formbook-adopts-cab-less-approach"
        reference_sample = "8555a6d313cb17f958fc2e08d6c042aaff9ceda967f8598ac65ab6333d14efd9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { E9 C5 9C FF FF C3 E8 00 00 00 00 58 C3 68 }
    condition:
        all of them
}


////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: formbook.yara
// license: The 3-Clause BSD License
// repository: JPCERTCC/jpcert-yara
// url: https://github.com/JPCERTCC/jpcert-yara/blob/0722a9365ec6bc969c517c623cd166743d1bc473/other/formbook.yara

// original YARA name: malware_Formbook_strings
private rule Formbook4 {
          meta:
            description = "detect Formbook in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $sqlite3step = { 68 34 1c 7b e1 }
            $sqlite3text = { 68 38 2a 90 c5 }
            $sqlite3blob = { 68 53 d8 7f 8c }

          condition:
            all of them
}

////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: win.formbook_auto.yar
// repository: malpedia/signator-rules
// url: https://github.com/malpedia/signator-rules/blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.formbook_auto.yar

// original YARA name: win_formbook_auto
private rule Formbook5 {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.formbook."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.formbook"
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
        $sequence_0 = { 5b 5f 5e 8be5 5d c3 8d0476 }
            // n = 7, score = 2200
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8d0476               | lea                 eax, [esi + esi*2]

        $sequence_1 = { 6a0d 8d8500fcffff 50 56 e8???????? 8d8d00fcffff 51 }
            // n = 7, score = 2200
            //   6a0d                 | push                0xd
            //   8d8500fcffff         | lea                 eax, [ebp - 0x400]
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   8d8d00fcffff         | lea                 ecx, [ebp - 0x400]
            //   51                   | push                ecx

        $sequence_2 = { 56 e8???????? 8d4df4 51 56 e8???????? 8d55e4 }
            // n = 7, score = 2200
            //   56                   | push                esi
            //   e8????????           |                     
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   51                   | push                ecx
            //   56                   | push                esi
            //   e8????????           |                     
            //   8d55e4               | lea                 edx, [ebp - 0x1c]

        $sequence_3 = { c3 3c04 752b 8b7518 8b0e 8b5510 8b7d14 }
            // n = 7, score = 2200
            //   c3                   | ret                 
            //   3c04                 | cmp                 al, 4
            //   752b                 | jne                 0x2d
            //   8b7518               | mov                 esi, dword ptr [ebp + 0x18]
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   8b7d14               | mov                 edi, dword ptr [ebp + 0x14]

        $sequence_4 = { 56 e8???????? 83c418 395df8 0f85a0000000 8b7d18 395f10 }
            // n = 7, score = 2200
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   395df8               | cmp                 dword ptr [ebp - 8], ebx
            //   0f85a0000000         | jne                 0xa6
            //   8b7d18               | mov                 edi, dword ptr [ebp + 0x18]
            //   395f10               | cmp                 dword ptr [edi + 0x10], ebx

        $sequence_5 = { c745fc01000000 e8???????? 6a14 8d4dec 51 50 }
            // n = 6, score = 2200
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   e8????????           |                     
            //   6a14                 | push                0x14
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   51                   | push                ecx
            //   50                   | push                eax

        $sequence_6 = { e8???????? 83c428 8906 85c0 75a8 5f 33c0 }
            // n = 7, score = 2200
            //   e8????????           |                     
            //   83c428               | add                 esp, 0x28
            //   8906                 | mov                 dword ptr [esi], eax
            //   85c0                 | test                eax, eax
            //   75a8                 | jne                 0xffffffaa
            //   5f                   | pop                 edi
            //   33c0                 | xor                 eax, eax

        $sequence_7 = { 56 e8???????? 6a03 ba5c000000 57 56 66891446 }
            // n = 7, score = 2200
            //   56                   | push                esi
            //   e8????????           |                     
            //   6a03                 | push                3
            //   ba5c000000           | mov                 edx, 0x5c
            //   57                   | push                edi
            //   56                   | push                esi
            //   66891446             | mov                 word ptr [esi + eax*2], dx

        $sequence_8 = { 3b75d0 72c0 8d55f8 52 e8???????? }
            // n = 5, score = 2200
            //   3b75d0               | cmp                 esi, dword ptr [ebp - 0x30]
            //   72c0                 | jb                  0xffffffc2
            //   8d55f8               | lea                 edx, [ebp - 8]
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_9 = { 8d8df6f7ffff 51 c745fc00000000 668985f4f7ffff e8???????? 8b7508 }
            // n = 6, score = 2200
            //   8d8df6f7ffff         | lea                 ecx, [ebp - 0x80a]
            //   51                   | push                ecx
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   668985f4f7ffff       | mov                 word ptr [ebp - 0x80c], ax
            //   e8????????           |                     
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 371712
}
////////////////////////////////////////////////////////


////////////////////////////////////////////////////////
// YARA ruleset: formbook.yara
// license: Detection Rule License (DRL) 1.1
// repository: MalGamy/YARA_Rules
// url: https://github.com/MalGamy/YARA_Rules/blob/1f538fcd5fe6d8aeec6c8a8394a785b69872b7a7/formbook.yara

// original YARA name: Windows_Trojan_Formbook
private rule Formbook6 {
    meta:
        author = "@malgamy12"
        date = "2022-11-8"
	license = "DRL 1.1"
        sample1 = "9fc57307d1cce6f6d8946a7dae41447b"
        sample2 = "0f4a7fa6e654b48c0334b8b88410eaed"
        sample3 = "0a25d588340300461738a677d0b53cd2"
        sample4 = "57d7bd215e4c4d03d73addec72936334"
        sample5 = "c943e31f7927683dc1b628f0972e801b"
        sample6 = "db87f238bb4e972ef8c0b94779798fa9"
        sample7 = "8ba1449ee35200556ecd88f23a35863a"
        sample8 = "8ca20642318337816d5db9666e004172"
        sample9 = "280f7c87c98346102980c514d2dd25c8"

    strings:
        $a1 = { 8B 45 ?? BA ?? [3] 8B CF D3 E2 84 14 03 74 ?? 8B 4D ?? 31 0E 8B 55 ?? 31 56 ?? 8B 4D ?? 8B 55 ?? 31 4E ?? 31 56 ?? }
			
        $a2 = { 0F B6 3A 8B C8 C1 E9 ?? 33 CF 81 E1 [4] C1 E0 ?? 33 84 8D [4] 42 4E }
        
        $a3 = { 1A D2 80 E2 ?? 80 C2 ?? EB ?? 80 FA ?? 75 ?? 8A D0 80 E2 ?? }

        $a4 = { 80 E2 ?? F6 DA 1A D2 80 E2 ?? 80 C2 ?? }

    condition:
         3 of them
}


////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: Formbook.yar
// repository: CAPESandbox/community
// url: https://github.com/CAPESandbox/community/blob/ed71b5eb9179e25174c1a2d0fe451e25cbf97dd1/data/yara/CAPE/deprecated/Formbook.yar

// original YARA name: Formbook
private rule Formbook7 {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2018-11-23"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator 0.1a"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.formbook"
        malpedia_version = "20180607"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
        cape_type = "Formbook Payload"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using yara-signator.
     * The code and documentation / approach will be published in the near future here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */

    strings:
        $sequence_0 = { 03c8 0f31 2bc1 8945fc }
            // n = 4, score = 6000
            //   03c8                 | add                 ecx, eax
            //   0f31                 | rdtsc
            //   2bc1                 | sub                 eax, ecx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_1 = { 3c24 0f8476ffffff 3c25 7494 }
            // n = 4, score = 6000
            //   3c24                 | cmp                 al, 0x24
            //   0f8476ffffff         | je                  0x112a53
            //   3c25                 | cmp                 al, 0x25
            //   7494                 | je                  0x112a75

        $sequence_2 = { 3b4f14 7395 85c9 7491 }
            // n = 4, score = 6000
            //   3b4f14               | cmp                 ecx, dword ptr [edi + 0x14]
            //   7395                 | jae                 0x11255b
            //   85c9                 | test                ecx, ecx
            //   7491                 | je                  0x11255b

        $sequence_3 = { 3c69 7544 8b7d18 8b0f }
            // n = 4, score = 6000
            //   3c69                 | cmp                 al, 0x69
            //   7544                 | jne                 0x112c1f
            //   8b7d18               | mov                 edi, dword ptr [ebp + 0x18]
            //   8b0f                 | mov                 ecx, dword ptr [edi]

        $sequence_4 = { 5d c3 8d507c 80fa07 }
            // n = 4, score = 6000
            //   5d                   | pop                 ebp
            //   c3                   | ret
            //   8d507c               | lea                 edx, dword ptr [eax + 0x7c]
            //   80fa07               | cmp                 dl, 7

        $sequence_5 = { 0fbe5c0e01 0fb6540e02 83e30f c1ea06 }
            // n = 4, score = 6000
            //   0fbe5c0e01           | movsx               ebx, byte ptr [esi + ecx + 1]
            //   0fb6540e02           | movzx               edx, byte ptr [esi + ecx + 2]
            //   83e30f               | and                 ebx, 0xf
            //   c1ea06               | shr                 edx, 6

        $sequence_6 = { 57 8945fc 8945f4 8945f8 }
            // n = 4, score = 6000
            //   57                   | push                edi
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

        $sequence_7 = { 66890c02 5b 8be5 5d }
            // n = 4, score = 6000
            //   66890c02             | mov                 word ptr [edx + eax], cx
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp

        $sequence_8 = { 3c54 7404 3c74 75f4 }
            // n = 4, score = 6000
            //   3c54                 | cmp                 al, 0x54
            //   7404                 | je                  0x117e2f
            //   3c74                 | cmp                 al, 0x74
            //   75f4                 | jne                 0x117e23

        $sequence_9 = { 56 6803010000 8d8595feffff 6a00 }
            // n = 4, score = 6000
            //   56                   | push                esi
            //   6803010000           | push                0x103
            //   8d8595feffff         | lea                 eax, dword ptr [ebp - 0x16b]
            //   6a00                 | push                0

    condition:
        7 of them
}

////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: Win32_Trojan_Formbook.yar
// license: MIT License
// repository: netskopeoss/NetskopeThreatLabsIOCs
// url: https://github.com/netskopeoss/NetskopeThreatLabsIOCs/blob/52c780db6106d0c0e8deb04653e036cdd4408e56/Malware/Formbook/Yara/Win32_Trojan_Formbook.yar

import "pe"
import "math"


// original YARA name: Win32_Trojan_Formbook_01
private rule Formbook8 {
	meta:
		description = "Identifies the first stage of the .NET Formbook loader"
		author = "Netskope Threat Labs"
		sha256 = "388292015e4c2d075b935a8299d99335d957e3ad5134a33f28c4dc7f5e3687c5"

	strings:
		$str00 = "PlaylistPanda"
		$str01 = "CorExeMain"
		$str02 = "VarArgMet"
		$str03 = "System.Net"
		$str04 = "MainForm"
		$str05 = "x121312x121312"
		$str06 = "ZoneIdentityPermissionAttrib"

	condition:
		uint16(0) == 0x5a4d
		and math.entropy(0, filesize) >= 7
		and all of ($str*)
}

// original YARA name: Win32_Trojan_Formbook_02
private rule Formbook9 {
	meta:
		description = "Identifies the second stage of the .NET Formbook loader"
		author = "Netskope Threat Labs"
		sha256 = "e33254e2ad4d279914a29450f98d1750a9f513fc8ddb853e0dd8346b805faa43"

	strings:
		$str01 = "Microsoft.VisualBasic"
		$str02 = "SpaceChemSolver"
		$str03 = "SortHelper"
		$str04 = "RunCore"
		$str05 = "DemandedResources"
		$str06 = "ConstructionResponse"
		$str07 = "GetBytes"

	condition:
		uint16(0) == 0x5a4d
		and all of ($str*)
}

// original YARA name: Win32_Trojan_Formbook_03
private rule Formbook10 {
	meta:
		description = "Identifies the third stage of the .NET Formbook loader (a.k.a. CyaX-Sharp)"
		author = "Netskope Threat Labs"
		sha256 = "04e27134490848fda6a4fc5abaa4001d36bc222f0b1098698573c510e3af69c8"
		sha256 = "4322269fa75f84f6d21dd1e334fe01541ae55a6bed21d8ea7ea26b9bd2bff499"

	strings:
		$str01 = "DotNetZipAdditionalPlatforms"

		$p00 = "x5PhlKc5Z75TX8ZAxA.2M4tZ3G4Di2E5P924i"
		$p01 = "4HnSVBQUZwSvdLstPZ.tUdWKyFDwClq26Va54"

		$u00 = "eaIgfPjRhA"
		$u01 = "pepVuxoygA"
		$u02 = "fVkXSK7E.resources"
		$u04 = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTE2Ij8" wide

	condition:
		uint16(0) == 0x5a4d
		and $str01
		and (all of ($p*) or all of ($u*))
}

// original YARA name: Win32_Trojan_Formbook_04
private rule Formbook11 {
	meta:
		description = "Identifies the Formbook samples"
		author = "Netskope Threat Labs"
		sha256 = "0d1caeae9e59a10b6b52ffb7687966ec6b0c2f0f36b8d76657d51f1aa57cd737"

	strings:
		// Based on 0x409900
		$asm = { 55 8b ec 51 0f 31 33 c9 03 c8 0f 31 2b c1 }

		// Based on 0x4154e0
		$asm01 = { 3c 1d 0f 84 ?? ?? ?? ?? 8d 50 e0 80 fa 03 0f 86 ?? ?? ?? ?? 3c 24 0f 84 ?? ?? ?? ?? 3c 25 74 ?? 8d 48 d8 80 f9 03 0f 86 ?? ?? ?? ?? 3c 2c 74 ?? 3c 2d 0f 84 }

		// call $+5 -> pop eax -> retn
		$asm02 = { E8 00 00 00 00 58 C3 }

	condition:
		uint16(0) == 0x5a4d
		and pe.number_of_sections == 1
		and pe.number_of_imports == 0
		and math.entropy(0, filesize) >= 7
		and all of ($asm*)
}

////////////////////////////////////////////////////////


rule fsFormbook {
    meta:
        description = "FsYARA - Malware Trends"
        vetted_family = "formbook"
	condition:
		Formbook0 or Formbook1 or Formbook2 or Formbook3 or Formbook4 or Formbook5 or Formbook6 or Formbook7 or Formbook8 or Formbook9 or Formbook10 or Formbook11
}