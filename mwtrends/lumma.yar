private rule win_lumma_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.lumma."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma"
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
        $sequence_0 = { 57 53 ff767c ff7678 }
            // n = 4, score = 1100
            //   57                   | push                edi
            //   53                   | push                ebx
            //   ff767c               | push                dword ptr [esi + 0x7c]
            //   ff7678               | push                dword ptr [esi + 0x78]

        $sequence_1 = { ffd0 83c40c 894648 85c0 }
            // n = 4, score = 1000
            //   ffd0                 | call                eax
            //   83c40c               | add                 esp, 0xc
            //   894648               | mov                 dword ptr [esi + 0x48], eax
            //   85c0                 | test                eax, eax

        $sequence_2 = { ff5130 83c410 85c0 7407 }
            // n = 4, score = 1000
            //   ff5130               | call                dword ptr [ecx + 0x30]
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9

        $sequence_3 = { ff7678 ff7644 ff563c 83c414 }
            // n = 4, score = 1000
            //   ff7678               | push                dword ptr [esi + 0x78]
            //   ff7644               | push                dword ptr [esi + 0x44]
            //   ff563c               | call                dword ptr [esi + 0x3c]
            //   83c414               | add                 esp, 0x14

        $sequence_4 = { ff770c ff37 ff7134 ff5130 }
            // n = 4, score = 1000
            //   ff770c               | push                dword ptr [edi + 0xc]
            //   ff37                 | push                dword ptr [edi]
            //   ff7134               | push                dword ptr [ecx + 0x34]
            //   ff5130               | call                dword ptr [ecx + 0x30]

        $sequence_5 = { ff7608 ff7044 ff503c 83c414 }
            // n = 4, score = 1000
            //   ff7608               | push                dword ptr [esi + 8]
            //   ff7044               | push                dword ptr [eax + 0x44]
            //   ff503c               | call                dword ptr [eax + 0x3c]
            //   83c414               | add                 esp, 0x14

        $sequence_6 = { 894610 8b461c c1e002 50 }
            // n = 4, score = 1000
            //   894610               | mov                 dword ptr [esi + 0x10], eax
            //   8b461c               | mov                 eax, dword ptr [esi + 0x1c]
            //   c1e002               | shl                 eax, 2
            //   50                   | push                eax

        $sequence_7 = { 833800 740a e8???????? 833822 }
            // n = 4, score = 1000
            //   833800               | cmp                 dword ptr [eax], 0
            //   740a                 | je                  0xc
            //   e8????????           |
            //   833822               | cmp                 dword ptr [eax], 0x22

        $sequence_8 = { 83c40c 6a02 6804010000 e8???????? }
            // n = 4, score = 800
            //   83c40c               | add                 esp, 0xc
            //   6a02                 | push                2
            //   6804010000           | push                0x104
            //   e8????????           |

        $sequence_9 = { 017e78 83567c00 017e68 83566c00 }
            // n = 4, score = 800
            //   017e78               | add                 dword ptr [esi + 0x78], edi
            //   83567c00             | adc                 dword ptr [esi + 0x7c], 0
            //   017e68               | add                 dword ptr [esi + 0x68], edi
            //   83566c00             | adc                 dword ptr [esi + 0x6c], 0

        $sequence_10 = { 89e5 8b550c 6bd204 89d1 }
            // n = 4, score = 700
            //   89e5                 | mov                 ebp, esp
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   6bd204               | imul                edx, edx, 4
            //   89d1                 | mov                 ecx, edx

        $sequence_11 = { 41 5d 41 5b 41 5c }
            // n = 6, score = 700
            //   41                   | inc                 ecx
            //   5d                   | pop                 ebp
            //   41                   | inc                 ecx
            //   5b                   | pop                 ebx
            //   41                   | inc                 ecx
            //   5c                   | pop                 esp

        $sequence_12 = { 48 83ec28 0f05 48 83c428 49 }
            // n = 6, score = 700
            //   48                   | dec                 eax
            //   83ec28               | sub                 esp, 0x28
            //   0f05                 | syscall
            //   48                   | dec                 eax
            //   83c428               | add                 esp, 0x28
            //   49                   | dec                 ecx

    condition:
        7 of them and filesize < 1115136
}

private rule win_lumma_w0 {
	meta:
		description = "detect_Lumma_stealer"
		author = "@malgamy12"
		date = "2022-11-3"
		license = "DRL 1.1"
		hunting = "https://www.hybrid-analysis.com/sample/f18d0cd673fd0bd3b071987b53b5f97391a56f6e4f0c309a6c1cee6160f671c0"
		hash1 = "19b937654065f5ee8baee95026f6ea7466ee2322"
        hash2 = "987f93e6fa93c0daa0ef2cf4a781ca53a02b65fe"
        hash3 = "70517a53551269d68b969a9328842cea2e1f975c"
        hash4 = "9b7b72c653d07a611ce49457c73ee56ed4c4756e"
        hash5 = "4992ebda2b069281c924288122f76556ceb5ae02"
        hash6 = "5c67078819246f45ff37d6db81328be12f8fc192"
        hash7 = "87fe98a00e1c3ed433e7ba6a6eedee49eb7a9cf9"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma"
        malpedia_rule_date = "20230118"
        malpedia_hash = ""
        malpedia_version = "20230118"
        malpedia_license = "DRL 1.1"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $m1 = "LummaC\\Release\\LummaC.pdb" ascii fullword

        $s1 = "Cookies.txt" ascii
        $s2 = "Autofills.txt" ascii
        $s3 = "ProgramData\\config.txt" ascii
        $s4 = "ProgramData\\softokn3.dll" ascii
        $s5 = "ProgramData\\winrarupd.zip" ascii


        $chunk_1 = {C1 E8 ?? 33 C6 69 C8 ?? ?? ?? ?? 5F 5E 8B C1 C1 E8 ??}

    condition:
        $m1 or (4 of ($s*) and $chunk_1 )
}

private rule win_lumma_w1 {
	meta:
		author = "Matthew @ Embee_Research"
		yarahub_author_twitter = "@embee_research"
		desc = "Detects obfuscation methods observed in Lumma Stealer Payloads"
		sha_256 = "277d7f450268aeb4e7fe942f70a9df63aa429d703e9400370f0621a438e918bf"
		sha_256 = "7f18cf601b818b11068bb8743283ae378f547a1581682ea3cc163186aae7c55d"
		sha_256 = "03796740db48a98a4438c36d7b8c14b0a871bf8c692e787f1bf093b2d584999f"
		date = "2023-09-13"
		source = "https://github.com/embee-research/Yara-detection-rules/blob/main/Rules/win_lumma%20_simple.yar"
        yarahub_uuid = "39c32477-9a80-485b-b17a-4adf05f66cf8"
       	yarahub_license = "CC BY-NC 4.0"
        malpedia_family = "win.lumma"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma"
        malpedia_version = "20230918"
        malpedia_license = ""
        malpedia_sharing = "TLP:WHITE"
	strings:

		$o1 = {57 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 65 00 62 00 20 00 44 00 61 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 74 00 61 00}
		$o2 = {4f 00 70 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 65 00 72 00 61 00 20 00 4e 00 65 00 6f 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 6e 00}
		$o3 = {4c 00 6f 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 67 00 69 00 6e 00 20 00 44 00 61 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 74 00 61 00}

	condition:
		uint16(0) == 0x5a4d
		and
		filesize < 5000KB
		and
		(all of ($o*))


}


private rule Lumma
 {
    meta:
        author = "kevoreilly"
        description = "Lumma Payload"
        cape_type = "Lumma Payload"
        packed = "0ee580f0127b821f4f1e7c032cf76475df9724a9fade2e153a69849f652045f8"
    strings:
        $c2 = {8D 44 24 ?? 50 89 4C 24 ?? FF 31 E8 [4] 83 C4 08 B8 FF FF FF FF}
        $peb = {8B 44 24 04 85 C0 74 13 64 8B 0D 30 00 00 00 50 6A 00 FF 71 18 FF 15}
        $remap = {C6 44 24 20 00 C7 44 24 1C C2 00 00 90 C7 44 24 18 00 00 FF D2 C7 44 24 14 00 BA 00 00 C7 44 24 10 B8 00 00 00 8B ?? 89 44 24 11}
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule Detect_lumma_stealer: lumma
{
    meta:

	description = "Detect_lumma_stealer"
	author = "@malgamy12"
	date = "2023/1/7"
	license = "DRL 1.1"
        hash = "61b9701ec94779c40f9b6d54faf9683456d02e0ee921adbb698bf1fee8b11ce8"
        hash = "277d7f450268aeb4e7fe942f70a9df63aa429d703e9400370f0621a438e918bf"
        hash = "9b742a890aff9c7a2b54b620fe5e1fcfa553648695d79c892564de09b850c92b"
        hash = "60247d4ddd08204818b60ade4bfc32d6c31756c574a5fe2cd521381385a0f868"

    strings:

        $s1 = "- PC:" ascii
        $s2 = "- User:" ascii
        $s3 = "- Screen Resoluton:" ascii
        $s4 = "- Language:" ascii

        $op = {0B C8 69 F6 [4] 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 07 C1 E1 ?? 83 C7 ?? 0B C8 69 C9 [4] 8B C1 C1 E8 ?? 33 C1 69 C8 [4] 33 F1}

    condition:
        uint16(0) == 0x5A4D and $op and all of ($s*)
}



private rule Trojan_BAT_Lumma_RDB_MTB {
	meta:
		description = "Trojan:BAT/Lumma.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "

	strings :
		$a_01_0 = {6c 61 6e 67 75 61 67 65 5f 73 75 70 70 6f 72 74 5f 61 6e 64 5f 6c 6f 63 61 6c 69 7a 61 74 69 6f 6e } //01 00  language_support_and_localization
		$a_01_1 = {7b 00 7d 00 64 00 7b 00 7d 00 6f 00 7b 00 7d 00 68 00 7b 00 7d 00 74 00 7b 00 7d 00 65 00 7b 00 7d 00 4d 00 7b 00 7d 00 74 00 7b 00 7d 00 65 00 7b 00 7d 00 47 00 7b 00 7d 00 } //01 00  {}d{}o{}h{}t{}e{}M{}t{}e{}G{}
		$a_01_2 = {3d 00 2f 00 2a 00 2d 00 54 00 3d 00 79 00 3d 00 70 00 3d 00 65 00 3d 00 } //00 00  =/*-T=y=p=e=
	condition:
		any of ($a_*)

}

private rule win_lumma_simple_strings
 {
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/09/13"
		description = ""
		sha_256 = "277d7f450268aeb4e7fe942f70a9df63aa429d703e9400370f0621a438e918bf"

	strings:

		$s1 = "Binedx765ance Chaedx765in Waledx765let" wide
		$s2 = "%appdaedx765ta%\\Moedx765zilla\\Firedx765efox\\Profedx765iles"
		$s3 = "\\Locedx765al Extensedx765ion Settinedx765gs\\"
		$s4 = "%appdedx765ata%\\Opedx765era Softwedx765are\\Opedx765era GX Staedx765ble"


		/*
			Wedx765eb Daedx765ta
			Opedx765era Neoedx765n
			Loedx765gin Daedx765ta

		*/

		$o1 = {57 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 65 00 62 00 20 00 44 00 61 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 74 00 61 00}
		$o2 = {4f 00 70 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 65 00 72 00 61 00 20 00 4e 00 65 00 6f 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 6e 00}
		$o3 = {4c 00 6f 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 67 00 69 00 6e 00 20 00 44 00 61 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 74 00 61 00}

	condition:
		uint16(0) == 0x5a4d
		and
		filesize < 5000KB
		and
		(
			(all of ($s*))
			or
			(all of ($o*))
		)


}

rule detect_Lumma_stealer: Lumma
{
	meta:
		description = "detect_Lumma_stealer"
		author = "@malgamy12"
		date = "2022-11-3"
		hunting = "https://www.hybrid-analysis.com/sample/f18d0cd673fd0bd3b071987b53b5f97391a56f6e4f0c309a6c1cee6160f671c0"
		hash1 = "19b937654065f5ee8baee95026f6ea7466ee2322"
                hash2 = "987f93e6fa93c0daa0ef2cf4a781ca53a02b65fe"
                hash3 = "70517a53551269d68b969a9328842cea2e1f975c"
                hash4 = "9b7b72c653d07a611ce49457c73ee56ed4c4756e"
                hash5 = "4992ebda2b069281c924288122f76556ceb5ae02"
                hash6 = "5c67078819246f45ff37d6db81328be12f8fc192"
                hash7 = "87fe98a00e1c3ed433e7ba6a6eedee49eb7a9cf9"

    strings:
        $m1 = "LummaC\\Release\\LummaC.pdb" ascii fullword

        $s1 = "Cookies.txt" ascii
        $s2 = "Autofills.txt" ascii
        $s3 = "ProgramData\\config.txt" ascii
        $s4 = "ProgramData\\softokn3.dll" ascii
        $s5 = "ProgramData\\winrarupd.zip" ascii


        $chunk_1 = {C1 E8 ?? 33 C6 69 C8 ?? ?? ?? ?? 5F 5E 8B C1 C1 E8 ??}

    condition:
        $m1 or (4 of ($s*) and $chunk_1 )
}



private rule LummaC2 {

       meta:
           author = "RussianPanda"
           description = "LummaC2 Detection"

       strings:
           $p1="lid=%s&j=%s&ver"
           $p2= {89 ca 83 e2 03 8a 54 14 08 32 54 0d 04}

       condition:
           all of them and filesize <= 500KB
   }


private rule LummaStealer {
    meta:
        author = "ditekSHen"
        description = "Detects Lumma Stealer"
        cape_type = "LummaStealer Payload"
    strings:
        $x1 = /Lum[0-9]{3}xedmaC2,\sBuild/ ascii
        $x2 = /LID\(Lu[0-9]{3}xedmma\sID\):/ ascii
        $s1 = /os_c[0-9]{3}xedrypt\.encry[0-9]{3}xedpted_key/ fullword ascii
        $s2 = "c2sock" wide
        $s3 = "c2conf" wide
        $s4 = "TeslaBrowser/" wide
        $s5 = "Software.txt" fullword wide
        $s6 = "SysmonDrv" fullword
        $s7 = "*.eml" fullword wide nocase
        $s8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" wide
        $s9 = "- Screen Resoluton:" ascii
        $s10 = "lid=%s" ascii
        $s11 = "&ver=" ascii
        $s12 = "769cb9aa22f4ccc412f9cbc81feedd" fullword wide
        $s13 = "gapi-node.io" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or (1 of ($x*) and 2 of ($s*)) or 5 of ($s*) or 7 of them)
}


rule fsLumma {
    meta:
        description = "FsYARA - Malware Trends"
        vetted_family = "lumma"

    condition:
        win_lumma_auto or win_lumma_w0 or win_lumma_w1 or Lumma or Detect_lumma_stealer or Trojan_BAT_Lumma_RDB_MTB or win_lumma_simple_strings or detect_Lumma_stealer or LummaC2 or LummaStealer
}