////////////////////////////////////////////////////////
// YARA ruleset: gen_qakbot_uninstaller.yar
// license: Other
// repository: Neo23x0/signature-base
// url: https://github.com/Neo23x0/signature-base/blob/007d9ddee386f68aca3a3aac5e1514782f02ed2d/yara/gen_qakbot_uninstaller.yar


// original YARA name: SUSP_Qakbot_Uninstaller_ShellCode_Aug23
private rule Qakbot0 {
   meta:
      description = "Detects Qakbot Uninstaller files used by the FBI and Dutch National Police in a disruption operation against the Qakbot in August 2023"
      author = "Florian Roth"
      reference = "https://www.justice.gov/usao-cdca/divisions/national-security-division/qakbot-resources"
      date = "2023-08-30"
      score = 60
      id = "860796ab-689f-5c5f-bc40-3e2ef7fd1d5d"
   strings:
      $xc1 = { E8 00 00 00 00 58 55 89 E5 89 C2 68 03 00 00 00 68 00 2C 00 00 05 20 0A 00 00 50 E8 05 00 00 00 83 C4 04 C9 C3 81 EC 08 01 00 00 53 55 56 57 6A 6B 58 6A 65 5B 6A 72 66 89 84 24 D4 00 00 00 33 }
   condition:
      $xc1
}

// original YARA name: SUSP_QakBot_Uninstaller_FBI_Aug23
private rule Qakbot1 {
   meta:
      description = "Detects Qakbot uninstaller used by the FBI / Dutch Police"
      author = "Florian Roth"
      reference = "https://www.justice.gov/usao-cdca/divisions/national-security-division/qakbot-resources"
      date = "2023-08-31"
      score = 60
      hash1 = "559cae635f0d870652b9482ef436b31d4bb1a5a0f51750836f328d749291d0b6"
      hash2 = "855eb5481f77dde5ad8fa6e9d953d4aebc280dddf9461144b16ed62817cc5071"
      hash3 = "fab408536aa37c4abc8be97ab9c1f86cb33b63923d423fdc2859eb9d63fa8ea0"
      id = "499bff56-ff49-53df-9922-227b816c0a36"
   strings:
      $op1 = { 69 c1 65 89 07 6c 03 c2 89 84 95 24 f6 ff ff 8b 55 e4 42 89 55 e4 81 fa 70 02 00 00 7c d4 }
      $op2 = { 42 89 55 e4 81 fa 70 02 00 00 7c d4 f2 0f 10 0d a0 31 00 10 33 f6 f2 0f 10 15 a8 31 00 10 66 90 }
      $op5 = { 68 48 31 00 10 6a 28 57 e8 e4 fd ff ff 8b 4d fc 83 c4 4c 33 cd 33 c0 }
      $op6 = { 33 c0 66 39 06 74 0f 0f 1f 80 00 00 00 00 40 66 83 3c 46 00 75 f8 8d 3c 00 }
   condition:
      all of them
}

////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: QakBot.yar
// license: Other
// repository: kevoreilly/CAPEv2
// url: https://github.com/kevoreilly/CAPEv2/blob/3cff06445d2f56ba1cea2846e79a7df06ac39c46/data/yara/CAPE/QakBot.yar

// original YARA name: QakBot5
private rule Qakbot2 {
    meta:
        author = "kevoreilly, enzok"
        description = "QakBot v5 Payload"
        cape_type = "QakBot Payload"
        packed = "f4bb0089dcf3629b1570fda839ef2f06c29cbf846c5134755d22d419015c8bd2"
        hash = "59559e97962e40a15adb2237c4d01cfead03623aff1725616caeaa5a8d273a35"
    strings:
        $loop = {8B 75 ?? 48 8B 4C [2] FF 15 [4] 48 8B 4C [2] 48 8B 01 FF 50 ?? 8B DE 48 8B 4C [2] 48 85 C9 0F 85 [4] EB 4E}
        $c2list = {0F B7 1D [4] B? [2] 00 00 E8 [4] 8B D3 4? 89 45 ?? 4? 33 C9 4? 8D 0D [4] 4? 8B C0 4? 8B F8 E8}
        $campaign = {0F B7 1D [4] B? [2] 00 00 E8 [4] 8B D3 4? 89 44 24 ?? 4? 33 C9 4? 8D 0D [4] 4? 8B C0 4? 8B F8 E8}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

// original YARA name: QakBot4
private rule Qakbot3 {
    meta:
        author = "kevoreilly"
        description = "QakBot v4 Payload"
        cape_type = "QakBot Payload"
    strings:
        $crypto1 = {8B 5D 08 0F B6 C2 8A 16 0F B6 1C 18 88 55 13 0F B6 D2 03 CB 03 CA 81 E1 FF 00 00 80 79 08 49 81 C9 00 FF FF FF 41}
        $sha1_1 = {5? 33 F? [0-9] 89 7? 24 ?? 89 7? 24 ?? 8? [1-3] 24 [1-4] C7 44 24 ?0 01 23 45 67 C7 44 24 ?4 89 AB CD EF C7 44 24 ?8 FE DC BA 98 C7 44 24 ?C 76 54 32 10 C7 44 24 ?0 F0 E1 D2 C3}
        $sha1_2 = {33 C0 C7 01 01 23 45 67 89 41 14 89 41 18 89 41 5C C7 41 04 89 AB CD EF C7 41 08 FE DC BA 98 C7 41 0C 76 54 32 10 C7 41 10 F0 E1 D2 C3 89 41 60 89 41 64 C3}
        $anti_sandbox1 = {8D 4? FC [0-1] E8 [4-7] E8 [4] 85 C0 7E (04|07) [4-7] 33 (C0|D2) 74 02 EB FA}
        $anti_sandbox2 = {8D 45 ?? 50 E8 [2] 00 00 59 68 [4] FF 15 [4] 89 45 ?? 83 7D ?? 0F 76 0C}
        $decrypt_config1 = {FF 37 83 C3 EC 53 8B 5D 0C 8D 43 14 50 6A 14 53 E8 ?? ?? ?? ?? 83 C4 14 85 C0 ?? 26 ?? ?? 86 20 02 00 00 66 85 C0 ?? ?? FF 37 FF 75 10 53}
        $decrypt_config2 = {8B 45 08 8B 88 24 04 00 00 51 8B 55 10 83 EA 14 52 8B 45 0C 83 C0 14 50 6A 14 8B 4D 0C 51 E8 6C 08 00 00}
        $decrypt_config3 = {6A 13 8B CE 8B C3 5A 8A 18 3A 19 75 05 40 41 4A 75 F5 0F B6 00 0F B6 09 2B C1 74 05 83 C8 FF EB 0E}
        $call_decrypt = {83 7D ?? 00 56 74 0B FF 75 10 8B F3 E8 [4] 59 8B 45 0C 83 F8 28 72 19 8B 55 08 8B 37 8D 48 EC 6A 14 8D 42 14 52 E8}
    condition:
        uint16(0) == 0x5A4D and any of ($*)
}

////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: QakBot_OneNote_Loader.yara
// license: GNU General Public License v3.0
// repository: CYB3RMX/Qu1cksc0pe
// url: https://github.com/CYB3RMX/Qu1cksc0pe/blob/b169586bc84601f9614d32520c7e97b964135dee/Systems/Multiple/YaraRules_Multiple/QakBot_OneNote_Loader.yara

// original YARA name: QakBot_OneNote_Loader
private rule Qakbot4 {

  meta:
      author = "Ankit Anubhav - ankitanubhav.info"
      description = "Detects a OneNote malicious loader mostly used by QBot (TA570/TA577)"
      date = "2023-02-04"
      yarahub_author_twitter = "@ankit_anubhav"
      yarahub_author_email = "ankit.yara@inbox.ru"
      yarahub_reference_link = "https://twitter.com/ankit_anubhav"
      yarahub_reference_md5 = "b6c8d82a4ec67398c756fc1f36e32511"
      yarahub_uuid = "cbbe7ec6-1658-4f4b-b229-8ade27bff9f4"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malpedia_family = "win.qakbot"

strings:

  $x = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 } // OneNote header

// Variant 1
// Looking for evidence of onenote containing vbs/js/ and code to write data in registry and execute it.
// Some of these might be obfuscated so looking for a 3/5 match.
  $a = "javascript" nocase
  $b = "vbscript" nocase
  $c = "regread" nocase
  $d = "regwrite" nocase
  $e = "RegDelete" nocase

// Variant 2
// Instead of hta abuses batch and powershell to download and run the DLL

  $f = ".cmd&&start /min" nocase //edit 07.02.22 for batch file vector
  $f2 = "&&cmd /c start /min" nocase // edit 14.02.22 run command and then exit
  $g = "powershell" nocase

// Variant 3
// Involves powershell as well but obfuscation is different.
// The string powershell can not be found because it is partially hidden by environment variables.

  $tok1 = "rundll32 C:\\ProgramData\\" nocase // tok1 botnet ID

// Some cases they are obfuscating a lot by breaking all in set

$h = "set" // Look for several of these
$i = "start /min"



condition:
	$x and ((3 of ($a,$b,$c,$d,$e)) or (($f or $f2) and $g) or $tok1 or (#h > 15 and $i))


}

////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: win.qakbot_auto.yar
// repository: malpedia/signator-rules
// url: https://github.com/malpedia/signator-rules/blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.qakbot_auto.yar

// original YARA name: win_qakbot_auto
private rule Qakbot5 {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.qakbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.qakbot"
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
        $sequence_0 = { c9 c3 55 8bec 81ecc4090000 }
            // n = 5, score = 15700
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ecc4090000         | sub                 esp, 0x9c4

        $sequence_1 = { 33c0 7402 ebfa e8???????? }
            // n = 4, score = 15500
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4
            //   ebfa                 | jmp                 0xfffffffc
            //   e8????????           |                     

        $sequence_2 = { 7402 ebfa 33c0 7402 }
            // n = 4, score = 15400
            //   7402                 | je                  4
            //   ebfa                 | jmp                 0xfffffffc
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4

        $sequence_3 = { 7402 ebfa eb06 33c0 }
            // n = 4, score = 14900
            //   7402                 | je                  4
            //   ebfa                 | jmp                 0xfffffffc
            //   eb06                 | jmp                 8
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { e8???????? 33c9 85c0 0f9fc1 41 }
            // n = 5, score = 14800
            //   e8????????           |                     
            //   33c9                 | xor                 ecx, ecx
            //   85c0                 | test                eax, eax
            //   0f9fc1               | setg                cl
            //   41                   | inc                 ecx

        $sequence_5 = { 50 e8???????? 8b06 47 59 }
            // n = 5, score = 14400
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   47                   | inc                 edi
            //   59                   | pop                 ecx

        $sequence_6 = { 8d45fc 6aff 50 e8???????? }
            // n = 4, score = 14100
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_7 = { 59 59 33c0 7402 }
            // n = 4, score = 13900
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4

        $sequence_8 = { e8???????? 59 59 6afb e9???????? }
            // n = 5, score = 13800
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   6afb                 | push                -5
            //   e9????????           |                     

        $sequence_9 = { 740d 8d45fc 6a00 50 }
            // n = 4, score = 13700
            //   740d                 | je                  0xf
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_10 = { 50 8d8534f6ffff 6a00 50 e8???????? }
            // n = 5, score = 13700
            //   50                   | push                eax
            //   8d8534f6ffff         | lea                 eax, [ebp - 0x9cc]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_11 = { 8945fc e8???????? 8bf0 8d45fc 50 e8???????? }
            // n = 6, score = 13500
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_12 = { 33c0 e9???????? 33c0 7402 }
            // n = 4, score = 13400
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4

        $sequence_13 = { 7402 ebfa e9???????? 6a00 }
            // n = 4, score = 13200
            //   7402                 | je                  4
            //   ebfa                 | jmp                 0xfffffffc
            //   e9????????           |                     
            //   6a00                 | push                0

        $sequence_14 = { 8975f8 8975f0 8975f4 e8???????? }
            // n = 4, score = 13200
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   8975f0               | mov                 dword ptr [ebp - 0x10], esi
            //   8975f4               | mov                 dword ptr [ebp - 0xc], esi
            //   e8????????           |                     

        $sequence_15 = { eb0b c644301c00 ff465c 8b465c 83f840 7cf0 }
            // n = 6, score = 13000
            //   eb0b                 | jmp                 0xd
            //   c644301c00           | mov                 byte ptr [eax + esi + 0x1c], 0
            //   ff465c               | inc                 dword ptr [esi + 0x5c]
            //   8b465c               | mov                 eax, dword ptr [esi + 0x5c]
            //   83f840               | cmp                 eax, 0x40
            //   7cf0                 | jl                  0xfffffff2

        $sequence_16 = { 7cef eb10 c644301c00 ff465c 8b465c 83f838 }
            // n = 6, score = 13000
            //   7cef                 | jl                  0xfffffff1
            //   eb10                 | jmp                 0x12
            //   c644301c00           | mov                 byte ptr [eax + esi + 0x1c], 0
            //   ff465c               | inc                 dword ptr [esi + 0x5c]
            //   8b465c               | mov                 eax, dword ptr [esi + 0x5c]
            //   83f838               | cmp                 eax, 0x38

        $sequence_17 = { e8???????? 83c410 33c0 7402 }
            // n = 4, score = 12800
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4

        $sequence_18 = { 85c0 750a 33c0 7402 }
            // n = 4, score = 12700
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4

        $sequence_19 = { c644061c00 ff465c 837e5c38 7cef eb10 c644301c00 }
            // n = 6, score = 12700
            //   c644061c00           | mov                 byte ptr [esi + eax + 0x1c], 0
            //   ff465c               | inc                 dword ptr [esi + 0x5c]
            //   837e5c38             | cmp                 dword ptr [esi + 0x5c], 0x38
            //   7cef                 | jl                  0xfffffff1
            //   eb10                 | jmp                 0x12
            //   c644301c00           | mov                 byte ptr [eax + esi + 0x1c], 0

        $sequence_20 = { 7507 c7466401000000 83f840 7507 }
            // n = 4, score = 12400
            //   7507                 | jne                 9
            //   c7466401000000       | mov                 dword ptr [esi + 0x64], 1
            //   83f840               | cmp                 eax, 0x40
            //   7507                 | jne                 9

        $sequence_21 = { 837dfc00 750b 33c0 7402 }
            // n = 4, score = 12300
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   750b                 | jne                 0xd
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4

        $sequence_22 = { e8???????? e8???????? 33c0 7402 }
            // n = 4, score = 12300
            //   e8????????           |                     
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4

        $sequence_23 = { 833d????????00 7508 33c0 7402 }
            // n = 4, score = 12100
            //   833d????????00       |                     
            //   7508                 | jne                 0xa
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4

        $sequence_24 = { c7466001000000 33c0 40 5e }
            // n = 4, score = 11900
            //   c7466001000000       | mov                 dword ptr [esi + 0x60], 1
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   5e                   | pop                 esi

        $sequence_25 = { 7402 ebfa 837d1000 7408 }
            // n = 4, score = 11600
            //   7402                 | je                  4
            //   ebfa                 | jmp                 0xfffffffc
            //   837d1000             | cmp                 dword ptr [ebp + 0x10], 0
            //   7408                 | je                  0xa

        $sequence_26 = { 80ea80 8855f0 e8???????? 0fb64df7 }
            // n = 4, score = 11600
            //   80ea80               | sub                 dl, 0x80
            //   8855f0               | mov                 byte ptr [ebp - 0x10], dl
            //   e8????????           |                     
            //   0fb64df7             | movzx               ecx, byte ptr [ebp - 9]

        $sequence_27 = { 50 8d45d8 50 8d45d4 50 8d45ec }
            // n = 6, score = 9500
            //   50                   | push                eax
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   50                   | push                eax
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   50                   | push                eax
            //   8d45ec               | lea                 eax, [ebp - 0x14]

        $sequence_28 = { 56 e8???????? 8b45fc 83c40c 40 }
            // n = 5, score = 9500
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   83c40c               | add                 esp, 0xc
            //   40                   | inc                 eax

        $sequence_29 = { 6a00 6800600900 6a00 ff15???????? }
            // n = 4, score = 8800
            //   6a00                 | push                0
            //   6800600900           | push                0x96000
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_30 = { 50 ff5508 8bf0 59 }
            // n = 4, score = 6300
            //   50                   | push                eax
            //   ff5508               | call                dword ptr [ebp + 8]
            //   8bf0                 | mov                 esi, eax
            //   59                   | pop                 ecx

        $sequence_31 = { 6a00 58 0f95c0 40 50 }
            // n = 5, score = 5800
            //   6a00                 | push                0
            //   58                   | pop                 eax
            //   0f95c0               | setne               al
            //   40                   | inc                 eax
            //   50                   | push                eax

        $sequence_32 = { 57 ff15???????? 33c0 85f6 0f94c0 }
            // n = 5, score = 5200
            //   57                   | push                edi
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   85f6                 | test                esi, esi
            //   0f94c0               | sete                al

        $sequence_33 = { 750c 57 ff15???????? 6afe 58 }
            // n = 5, score = 5200
            //   750c                 | jne                 0xe
            //   57                   | push                edi
            //   ff15????????         |                     
            //   6afe                 | push                -2
            //   58                   | pop                 eax

        $sequence_34 = { c3 33c9 3d80000000 0f94c1 }
            // n = 4, score = 5200
            //   c3                   | ret                 
            //   33c9                 | xor                 ecx, ecx
            //   3d80000000           | cmp                 eax, 0x80
            //   0f94c1               | sete                cl

        $sequence_35 = { 6a02 ff15???????? 8bf8 83c8ff }
            // n = 4, score = 5000
            //   6a02                 | push                2
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   83c8ff               | or                  eax, 0xffffffff

        $sequence_36 = { 50 e8???????? 6a40 8d4590 }
            // n = 4, score = 4500
            //   50                   | push                eax
            //   e8????????           |                     
            //   6a40                 | push                0x40
            //   8d4590               | lea                 eax, [ebp - 0x70]

        $sequence_37 = { 8d85e4fcffff 50 8d85e4fdffff 50 }
            // n = 4, score = 4300
            //   8d85e4fcffff         | lea                 eax, [ebp - 0x31c]
            //   50                   | push                eax
            //   8d85e4fdffff         | lea                 eax, [ebp - 0x21c]
            //   50                   | push                eax

        $sequence_38 = { 56 e8???????? 83c40c 8d4514 50 }
            // n = 5, score = 4000
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d4514               | lea                 eax, [ebp + 0x14]
            //   50                   | push                eax

        $sequence_39 = { e8???????? 6a00 8d45d4 50 68???????? }
            // n = 5, score = 500
            //   e8????????           |                     
            //   6a00                 | push                0
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_40 = { 5d c3 33c9 66890c46 }
            // n = 4, score = 300
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   33c9                 | xor                 ecx, ecx
            //   66890c46             | mov                 word ptr [esi + eax*2], cx

        $sequence_41 = { 8b4a04 83c204 03f0 85c9 75e1 }
            // n = 5, score = 100
            //   8b4a04               | mov                 ecx, dword ptr [edx + 4]
            //   83c204               | add                 edx, 4
            //   03f0                 | add                 esi, eax
            //   85c9                 | test                ecx, ecx
            //   75e1                 | jne                 0xffffffe3

        $sequence_42 = { 01f1 898424a8000000 899424ac000000 8d8424b4000000 89c2 8db424c4000000 }
            // n = 6, score = 100
            //   01f1                 | add                 ecx, esi
            //   898424a8000000       | mov                 dword ptr [esp + 0xa8], eax
            //   899424ac000000       | mov                 dword ptr [esp + 0xac], edx
            //   8d8424b4000000       | lea                 eax, [esp + 0xb4]
            //   89c2                 | mov                 edx, eax
            //   8db424c4000000       | lea                 esi, [esp + 0xc4]

        $sequence_43 = { 8a442417 8b4c2410 0485 88440c66 89ca 83c201 }
            // n = 6, score = 100
            //   8a442417             | mov                 al, byte ptr [esp + 0x17]
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   0485                 | add                 al, 0x85
            //   88440c66             | mov                 byte ptr [esp + ecx + 0x66], al
            //   89ca                 | mov                 edx, ecx
            //   83c201               | add                 edx, 1

        $sequence_44 = { ffd3 85ff 741b 6808020000 6a00 }
            // n = 5, score = 100
            //   ffd3                 | call                ebx
            //   85ff                 | test                edi, edi
            //   741b                 | je                  0x1d
            //   6808020000           | push                0x208
            //   6a00                 | push                0

        $sequence_45 = { 88442401 894c245c 0f847afdffff e9???????? }
            // n = 4, score = 100
            //   88442401             | mov                 byte ptr [esp + 1], al
            //   894c245c             | mov                 dword ptr [esp + 0x5c], ecx
            //   0f847afdffff         | je                  0xfffffd80
            //   e9????????           |                     

        $sequence_46 = { 89442410 884c2417 eb94 55 89e5 31c0 }
            // n = 6, score = 100
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   884c2417             | mov                 byte ptr [esp + 0x17], cl
            //   eb94                 | jmp                 0xffffff96
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   31c0                 | xor                 eax, eax

        $sequence_47 = { 8945fc 8b4518 53 8b5d10 56 8945c4 }
            // n = 6, score = 100
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]
            //   53                   | push                ebx
            //   8b5d10               | mov                 ebx, dword ptr [ebp + 0x10]
            //   56                   | push                esi
            //   8945c4               | mov                 dword ptr [ebp - 0x3c], eax

        $sequence_48 = { 8b742420 81c638a1e7c3 39f0 89442410 894c240c 89542408 7408 }
            // n = 7, score = 100
            //   8b742420             | mov                 esi, dword ptr [esp + 0x20]
            //   81c638a1e7c3         | add                 esi, 0xc3e7a138
            //   39f0                 | cmp                 eax, esi
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   894c240c             | mov                 dword ptr [esp + 0xc], ecx
            //   89542408             | mov                 dword ptr [esp + 8], edx
            //   7408                 | je                  0xa

        $sequence_49 = { 8b74242c bb3c13b648 f7e3 69f63c13b648 01f2 89442428 8954242c }
            // n = 7, score = 100
            //   8b74242c             | mov                 esi, dword ptr [esp + 0x2c]
            //   bb3c13b648           | mov                 ebx, 0x48b6133c
            //   f7e3                 | mul                 ebx
            //   69f63c13b648         | imul                esi, esi, 0x48b6133c
            //   01f2                 | add                 edx, esi
            //   89442428             | mov                 dword ptr [esp + 0x28], eax
            //   8954242c             | mov                 dword ptr [esp + 0x2c], edx

        $sequence_50 = { 8b4c2444 ffd1 83ec08 b901000000 ba66000000 31ff 89c3 }
            // n = 7, score = 100
            //   8b4c2444             | mov                 ecx, dword ptr [esp + 0x44]
            //   ffd1                 | call                ecx
            //   83ec08               | sub                 esp, 8
            //   b901000000           | mov                 ecx, 1
            //   ba66000000           | mov                 edx, 0x66
            //   31ff                 | xor                 edi, edi
            //   89c3                 | mov                 ebx, eax

        $sequence_51 = { 89e0 89580c bb04000000 895808 8b5c246c 895804 8b9c2480000000 }
            // n = 7, score = 100
            //   89e0                 | mov                 eax, esp
            //   89580c               | mov                 dword ptr [eax + 0xc], ebx
            //   bb04000000           | mov                 ebx, 4
            //   895808               | mov                 dword ptr [eax + 8], ebx
            //   8b5c246c             | mov                 ebx, dword ptr [esp + 0x6c]
            //   895804               | mov                 dword ptr [eax + 4], ebx
            //   8b9c2480000000       | mov                 ebx, dword ptr [esp + 0x80]

        $sequence_52 = { 8bf0 83c40c 85f6 0f84f8000000 a1???????? }
            // n = 5, score = 100
            //   8bf0                 | mov                 esi, eax
            //   83c40c               | add                 esp, 0xc
            //   85f6                 | test                esi, esi
            //   0f84f8000000         | je                  0xfe
            //   a1????????           |                     

    condition:
        7 of them and filesize < 4883456
}
////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: win_qakbot_api_hashing_oct_2022.yar
// repository: embee-research/Yara-detection-rules
// url: https://github.com/embee-research/Yara-detection-rules/blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/2022/win_qakbot_api_hashing_oct_2022.yar


// original YARA name: win_qakbot_api_hashing_oct_2022
private rule Qakbot6 {
	meta:
		author = "@Embee_Research"
		vendor = "Huntress Labs"
		created = "2022/11/14"
		updated = "2022/12/01"
		reference =  "@Embee_Research @HuntressLabs"
		reference = "https://twitter.com/embee_research/status/1592067841154756610"
	strings:
		
		//Qakbot string hashing routine extracted from Ghidra
		//This is unique to qakbot samples
		$qakbot_hashing = {0f b6 04 39 33 f0 8b c6 c1 ee 04 83 e0 0f 33 34 85 ?? ?? ?? ?? 8b c6 c1 ee 04 83 e0 0f 33 34 85 ?? ?? ?? ?? 41 3b ca} 

		
	condition:
		uint16(0) == 0x5a4d and any of them
}

////////////////////////////////////////////////////////



////////////////////////////////////////////////////////
// YARA ruleset: QakBot.yar
// repository: ctxis/CAPE
// url: https://github.com/ctxis/CAPE/blob/dae9fa6a254ecdbabeb7eb0d2389fa63722c1e82/data/yara/CAPE/QakBot.yar

// original YARA name: QakBot
private rule Qakbot7 {
    meta:
        author = "kevoreilly"
        description = "QakBot Payload"
        cape_type = "QakBot Payload"
    strings:
        $crypto = {8B 5D 08 0F B6 C2 8A 16 0F B6 1C 18 88 55 13 0F B6 D2 03 CB 03 CA 81 E1 FF 00 00 80 79 08 49 81 C9 00 FF FF FF 41}
        $anti_sandbox = {8D 4D FC 51 E8 ?? ?? ?? ?? 83 C4 04 E8 ?? ?? ?? ?? 85 C0 7E 07 C7 45 F8 00 00 00 00 33 D2 74 02 EB FA 8B 45 F8 EB 08 33 C0 74 02 EB FA 33 C0 8B E5 5D C3}
        $decrypt_config1 = {FF 37 83 C3 EC 53 8B 5D 0C 8D 43 14 50 6A 14 53 E8 ?? ?? ?? ?? 83 C4 14 85 C0 ?? 26 ?? ?? 86 20 02 00 00 66 85 C0 ?? ?? FF 37 FF 75 10 53}
        $decrypt_config2 = {8B 45 08 8B 88 24 04 00 00 51 8B 55 10 83 EA 14 52 8B 45 0C 83 C0 14 50 6A 14 8B 4D 0C 51 E8 6C 08 00 00}
    condition:
        uint16(0) == 0x5A4D and any of ($*)
}

////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: win_qakbot_string_decrypt_nov_2022.yar
// repository: embee-research/Yara-detection-rules
// url: https://github.com/embee-research/Yara-detection-rules/blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/2022/win_qakbot_string_decrypt_nov_2022.yar

// original YARA name: win_qakbot_string_decrypt_nov_2022
private rule Qakbot8 {
	meta:
		author = "Embee_Research @ Huntress"
		created = "2022/11/14"
	strings:
		
		//Qakbot string hashing routine extracted from Ghidra
		$qakbot_decrypt = {33 d2 8b c7 f7 75 10 8a 04 1a 8b 55 fc 32 04 17 88 04 39 47 83 ee 01} 
	
		
	condition:
		uint16(0) == 0x5a4d and 
		$qakbot_decrypt 
}
////////////////////////////////////////////////////////


rule fsQakbot {
    meta:
        description = "FsYARA - Malware Trends"
        vetted_family = "qakbot"
	condition:
		Qakbot0 or Qakbot1 or Qakbot2 or Qakbot3 or Qakbot4 or Qakbot5 or Qakbot6 or Qakbot7 or Qakbot8
}