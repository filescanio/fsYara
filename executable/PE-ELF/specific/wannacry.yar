private rule MS17_010_WanaCry_worm : refined hardened
{
	meta:
		description = "Worm exploiting MS17-010 and dropping WannaCry Ransomware"
		author = "Felipe Molina (@felmoltor)"
		reference = "https://www.exploit-db.com/exploits/41987/"
		date = "2017/05/12"

	strings:
		$ms17010_str1 = {50 43 20 4e 45 54 57 4f 52 4b 20 50 52 4f 47 52 41 4d 20 31 2e 30}
		$ms17010_str2 = {4c 41 4e 4d 41 4e 31 2e 30}
		$ms17010_str3 = {57 69 6e 64 6f 77 73 20 66 6f 72 20 57 6f 72 6b 67 72 6f 75 70 73 20 33 2e 31 61}
		$ms17010_str4 = {5f 5f 54 52 45 45 49 44 5f 5f 50 4c 41 43 45 48 4f 4c 44 45 52 5f 5f}
		$ms17010_str5 = {5f 5f 55 53 45 52 49 44 5f 5f 50 4c 41 43 45 48 4f 4c 44 45 52 5f 5f}
		$wannacry_payload_substr1 = {68 36 61 67 4c 43 71 50 71 56 79 58 69 32 56 53 51 38 4f 36 59 62 39 69 6a 42 58 35 34 6a}
		$wannacry_payload_substr2 = {68 35 34 57 66 46 39 63 47 69 67 57 46 45 78 39 32 62 7a 6d 4f 64 30 55 4f 61 5a 6c 4d}
		$wannacry_payload_substr3 = {74 70 47 46 45 6f 4c 4f 55 36 2b 35 49 37 38 54 6f 68 2f 6e 48 73 2f 52 41 50}

	condition:
		all of them
}

rule WannaDecryptor : hardened
{
	meta:
		description = "Detection for common strings of WannaDecryptor"

	strings:
		$id1 = {74 61 73 6b 64 6c 2e 65 78 65}
		$id2 = {74 61 73 6b 73 65 2e 65 78 65}
		$id3 = {72 2e 77 6e 72 79}
		$id4 = {73 2e 77 6e 72 79}
		$id5 = {74 2e 77 6e 72 79}
		$id6 = {75 2e 77 6e 72 79}
		$id7 = {6d 73 67 2f 6d 5f}

	condition:
		3 of them
}

rule Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549 : hardened
{
	meta:
		description = "Specific sample match for WannaCryptor"
		MD5 = "84c82835a5d21bbcf75a61706d8ab549"
		SHA1 = "5ff465afaabcbf0150d1a3ab2c2e74f3a4426467"
		SHA256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
		INFO = "Looks for 'taskdl' and 'taskse' at known offsets"

	strings:
		$taskdl = { 00 74 61 73 6b 64 6c }
		$taskse = { 00 74 61 73 6b 73 65 }

	condition:
		$taskdl at 3419456 and $taskse at 3422953
}

rule Wanna_Sample_4da1f312a214c07143abeeafb695d904 : hardened
{
	meta:
		description = "Specific sample match for WannaCryptor"
		MD5 = "4da1f312a214c07143abeeafb695d904"
		SHA1 = "b629f072c9241fd2451f1cbca2290197e72a8f5e"
		SHA256 = "aee20f9188a5c3954623583c6b0e6623ec90d5cd3fdec4e1001646e27664002c"
		INFO = "Looks for offsets of r.wry and s.wry instances"

	strings:
		$rwnry = { 72 2e 77 72 79 }
		$swnry = { 73 2e 77 72 79 }

	condition:
		$rwnry at 88195 and $swnry at 88656 and $rwnry at 4495639
}

private rule NHS_Strain_Wanna : NHS_Strain_Wanna refined hardened
{
	meta:
		description = "Detection for worm-strain bundle of Wcry, DOublePulsar"
		MD5 = "db349b97c37d22f5ea1d1841e3c89eb4"
		SHA1 = "e889544aff85ffaf8b0d0da705105dee7c97fe26"
		SHA256 = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
		INFO = "Looks for specific offsets of c.wnry and t.wnry strings"

	strings:
		$cwnry = { 63 2e 77 6e 72 79 }
		$twnry = { 74 2e 77 6e 72 79 }

	condition:
		$cwnry at 262324 and $twnry at 267672 and $cwnry at 284970
}

private rule ransom_telefonica : TELEF refined hardened limited
{
	meta:
		author = "Jaume Martin <@Xumeiquer>"
		description = "Ransmoware Telefonica"
		date = "2017-05-13"
		reference = "http://www.elmundo.es/tecnologia/2017/05/12/59158a8ce5fdea194f8b4616.html"
		md5 = "7f7ccaa16fb15eb1c7399d422f8363e8"
		sha256 = "2584e1521065e45ec3c17767c065429038fc6291c091097ea8b22c8a502c41dd"

	strings:
		$a = {((52 65 67 43 72 65 61 74 65 4b 65 79 57) | (52 00 65 00 67 00 43 00 72 00 65 00 61 00 74 00 65 00 4b 00 65 00 79 00 57 00))}
		$b = {63 6d 64 2e 65 78 65 20 2f 63}
		$c = {31 31 35 70 37 55 4d 4d 6e 67 6f 6a 31 70 4d 76 6b 70 48 69 6a 63 52 64 66 4a 4e 58 6a 36 4c 72 4c 6e}
		$d = {31 32 74 39 59 44 50 67 77 75 65 5a 39 4e 79 4d 67 77 35 31 39 70 37 41 41 38 69 73 6a 72 36 53 4d 77}
		$e = {31 33 41 4d 34 56 57 32 64 68 78 59 67 58 65 51 65 70 6f 48 6b 48 53 51 75 79 36 4e 67 61 45 62 39 34}
		$f = {74 61 73 6b 73 63 68 65 2e 65 78 65}

	condition:
		uint16( 0 ) == 0x5A4D and $a and for all of ( $b , $c , $d , $e , $f ) : ( @ > @a )
}

private rule Wanna_Cry_Ransomware_Generic : refined hardened
{
	meta:
		description = "Detects WannaCry Ransomware on Disk and in Virtual Page"
		author = "US-CERT Code Analysis Team"
		reference = "not set"
		date = "2017/05/12"
		hash0 = "4DA1F312A214C07143ABEEAFB695D904"

	strings:
		$s0 = {410044004D0049004E0024}
		$s1 = {57 61 6e 6e 61 44 65 63 72 79 70 74 6f 72}
		$s2 = {57 41 4e 4e 41 43 52 59}
		$s3 = {4d 69 63 72 6f 73 6f 66 74 20 45 6e 68 61 6e 63 65 64 20 52 53 41 20 61 6e 64 20 41 45 53 20 43 72 79 70 74 6f 67 72 61 70 68 69 63}
		$s4 = {50 4b 53}
		$s5 = {53 74 61 72 74 54 61 73 6b}
		$s6 = {77 63 72 79 40 31 32 33}
		$s7 = {2F6600002F72}
		$s8 = {75 6e 7a 69 70 20 30 2e 31 35 20 43 6f 70 79 72 69 67 68}
		$s9 = {47 6c 6f 62 61 6c 5c 57 49 4e 44 4f 57 53 5f 54 41 53 4b 4f 53 48 54 5f 4d 55 54 45 58}
		$s10 = {47 6c 6f 62 61 6c 5c 57 49 4e 44 4f 57 53 5f 54 41 53 4b 43 53 54 5f 4d 55 54 45 58}
		$s11 = {7461736B736368652E657865000000005461736B5374617274000000742E776E7279000069636163}
		$s12 = {6C73202E202F6772616E742045766572796F6E653A46202F54202F43202F5100617474726962202B68}
		$s13 = {57 4e 63 72 79 40 32 6f 6c 37}
		$s14 = {77 63 72 79 40 31 32 33}
		$s15 = {47 6c 6f 62 61 6c 5c 4d 73 57 69 6e 5a 6f 6e 65 73 43 61 63 68 65 43 6f 75 6e 74 65 72 4d 75 74 65 78 41}

	condition:
		$s0 and $s1 and $s2 and $s3 or $s4 and $s5 and $s6 and $s7 or $s8 and $s9 and $s10 or $s11 and $s12 or $s13 or $s14 or $s15
}

rule WannaCry_Ransomware : refined hardened
{
	meta:
		description = "Detects WannaCry Ransomware"
		author = "Florian Roth (with the help of binar.ly)"
		reference = "https://goo.gl/HG2j5T"
		date = "2017-05-12"
		hash1 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
		hash2 = "9fe91d542952e145f2244572f314632d93eb1e8657621087b2ca7f7df2b0cb05"
		hash3 = "8e5b5841a3fe81cade259ce2a678ccb4451725bba71f6662d0cc1f08148da8df"
		hash4 = "4384bf4530fb2e35449a8e01c7e0ad94e3a25811ba94f7847c1e6612bbb45359"

	strings:
		$x1 = {69 63 61 63 6c 73 20 2e 20 2f 67 72 61 6e 74 20 45 76 65 72 79 6f 6e 65 3a 46 20 2f 54 20 2f 43 20 2f 51}
		$x2 = {74 61 73 6b 64 6c 2e 65 78 65}
		$x3 = {74 61 73 6b 73 63 68 65 2e 65 78 65}
		$x4 = {47 6c 6f 62 61 6c 5c 4d 73 57 69 6e 5a 6f 6e 65 73 43 61 63 68 65 43 6f 75 6e 74 65 72 4d 75 74 65 78 41}
		$x5 = {57 4e 63 72 79 40 32 6f 6c 37}
		$x6 = {77 77 77 2e 69 75 71 65 72 66 73 6f 64 70 39 69 66 6a 61 70 6f 73 64 66 6a 68 67 6f 73 75 72 69 6a 66 61 65 77 72 77 65 72 67 77 65 61 2e 63 6f 6d}
		$x7 = {6d 73 73 65 63 73 76 63 2e 65 78 65}
		$x8 = {43 3a 5c 25 73 5c 71 65 72 69 75 77 6a 68 72 66}
		$x9 = {69 63 61 63 6c 73 20 2e 20 2f 67 72 61 6e 74 20 45 76 65 72 79 6f 6e 65 3a 46 20 2f 54 20 2f 43 20 2f 51}
		$s1 = {43 3a 5c 25 73 5c 25 73}
		$s2 = {3c 21 2d 2d 20 57 69 6e 64 6f 77 73 20 31 30 20 2d 2d 3e 20}
		$s3 = {63 6d 64 2e 65 78 65 20 2f 63 20 22 25 73 22}
		$s4 = {6d 73 67 2f 6d 5f 70 6f 72 74 75 67 75 65 73 65 2e 77 6e 72 79}
		$s5 = {5c 00 5c 00 31 00 39 00 32 00 2e 00 31 00 36 00 38 00 2e 00 35 00 36 00 2e 00 32 00 30 00 5c 00 49 00 50 00 43 00 24 00}
		$s6 = {5c 00 5c 00 31 00 37 00 32 00 2e 00 31 00 36 00 2e 00 39 00 39 00 2e 00 35 00 5c 00 49 00 50 00 43 00 24 00}
		$op1 = { 10 ac 72 0d 3d ff ff 1f ac 77 06 b8 01 00 00 00 }
		$op2 = { 44 24 64 8a c6 44 24 65 0e c6 44 24 66 80 c6 44 }
		$op3 = { 18 df 6c 24 14 dc 64 24 2c dc 6c 24 5c dc 15 88 }
		$op4 = { 09 ff 76 30 50 ff 56 2c 59 59 47 3b 7e 0c 7c }
		$op5 = { c1 ea 1d c1 ee 1e 83 e2 01 83 e6 01 8d 14 56 }
		$op6 = { 8d 48 ff f7 d1 8d 44 10 ff 23 f1 23 c1 }
		$gen1 = {5f 5f 54 52 45 45 49 44 5f 5f 50 4c 41 43 45 48 4f 4c 44 45 52 5f 5f}
		$gen2 = {5f 5f 55 53 45 52 49 44 5f 5f 50 4c 41 43 45 48 4f 4c 44 45 52 5f 5f}
		$gen3 = {57 69 6e 64 6f 77 73 20 66 6f 72 20 57 6f 72 6b 67 72 6f 75 70 73 20 33 2e 31 61}
		$gen4 = {50 43 20 4e 45 54 57 4f 52 4b 20 50 52 4f 47 52 41 4d 20 31 2e 30}
		$gen5 = {4c 41 4e 4d 41 4e 31 2e 30}

	condition:
		uint16( 0 ) == 0x5a4d and ( ( filesize < 10000KB and ( 1 of ( $x* ) and 1 of ( $s* ) or 3 of ( $op* ) ) ) or filesize < 5000KB and all of ( $gen* ) )
}

private rule WannaCry_Ransomware_Dropper : refined hardened
{
	meta:
		description = "WannaCry Ransomware Dropper"
		reference = "https://www.cylance.com/en_us/blog/threat-spotlight-inside-the-wannacry-attack.html"
		date = "2017-05-12"

	strings:
		$s1 = {63 6d 64 2e 65 78 65 20 2f 63 20 22 25 73 22}
		$s2 = {74 61 73 6b 73 63 68 65 2e 65 78 65}
		$s3 = {69 63 61 63 6c 73 20 2e 20 2f 67 72 61 6e 74 20 45 76 65 72 79 6f 6e 65 3a 46 20 2f 54 20 2f 43 20 2f 51}
		$s4 = {47 6c 6f 62 61 6c 5c 4d 73 57 69 6e 5a 6f 6e 65 73 43 61 63 68 65 43 6f 75 6e 74 65 72 4d 75 74 65 78 41}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 4MB and all of them
}

import "pe"

rule WannaCry_SMB_Exploit : hardened
{
	meta:
		description = "WannaCry SMB Exploit"
		reference = "https://www.cylance.com/en_us/blog/threat-spotlight-inside-the-wannacry-attack.html"
		date = "2017-05-12"

	strings:
		$s1 = { 53 4D 42 72 00 00 00 00 18 53 C0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FE 00 00 40 00 00 62 00 02 50 43 20 4E 45 54 57 4F 52 4B 20 50 52 4F 47 52 41 4D 20 31 2E 30 00 02 4C 41 4E 4D 41 4E 31 2E 30 00 02 57 69 6E 64 6F 77 73 20 66 6F 72 20 57 6F 72 6B 67 72 6F 75 70 73 20 33 2E 31 61 00 02 4C 4D 31 2E 32 58 30 30 32 00 02 4C 41 4E 4D 41 4E 32 2E 31 00 02 4E 54 20 4C 4D 20 30 2E 31 32 00 00 00 00 00 00 00 88 FF 53 4D 42 73 00 00 00 00 18 07 C0 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 4MB and all of them and pe.imports ( "ws2_32.dll" , "connect" ) and pe.imports ( "ws2_32.dll" , "send" ) and pe.imports ( "ws2_32.dll" , "recv" ) and pe.imports ( "ws2_32.dll" , "socket" ) and pe.imports ( "ws2_32.dll" , "closesocket" )
}

private rule wannacry_static_ransom : wannacry_static_ransom refined hardened
{
	meta:
		description = "Detects WannaCryptor spreaded during 2017-May-12th campaign and variants"
		author = "Blueliv"
		reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"
		date = "2017-05-15"

	strings:
		$mutex01 = {47 6c 6f 62 61 6c 5c 4d 73 57 69 6e 5a 6f 6e 65 73 43 61 63 68 65 43 6f 75 6e 74 65 72 4d 75 74 65 78 41}
		$lang01 = {6d 5f 62 75 6c 67 61 72 69 61 6e 2e 77 6e 72}
		$lang02 = {6d 5f 76 69 65 74 6e 61 6d 65 73 65 2e 77 6e 72 79}
		$startarg01 = {53 74 61 72 74 54 61 73 6b}
		$startarg02 = {54 61 73 6b 53 74 61 72 74}
		$startarg03 = {53 74 61 72 74 53 63 68 65 64 75 6c 65}
		$wcry01 = {((57 61 6e 61 43 72 79 70 74 30 72) | (57 00 61 00 6e 00 61 00 43 00 72 00 79 00 70 00 74 00 30 00 72 00))}
		$wcry02 = {57 41 4e 41 43 52 59}
		$wcry03 = {57 41 4e 4e 41 43 52 59}
		$wcry04 = {((57 4e 43 52 59 54) | (57 00 4e 00 43 00 52 00 59 00 54 00))}
		$forig01 = {2e 77 6e 72 79 00}
		$fvar01 = {2e 77 72 79 00}

	condition:
		($mutex01 or any of ( $lang* ) ) and ( $forig01 or all of ( $fvar* ) ) and any of ( $wcry* ) and any of ( $startarg* )
}

rule wannacry_memory_ransom : wannacry_memory_ransom hardened
{
	meta:
		description = "Detects WannaCryptor spreaded during 2017-May-12th campaign and variants in memory"
		author = "Blueliv"
		reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"
		date = "2017-05-15"

	strings:
		$s01 = {25 30 38 58 2e 65 6b 79}
		$s02 = {25 30 38 58 2e 70 6b 79}
		$s03 = {25 30 38 58 2e 72 65 73}
		$s04 = {25 30 38 58 2e 64 6b 79}
		$s05 = {40 57 61 6e 61 44 65 63 72 79 70 74 6f 72 40 2e 65 78 65}

	condition:
		all of them
}

private rule worm_ms17_010 : worm_ms17_010 refined hardened
{
	meta:
		description = "Detects Worm used during 2017-May-12th WannaCry campaign, which is based on ETERNALBLUE"
		author = "Blueliv"
		reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"
		date = "2017-05-15"

	strings:
		$s01 = {5f 5f 54 52 45 45 49 44 5f 5f 50 4c 41 43 45 48 4f 4c 44 45 52 5f 5f}
		$s02 = {5f 5f 55 53 45 52 49 44 5f 5f 50 4c 41 43 45 48 4f 4c 44 45 52 5f 5f 40}
		$s03 = {53 4d 42 33}
		$s05 = {53 4d 42 75}
		$s06 = {53 4d 42 73}
		$s07 = {53 4d 42 72}
		$s08 = {25 73 20 2d 6d 20 73 65 63 75 72 69 74 79}
		$s09 = {25 64 2e 25 64 2e 25 64 2e 25 64}
		$payloadwin2000_2195 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 32 00 30 00 30 00 30 00 20 00 32 00 31 00 39 00 35 00 00 00}
		$payload2000_50 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 32 00 30 00 30 00 30 00 20 00 35 00 2e 00 30 00 00 00}

	condition:
		all of them
}

rule wannacry_wrapper : hardened
{
	meta:
		description = "Matches one or more wannacry yara rules"
		author = "Filescan"
		date = "2023-0525"
		vetted_family = "Wannacry"

	condition:
		MS17_010_WanaCry_worm or NHS_Strain_Wanna or worm_ms17_010 or wannacry_static_ransom or WannaCry_Ransomware_Dropper or ransom_telefonica or Wanna_Cry_Ransomware_Generic
}

rule WannCry_m_vbs : hardened
{
	meta:
		description = "Detects WannaCry Ransomware VBS"
		author = "Florian Roth"
		reference = "https://goo.gl/HG2j5T"
		date = "2017-05-12"
		hash1 = "51432d3196d9b78bdc9867a77d601caffd4adaa66dcac944a5ba0b3112bbea3b"

	strings:
		$x1 = {2e 54 61 72 67 65 74 50 61 74 68 20 3d 20 22 43 3a 5c 40}
		$x2 = {2e 43 72 65 61 74 65 53 68 6f 72 74 63 75 74 28 22 43 3a 5c 40}
		$s3 = {20 3d 20 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29}

	condition:
		( uint16( 0 ) == 0x4553 and filesize < 1KB and all of them )
}

rule WannCry_BAT : hardened
{
	meta:
		description = "Detects WannaCry Ransomware BATCH File"
		author = "Florian Roth"
		reference = "https://goo.gl/HG2j5T"
		date = "2017-05-12"
		hash1 = "f01b7f52e3cb64f01ddc248eb6ae871775ef7cb4297eba5d230d0345af9a5077"

	strings:
		$s1 = {40 2e 65 78 65 22 3e 3e 20 6d 2e 76 62 73}
		$s2 = {63 73 63 72 69 70 74 2e 65 78 65 20 2f 2f 6e 6f 6c 6f 67 6f 20 6d 2e 76 62 73}
		$s3 = {65 63 68 6f 20 53 45 54 20 6f 77 20 3d 20 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 3e 20}
		$s4 = {65 63 68 6f 20 6f 6d 2e 53 61 76 65 3e 3e 20 6d 2e 76 62 73}

	condition:
		( uint16( 0 ) == 0x6540 and filesize < 1KB and 1 of them )
}

rule WannaCry_RansomNote : hardened
{
	meta:
		description = "Detects WannaCry Ransomware Note"
		author = "Florian Roth"
		reference = "https://goo.gl/HG2j5T"
		date = "2017-05-12"
		hash1 = "4a25d98c121bb3bd5b54e0b6a5348f7b09966bffeec30776e5a731813f05d49e"

	strings:
		$s1 = {41 3a 20 20 44 6f 6e 27 74 20 77 6f 72 72 79 20 61 62 6f 75 74 20 64 65 63 72 79 70 74 69 6f 6e 2e}
		$s2 = {51 3a 20 20 57 68 61 74 27 73 20 77 72 6f 6e 67 20 77 69 74 68 20 6d 79 20 66 69 6c 65 73 3f}

	condition:
		( uint16( 0 ) == 0x3a51 and filesize < 2KB and all of them )
}

rule lazaruswannacry : hardened
{
	meta:
		description = "Rule based on shared code between Feb 2017 Wannacry sample and Lazarus backdoor from Feb 2015 discovered by Neel Mehta"
		date = "2017-05-15"
		reference = "https://twitter.com/neelmehta/status/864164081116225536"
		author = "Costin G. Raiu, Kaspersky Lab"
		version = "1.0"
		hash = "9c7c7149387a1c79679a87dd1ba755bc"
		hash = "ac21c8ad899727137c4b94458d7aa8d8"

	strings:
		$a1 = { 51 53 55 8B 6C 24 10 56 57 6A 20 8B 45 00 8D 75 04 24 01 0C 01 46 89 45 00 C6 46 FF 03 C6 06 01 46 56 E8 }
		$a2 = { 03 00 04 00 05 00 06 00 08 00 09 00 0A 00 0D 00 10 00 11 00 12 00 13 00 14 00 15 00 16 00 2F 00 30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00 3C 00 3D 00 3E 00 3F 00 40 00 41 00 44 00 45 00 46 00 62 00 63 00 64 00 66 00 67 00 68 00 69 00 6A 00 6B 00 84 00 87 00 88 00 96 00 FF 00 01 C0 02 C0 03 C0 04 C0 05 C0 06 C0 07 C0 08 C0 09 C0 0A C0 0B C0 0C C0 0D C0 0E C0 0F C0 10 C0 11 C0 12 C0 13 C0 14 C0 23 C0 24 C0 27 C0 2B C0 2C C0 FF FE }

	condition:
		uint16( 0 ) == 0x5A4D and filesize < 15000000 and all of them
}

import "pe"

rule Win32_Ransomware_WannaCry : tc_detection malicious hardened
{
	meta:
		author = "ReversingLabs"
		source = "ReversingLabs"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		malware = "WANNACRY"
		description = "Yara rule that detects WannaCry ransomware."
		tc_detection_type = "Ransomware"
		tc_detection_name = "WannaCry"
		tc_detection_factor = 5

	strings:
		$main_1 = {
            A0 ?? ?? ?? ?? 56 57 6A ?? 88 85 ?? ?? ?? ?? 59 33 C0 8D BD ?? ?? ?? ?? F3 AB 66 AB 
            AA 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 53 FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 85 
            ?? ?? ?? ?? 6A ?? 50 FF D6 59 85 C0 59 74 ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF D6 59 88 
            18 59 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 
            8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 53 53 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 85 
            C0 74 ?? 8D 45 ?? 8D 8D ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 89 5D
        }
		$main_2 = {
            68 ?? ?? ?? ?? 33 DB 50 53 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 FF 15 
            ?? ?? ?? ?? 83 38 ?? 75 ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 00 FF 70 ?? E8 ?? ?? 
            ?? ?? 59 85 C0 59 75 ?? 53 E8 ?? ?? ?? ?? 85 C0 59 74 ?? BE ?? ?? ?? ?? 53 8D 85 ?? 
            ?? ?? ?? 56 50 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 83 F8 ?? 74 ?? E8 ?? ?? ?? ?? 
            85 C0 0F 85 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF D6 59 85 C0 
            59 74 ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF D6 59 88 18 59 8D 85 ?? ?? ?? ?? 50 FF 15 ?? 
            ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            53 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 53 68 ?? ?? ?? ?? E8
        }
		$main_3 = {
            83 EC ?? 56 57 B9 ?? ?? ?? ?? BE ?? ?? ?? ?? 8D 7C 24 ?? 33 C0 F3 A5 A4 89 44 24 ?? 
            89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 66 89 44 24 ?? 50 50 50 6A ?? 50 88 
            44 24 ?? FF 15 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 8D 4C 24 ?? 8B F0 6A ?? 51 56 
            FF 15 ?? ?? ?? ?? 8B F8 56 8B 35 ?? ?? ?? ?? 85 FF 75 ?? FF D6 6A ?? FF D6 E8
        }
		$start_service_3 = {
            83 EC ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 83 
            38 ?? 7D ?? E8 ?? ?? ?? ?? 83 C4 ?? C3 57 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? 
            ?? 8B F8 85 FF 74 ?? 53 56 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 8B 1D 
            ?? ?? ?? ?? 8B F0 85 F6 74 ?? 6A ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 56 FF D3 57 FF D3 5E 
            5B 8D 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 50 C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? 
            ?? ?? C7 44 24 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 5F 83 C4 ?? C3 
        }
		$main_4 = {
            83 EC ?? 57 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B F8 85 FF 74 ?? 53 56 68 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8B F0 85 F6 74 ?? 
            6A ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 56 FF D3 57 FF D3 5E 5B 8D 44 24 ?? C7 44 24 ?? ?? 
            ?? ?? ?? 50 C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 
            FF 15 ?? ?? ?? ?? 33 C0 5F 83 C4 ?? C2 
        }
		$main_5 = {
            68 ?? ?? ?? ?? 50 53 FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 
            FF D6 59 85 C0 59 74 ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF D6 59 88 18 59 8D 85 ?? ?? ?? 
            ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 8D 8D ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 53 53 53 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 85 C0 74 ?? 8D 45 ?? 8D 
            8D ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 89 5D ?? E8 ?? ?? ?? ?? 3B C3 74 ?? FF 75 ?? 50 E8 
            ?? ?? ?? ?? 59 3B C3 59 74 ?? 68 ?? ?? ?? ?? 50 E8
        }
		$main_6 = {
            FF 74 24 ?? FF 74 24 ?? FF 74 24 ?? FF 74 24 ?? E8 ?? ?? ?? ?? C2
        }
		$set_reg_key_6 = {
            68 ?? ?? ?? ?? F3 AB 66 AB AA 8D 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 50 FF 15 ?? ?? ?? 
            ?? 8B 2D ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 83 C4 ?? 33 FF 89 7C 24 ?? 85 FF 75 ?? 8D 4C 
            24 ?? 8D 54 24 ?? 51 52 68 ?? ?? ?? ?? EB ?? 8D 44 24 ?? 8D 4C 24 ?? 50 51 68 ?? ?? 
            ?? ?? FF 15 ?? ?? ?? ?? 8B 44 24 ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 85 
            C9 74 ?? 8D 94 24 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? FF D5 8D BC 24 ?? ?? ?? ?? 83 C9 ?? 
            33 C0 F2 AE F7 D1 8D 84 24 ?? ?? ?? ?? 51 8B 4C 24 ?? 50 6A ?? 6A ?? 68 ?? ?? ?? ?? 
            51 FF D3 8B 7C 24 ?? 8B F0 F7 DE 1B F6 46 EB ?? 8D 54 24 ?? 8D 8C 24 ?? ?? ?? ?? 52 
            51 6A ?? 6A ?? 68 ?? ?? ?? ?? 50 C7 44 24 ?? ?? ?? ?? ?? FF 15 
        }
		$download_tor_6 = {
            81 EC ?? ?? ?? ?? 53 55 56 57 E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? A0 ?? ?? ?? ?? 
            B9 ?? ?? ?? ?? 88 44 24 ?? 33 C0 8D 7C 24 ?? 8B 35 ?? ?? ?? ?? F3 AB 68 ?? ?? ?? ?? 
            68 ?? ?? ?? ?? 66 AB 68 ?? ?? ?? ?? 8D 4C 24 ?? 33 ED 68 ?? ?? ?? ?? 51 89 2D ?? ?? 
            ?? ?? 89 2D ?? ?? ?? ?? AA FF D6 8B 1D ?? ?? ?? ?? 83 C4 ?? 8D 54 24 ?? 52 FF D3 83 
            F8 ?? 0F 85 ?? ?? ?? ?? 55 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 84 
            C0 75 ?? 5F 5E 5D 5B 81 C4 ?? ?? ?? ?? C3 A0 ?? ?? ?? ?? B9 ?? ?? ?? ?? 88 84 24 ?? 
            ?? ?? ?? 33 C0 8D BC 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? F3 AB 66 AB 68 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 51 AA FF D6 83 C4 ?? 8D 94 24 ?? ?? ?? 
            ?? 52 FF D3 83 F8 ?? 75 ?? 5F 5E 5D 32 C0 5B 81 C4 ?? ?? ?? ?? C3 
        }
		$main_7 = {
            68 ?? ?? ?? ?? 50 53 FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 
            FF D6 59 85 C0 59 74 ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF D6 59 88 18 59 8D 85 ?? ?? ?? 
            ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 8D 8D ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 53 53 53 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 85 C0 74 ?? 8D 45 ?? 8D 
            8D ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 53 8F 45 ?? E8 ?? ?? ?? ?? 39 44 24 ?? 74 ?? 89 44 
            24 ?? 83 EC ?? 2B C3 58 74 ?? FF 75 ?? 50 E8 ?? ?? ?? ?? 59 89 44 24 ?? 83 EC ?? 2B 
            C3 58 59 74 ?? 68 ?? ?? ?? ?? 50 E8 
        }
		$main_8 = {
            68 ?? ?? ?? ?? F3 AB 66 AB AA 8D 44 24 ?? 50 6A ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? 
            ?? 8D 4C 24 ?? 6A ?? 51 FF D6 83 C4 ?? 85 C0 74 ?? 8D 54 24 ?? 6A ?? 52 FF D6 83 C4 
            ?? C6 00 ?? 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 8C 24 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 8D 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 
            5E 85 C0 74 ?? 8D 4C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 51 68 ?? ?? ?? ?? 8D 8C 24 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 54 24 ?? 52 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 
            ?? 68 ?? ?? ?? ?? 50 E8 
        }
		$entrypoint_all = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? 
            ?? 83 EC ?? 53 56 57 89 65 ?? 33 DB 89 5D ?? 6A ?? FF 15 ?? ?? ?? ?? 59 83 0D ?? ?? 
            ?? ?? ?? 83 0D ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 89 08 FF 15 ?? ?? 
            ?? ?? 8B 0D ?? ?? ?? ?? 89 08 A1 ?? ?? ?? ?? 8B 00 A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 39 
            1D ?? ?? ?? ?? 75 ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 59 E8 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 45 ?? 8D 45 ?? 50 FF 35 ?? ?? ?? 
            ?? 8D 45 ?? 50 8D 45 ?? 50 8D 45 ?? 50 FF 15 
        }

	condition:
		uint16( 0 ) == 0x5A4D and ( $entrypoint_all at pe.entry_point ) and ( $main_1 or $main_2 or ( $main_3 and $start_service_3 ) or $main_4 or $main_5 or ( $main_6 and ( $set_reg_key_6 or $download_tor_6 ) ) or $main_7 or $main_8 )
}

