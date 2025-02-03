rule misc_iocs : hardened
{
	meta:
		author = "@patrickrolsen"
		maltype = "Misc."
		version = "0.1"
		reference = "N/A"

	strings:
		$doc = {D0 CF 11 E0}
		$s1 = {64 77 32 30 2e 65 78 65}
		$s2 = {63 6d 64 20 2f}

	condition:
		($doc at 0 ) and ( 1 of ( $s* ) )
}

rule malicious_LNK_files : hardened
{
	meta:
		author = "@patrickrolsen"
		score = 60

	strings:
		$magic = {4C 00 00 00 01 14 02 00}
		$s1 = {5c 00 52 00 45 00 43 00 59 00 43 00 4c 00 45 00 52 00 5c 00}
		$s2 = {25 00 74 00 65 00 6d 00 70 00 25 00}
		$s3 = {25 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 25 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}
		$s5 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00}
		$s6 = {6c 00 73 00 61 00 73 00 73 00 2e 00 65 00 78 00 65 00}
		$s7 = {63 00 73 00 72 00 73 00 73 00 2e 00 65 00 78 00 65 00}
		$s8 = {77 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 2e 00 65 00 78 00 65 00}
		$s13 = {2e 00 63 00 70 00 6c 00}

	condition:
		($magic at 0 ) and any of ( $s* )
}

rule memory_pivy : hardened
{
	meta:
		author = "https://github.com/jackcr/"

	strings:
		$a = {00 00 00 00 00 00 00 00 00 00 00 53 74 75 62 50 61 74 68 00}

	condition:
		any of them
}

rule ScanBox_Malware_Generic : hardened
{
	meta:
		description = "Scanbox Chinese Deep Panda APT Malware http://goo.gl/MUUfjv and http://goo.gl/WXUQcP"
		author = "Florian Roth"
		score = 75
		reference1 = "http://goo.gl/MUUfjv"
		reference2 = "http://goo.gl/WXUQcP"
		date = "2015/02/28"
		hash1 = "8d168092d5601ebbaed24ec3caeef7454c48cf21366cd76560755eb33aff89e9"
		hash2 = "d4be6c9117db9de21138ae26d1d0c3cfb38fd7a19fa07c828731fa2ac756ef8d"
		hash3 = "3fe208273288fc4d8db1bf20078d550e321d9bc5b9ab80c93d79d2cb05cbf8c2"

	strings:
		$s0 = {68 74 74 70 3a 2f 2f 31 34 32 2e 39 31 2e 37 36 2e 31 33 34 2f 70 2e 64 61 74}
		$s1 = {48 74 74 70 44 75 6d 70 20 31 2e 31}
		$s3 = {53 00 65 00 63 00 75 00 72 00 65 00 49 00 6e 00 70 00 75 00 74 00 20 00 2e 00 65 00 78 00 65 00}
		$s4 = {68 74 74 70 3a 2f 2f 65 78 74 63 69 74 72 69 78 2e 77 65 31 31 70 6f 69 6e 74 2e 63 6f 6d 2f 76 70 6e 2f 69 6e 64 65 78 2e 70 68 70 3f 72 65 66 3d 31}
		$s5 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6d 73 75 70 64 61 74 65}
		$s6 = {53 65 72 76 69 63 65 4d 61 69 78}
		$x1 = {4d 61 6e 61 67 65 6d 65 6e 74 20 53 75 70 70 6f 72 74 20 54 65 61 6d 31}
		$x2 = {44 54 4f 50 54 4f 4f 4c 5a 20 43 6f 2e 2c 4c 74 64 2e 30}
		$x3 = {53 45 4f 55 4c 31}

	condition:
		(1 of ( $s* ) and 2 of ( $x* ) ) or ( 3 of ( $x* ) )
}

rule TrojanDownloader : hardened
{
	meta:
		description = "Trojan Downloader - Flash Exploit Feb15"
		author = "Florian Roth"
		reference = "http://goo.gl/wJ8V1I"
		date = "2015/02/11"
		hash = "5b8d4280ff6fc9c8e1b9593cbaeb04a29e64a81e"
		score = 60

	strings:
		$x1 = {48 65 6c 6c 6f 20 57 6f 72 6c 64 21}
		$x2 = {43 4f 4e 49 4e 24}
		$s6 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41}
		$s7 = {45 78 69 74 50 72 6f 63 65 73 73}
		$s8 = {43 72 65 61 74 65 46 69 6c 65 41}
		$s5 = {53 65 74 43 6f 6e 73 6f 6c 65 4d 6f 64 65}
		$s9 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73}
		$s10 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73}
		$s11 = {55 6e 68 61 6e 64 6c 65 64 45 78 63 65 70 74 69 6f 6e 46 69 6c 74 65 72}
		$s3 = {75 73 65 72 33 32 2e 64 6c 6c}
		$s16 = {47 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73}
		$s2 = {47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70}
		$s17 = {47 65 74 46 69 6c 65 54 79 70 65}
		$s19 = {48 65 61 70 43 72 65 61 74 65}
		$s20 = {56 69 72 74 75 61 6c 46 72 65 65}
		$s21 = {57 72 69 74 65 46 69 6c 65}
		$s22 = {47 65 74 4f 45 4d 43 50}
		$s23 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63}
		$s24 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73}
		$s26 = {46 6c 75 73 68 46 69 6c 65 42 75 66 66 65 72 73}
		$s27 = {53 65 74 53 74 64 48 61 6e 64 6c 65}
		$s28 = {4b 45 52 4e 45 4c 33 32 2e 64 6c 6c}

	condition:
		$x1 and $x2 and ( all of ( $s* ) ) and filesize < 35000
}

rule Cloaked_as_JPG : hardened
{
	meta:
		description = "Detects a cloaked file as JPG"
		author = "Florian Roth (eval section from Didier Stevens)"
		date = "2015/02/29"
		score = 70

	strings:
		$ext = {65 78 74 65 6e 73 69 6f 6e 3a 20 2e 6a 70 67}

	condition:
		$ext and uint16be( 0x00 ) != 0xFFD8
}

rule rtf_yahoo_ken : hardened
{
	meta:
		author = "@patrickrolsen"
		maltype = "Yahoo Ken"
		filetype = "RTF"
		version = "0.1"
		description = "Test rule"
		date = "2013-12-14"

	strings:
		$magic1 = { 7b 5c 72 74 30 31 }
		$magic2 = { 7b 5c 72 74 66 31 }
		$magic3 = { 7b 5c 72 74 78 61 33 }
		$author1 = { 79 61 68 6f 6f 20 6b 65 63 }

	condition:
		($magic1 or $magic2 or $magic3 at 0 ) and $author1
}

rule EmiratesStatement : hardened
{
	meta:
		Author = "Christiaan Beek"
		Date = "2013-06-30"
		Description = "Credentials Stealing Attack"
		Reference = "https://blogs.mcafee.com/mcafee-labs/targeted-campaign-steals-credentials-in-gulf-states-and-caribbean"
		hash0 = "0e37b6efe5de1cc9236017e003b1fc37"
		hash1 = "a28b22acf2358e6aced43a6260af9170"
		hash2 = "6f506d7adfcc2288631ed2da37b0db04"
		hash3 = "8aebade47dc1aa9ac4b5625acf5ade8f"

	strings:
		$string0 = {6d 73 6e 2e 6b 6c 6d}
		$string1 = {77 6d 73 6e 2e 6b 6c 6d}
		$string2 = {62 6d 73 2e 6b 6c 6d}

	condition:
		all of them
}

rule callTogether_certificate : hardened
{
	meta:
		Author = "Fireeye Labs"
		Date = "2014/11/03"
		Description = "detects binaries signed with the CallTogether certificate"
		Reference = "https://www.fireeye.com/blog/threat-research/2014/11/operation-poisoned-handover-unveiling-ties-between-apt-activity-in-hong-kongs-pro-democracy-movement.html"

	strings:
		$serial = { 45 21 56 C3 B3 FB 01 76 36 5B DB 5B 77 15 BC 4C }
		$o = {43 61 6c 6c 54 6f 67 65 74 68 65 72 2c 20 49 6e 63 2e}

	condition:
		$serial and $o
}

rule qti_certificate : hardened
{
	meta:
		Author = "Fireeye Labs"
		Date = "2014/11/03"
		Description = "detects binaries signed with the QTI International Inc certificate"
		Reference = "https://www.fireeye.com/blog/threat-research/2014/11/operation-poisoned-handover-unveiling-ties-between-apt-activity-in-hong-kongs-pro-democracy-movement.html"

	strings:
		$cn = {51 54 49 20 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 20 49 6e 63}
		$serial = { 2e df b9 fd cf a0 0c cb 5a b0 09 ee 3a db 97 b9 }

	condition:
		$cn and $serial
}

rule DownExecute_A : hardened
{
	meta:
		Author = "PwC Cyber Threat Operations :: @tlansec"
		Date = "2015/04/27"
		Description = "Malware is often wrapped/protected, best to run on memory"
		Reference = "http://pwc.blogs.com/cyber_security_updates/2015/04/attacks-against-israeli-palestinian-interests.html"

	strings:
		$winver1 = {77 69 6e 20 38 2e 31}
		$winver2 = {77 69 6e 20 53 65 72 76 65 72 20 32 30 31 32 20 52 32}
		$winver3 = {77 69 6e 20 53 72 76 20 32 30 31 32}
		$winver4 = {77 69 6e 20 73 72 76 20 32 30 30 38 20 52 32}
		$winver5 = {77 69 6e 20 73 72 76 20 32 30 30 38}
		$winver6 = {77 69 6e 20 76 73 74 61}
		$winver7 = {77 69 6e 20 73 72 76 20 32 30 30 33 20 52 32}
		$winver8 = {77 69 6e 20 68 6d 20 73 72 76}
		$winver9 = {77 69 6e 20 53 74 72 67 20 73 72 76 20 32 30 30 33}
		$winver10 = {77 69 6e 20 73 72 76 20 32 30 30 33}
		$winver11 = {77 69 6e 20 58 50 20 70 72 6f 66 20 78 36 34 20 65 64 74}
		$winver12 = {77 69 6e 20 58 50}
		$winver13 = {77 69 6e 20 32 30 30 30}
		$pdb1 = {44 3a 5c 41 63 6d 73 5c 32 5c 64 6f 63 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 31 33 5c 50 72 6f 6a 65 63 74 73 5c 44 6f 77 6e 6c 6f 61 64 45 78 63 75 74 65 5c 44 6f 77 6e 6c 6f 61 64 45 78 63 75 74 65 5c 52 65 6c 65 61 73 65 5c 44 6f 77 6e 45 78 65 63 75 74 65 2e 70 64 62}
		$pdb2 = {64 3a 5c 61 63 6d 73 5c 32 5c 64 6f 63 73 5c 76 69 73 75 61 6c 20 73 74 75 64 69 6f 20 32 30 31 33 5c 70 72 6f 6a 65 63 74 73 5c 64 6f 77 6e 6c 6f 61 64 65 78 63 75 74 65 5c 64 6f 77 6e 6c 6f 61 64 65 78 63 75 74 65 5c 64 6f 77 6e 65 78 65 63 75 74 65 5c 6a 73 6f 6e 5c 72 61 70 69 64 6a 73 6f 6e 5c 77 72 69 74 65 72 2e 68}
		$pdb3 = {3a 5c 61 63 6d 73 5c 32 5c 64 6f 63 73 5c 76 69 73 75 61 6c 20 73 74 75 64 69 6f 20 32 30 31 33 5c 70 72 6f 6a 65 63 74 73 5c 64 6f 77 6e 6c 6f 61 64 65 78 63 75 74 65 5c 64 6f 77 6e 6c 6f 61 64 65 78 63 75 74 65 5c 64 6f 77 6e 65 78 65 63 75 74 65 5c 6a 73 6f 6e 5c 72 61 70 69 64 6a 73 6f 6e 5c 69 6e 74 65 72 6e 61 6c 2f 73 74 61 63 6b 2e 68}
		$pdb4 = {5c 64 6f 77 6e 6c 6f 61 64 65 78 63 75 74 65 5c 64 6f 77 6e 65 78 65 63 75 74 65 5c}
		$magic1 = {3c 57 69 6e 20 47 65 74 20 56 65 72 73 69 6f 6e 20 49 6e 66 6f 20 4e 61 6d 65 20 45 72 72 6f 72}
		$magic2 = {50 40 24 73 77 30 72 64 24 6e 64}
		$magic3 = {24 74 40 6b 30 76 32 72 46 31 30 77}
		$magic4 = {7c 00 2a 00 7c 00 31 00 32 00 33 00 78 00 58 00 78 00 28 00 4d 00 75 00 74 00 65 00 78 00 29 00 78 00 58 00 78 00 33 00 32 00 31 00 7c 00 2a 00 7c 00 36 00 2d 00 32 00 31 00 2d 00 32 00 30 00 31 00 34 00 2d 00 30 00 33 00 3a 00 30 00 36 00 50 00 4d 00}
		$str1 = {((44 6f 77 6e 6c 6f 61 64 20 45 78 63 75 74 65) | (44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 45 00 78 00 63 00 75 00 74 00 65 00))}
		$str2 = {45 6e 63 72 79 70 74 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 20 25 64}
		$str3 = {25 73 5c 25 73 2e 6c 6e 6b}
		$str4 = {4d 61 63 3a 25 73 2d 43 70 75 3a 25 73 2d 48 44 3a 25 73}
		$str5 = {66 65 65 64 20 62 61 63 6b 20 72 65 73 70 6f 6e 63 65 20 6f 66 20 68 6f 73 74}
		$str6 = {47 45 54 20 54 6f 6b 65 6e 20 61 74 20 68 6f 73 74}
		$str7 = {64 77 6e 20 6d 64 35 20 65 72 72}

	condition:
		all of ( $winver* ) or any of ( $pdb* ) or any of ( $magic* ) or 2 of ( $str* )
}

rule CVE_2015_1674_CNGSYS : hardened
{
	meta:
		description = "Detects exploits for CVE-2015-1674"
		author = "Florian Roth"
		reference = "http://www.binvul.com/viewthread.php?tid=508"
		reference2 = "https://github.com/Neo23x0/Loki/blob/master/signatures/exploit_cve_2015_1674.yar"
		date = "2015-05-14"
		hash = "af4eb2a275f6bbc2bfeef656642ede9ce04fad36"

	strings:
		$s1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 43 00 4e 00 47 00}
		$s2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73}
		$s3 = {4c 6f 61 64 4c 69 62 72 61 72 79}
		$s4 = {4b 45 52 4e 45 4c 33 32 2e 64 6c 6c}
		$s5 = {6e 74 64 6c 6c 2e 64 6c 6c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 60KB and all of them
}

rule Base64_encoded_Executable : hardened
{
	meta:
		description = "Detects an base64 encoded executable (often embedded)"
		author = "Florian Roth"
		date = "2015-05-28"
		score = 50

	strings:
		$s1 = {54 56 70 54 41 51 45 41 41 41 41 45 41 41 41 41 2f 2f 38 41 41 4c 67 41 41 41 41}
		$s2 = {54 56 6f 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41}
		$s3 = {54 56 71 41 41 41 45 41 41 41 41 45 41 42 41 41 41 41 41 41 41 41 41 41 41 41 41}
		$s4 = {54 56 70 51 41 41 49 41 41 41 41 45 41 41 38 41 2f 2f 38 41 41 4c 67 41 41 41 41}
		$s5 = {54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41 2f 2f 38 41 41 4c 67 41 41 41 41}

	condition:
		1 of them
}

rule CredStealESY : For CredStealer hardened
{
	meta:
		description = "Generic Rule to detect the CredStealer Malware"
		author = "IsecG – McAfee Labs"
		date = "2015/05/08"

	strings:
		$my_hex_string = {43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 4b 00 65 00 79 00 62 00 6f 00 61 00 72 00 64 00 20 00 4c 00 61 00 79 00 6f 00 75 00 74 00 73 00 5c 00}
		$my_hex_string2 = {89 45 E8 3B 7D E8 7C 0F 8B 45 E8 05 FF 00 00 00 2B C7 89 45 E8}

	condition:
		$my_hex_string and $my_hex_string2
}

rule Typical_Malware_String_Transforms : hardened
{
	meta:
		description = "Detects typical strings in a reversed or otherwise modified form"
		author = "Florian Roth"
		reference = "Internal Research"
		date = "2016-07-31"
		score = 60

	strings:
		$e1 = {65 78 65 2e 74 73 6f 68 63 76 73}
		$e2 = {65 78 65 2e 73 73 61 73 6c}
		$e3 = {65 78 65 2e 72 65 72 6f 6c 70 78 65}
		$e4 = {65 78 65 2e 65 72 6f 6c 70 78 65 69}
		$e5 = {65 78 65 2e 32 33 6c 6c 64 6e 75 72}
		$e6 = {65 78 65 2e 64 6d 63}
		$e7 = {65 78 65 2e 6c 6c 69 6b 6b 73 61 74}
		$l1 = {6c 6c 64 2e 32 33 6c 65 6e 72 65 4b}
		$l2 = {6c 6c 64 2e 45 53 41 42 4c 45 4e 52 45 4b}
		$l3 = {6c 6c 64 2e 65 73 61 62 74 70 79 72 63}
		$l4 = {6c 6c 64 2e 74 72 63 76 73 6d}
		$l5 = {4c 4c 44 2e 4c 4c 44 54 4e}
		$i1 = {70 61 65 48 73 73 65 63 6f 72 50 74 65 47}
		$i2 = {73 73 65 72 64 64 41 63 6f 72 50 74 65 47}
		$i3 = {41 79 72 61 72 62 69 4c 64 61 6f 4c}
		$r1 = {74 65 53 6c 6f 72 74 6e 6f 43 74 6e 65 72 72 75 43}
		$r2 = {6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43}
		$f1 = {5c 32 33 6d 65 74 73 79 73 5c}
		$f2 = {5c 32 33 6d 65 74 73 79 53 5c}
		$f3 = {6e 69 42 2e 65 6c 63 79 63 65 52 24}
		$f4 = {25 74 6f 6f 52 6d 65 74 73 79 53 25}
		$fp1 = {41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 49 00 6d 00 70 00 61 00 63 00 74 00 20 00 54 00 65 00 6c 00 65 00 6d 00 65 00 74 00 72 00 79 00 20 00 53 00 74 00 61 00 74 00 69 00 63 00 20 00 41 00 6e 00 61 00 6c 00 79 00 7a 00 65 00 72 00}

	condition:
		( uint16( 0 ) == 0x5a4d and 1 of them and not 1 of ( $fp* ) )
}

