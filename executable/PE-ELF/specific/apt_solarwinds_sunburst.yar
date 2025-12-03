rule APT_Backdoor_SUNBURST_1 : hardened
{
	meta:
		author = "FireEye"
		description = "This rule is looking for portions of the SUNBURST backdoor that are vital to how it functions. The first signature fnv_xor matches a magic byte xor that the sample performs on process, service, and driver names/paths. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		date = "2020-12-14"
		score = 85
		id = "74b44844-5575-53d7-819b-ab1b2327a144"

	strings:
		$cmd_regex_encoded = {55 00 34 00 71 00 70 00 6a 00 6a 00 62 00 51 00 74 00 55 00 7a 00 55 00 54 00 64 00 4f 00 4e 00 72 00 54 00 59 00 32 00 71 00 34 00 32 00 70 00 56 00 61 00 70 00 52 00 67 00 6f 00 6f 00 41 00 42 00 59 00 78 00 51 00 75 00 49 00 5a 00 6d 00 74 00 55 00 6f 00 41 00}
		$cmd_regex_plain = { 5C 7B 5B 30 2D 39 61 2D 66 2D 5D 7B 33 36 7D 5C 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 33 32 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 31 36 7D }
		$fake_orion_event_encoded = {55 00 33 00 49 00 74 00 53 00 38 00 30 00 72 00 43 00 61 00 6b 00 73 00 53 00 46 00 57 00 79 00 55 00 76 00 49 00 76 00 79 00 73 00 7a 00 50 00 55 00 39 00 49 00 42 00 41 00 41 00 3d 00 3d 00}
		$fake_orion_event_plain = { 22 45 76 65 6E 74 54 79 70 65 22 3A 22 4F 72 69 6F 6E 22 2C }
		$fake_orion_eventmanager_encoded = {55 00 33 00 49 00 74 00 53 00 38 00 30 00 72 00 38 00 55 00 76 00 4d 00 54 00 56 00 57 00 79 00 55 00 67 00 4b 00 7a 00 66 00 52 00 50 00 7a 00 45 00 74 00 4e 00 54 00 69 00 35 00 52 00 30 00 41 00 41 00 3d 00 3d 00}
		$fake_orion_eventmanager_plain = { 22 45 76 65 6E 74 4E 61 6D 65 22 3A 22 45 76 65 6E 74 4D 61 6E 61 67 65 72 22 2C }
		$fake_orion_message_encoded = {55 00 2f 00 4a 00 4e 00 4c 00 53 00 35 00 4f 00 54 00 45 00 39 00 56 00 73 00 6c 00 4b 00 71 00 4e 00 71 00 68 00 56 00 41 00 67 00 41 00 3d 00}
		$fake_orion_message_plain = { 22 4D 65 73 73 61 67 65 22 3A 22 7B 30 7D 22 }
		$fnv_xor = { 67 19 D8 A7 3B 90 AC 5B }

	condition:
		$fnv_xor and ( $cmd_regex_encoded or $cmd_regex_plain ) or ( ( $fake_orion_event_encoded or $fake_orion_event_plain ) and ( $fake_orion_eventmanager_encoded or $fake_orion_eventmanager_plain ) and ( $fake_orion_message_encoded and $fake_orion_message_plain ) )
}

rule APT_Backdoor_SUNBURST_2 : hardened
{
	meta:
		author = "FireEye"
		description = "The SUNBURST backdoor uses a domain generation algorithm (DGA) as part of C2 communications. This rule is looking for each branch of the code that checks for which HTTP method is being used. This is in one large conjunction, and all branches are then tied together via disjunction. The grouping is intentionally designed so that if any part of the DGA is re-used in another sample, this signature should match that re-used portion. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		date = "2020-12-14"
		score = 85
		id = "329071d5-c9c6-5ae1-a514-aea9f4037bac"

	strings:
		$a = {30 00 79 00 33 00 4b 00 7a 00 79 00 38 00 42 00 41 00 41 00 3d 00 3d 00}
		$aa = {53 00 38 00 76 00 50 00 4b 00 79 00 6e 00 57 00 4c 00 38 00 39 00 50 00 53 00 39 00 4f 00 76 00 4e 00 71 00 6a 00 56 00 72 00 54 00 59 00 45 00 59 00 71 00 4e 00 61 00 33 00 66 00 4c 00 55 00 70 00 44 00 53 00 67 00 54 00 4c 00 56 00 78 00 72 00 52 00 35 00 49 00 7a 00 67 00 67 00 41 00}
		$ab = {53 00 38 00 76 00 50 00 4b 00 79 00 6e 00 57 00 4c 00 38 00 39 00 50 00 53 00 39 00 4f 00 76 00 4e 00 71 00 6a 00 56 00 72 00 54 00 59 00 45 00 59 00 71 00 50 00 61 00 61 00 75 00 4e 00 61 00 50 00 5a 00 43 00 59 00 45 00 51 00 41 00 3d 00}
		$ac = {43 00 38 00 38 00 73 00 53 00 73 00 31 00 4a 00 4c 00 53 00 34 00 47 00 41 00 41 00 3d 00 3d 00}
		$ad = {43 00 2f 00 55 00 45 00 41 00 41 00 3d 00 3d 00}
		$ae = {43 00 38 00 39 00 4d 00 53 00 55 00 38 00 74 00 4b 00 51 00 59 00 41 00}
		$af = {38 00 77 00 76 00 77 00 42 00 51 00 41 00 3d 00}
		$ag = {63 00 79 00 7a 00 49 00 7a 00 38 00 6e 00 4a 00 42 00 77 00 41 00 3d 00}
		$ah = {63 00 38 00 37 00 4a 00 4c 00 30 00 33 00 78 00 7a 00 63 00 2f 00 4c 00 4c 00 4d 00 6b 00 76 00 79 00 73 00 78 00 4c 00 42 00 77 00 41 00 3d 00}
		$ai = {38 00 38 00 74 00 50 00 53 00 53 00 30 00 47 00 41 00 41 00 3d 00 3d 00}
		$aj = {43 00 38 00 76 00 50 00 4b 00 63 00 31 00 4e 00 4c 00 51 00 59 00 41 00}
		$ak = {38 00 38 00 77 00 72 00 53 00 53 00 31 00 4b 00 53 00 30 00 78 00 4f 00 4c 00 51 00 59 00 41 00}
		$al = {63 00 38 00 37 00 50 00 4c 00 63 00 6a 00 50 00 53 00 38 00 30 00 72 00 4b 00 51 00 59 00 41 00}
		$am = {4b 00 79 00 37 00 50 00 4c 00 4e 00 41 00 76 00 4c 00 55 00 6a 00 52 00 42 00 77 00 41 00 3d 00}
		$an = {30 00 36 00 76 00 49 00 7a 00 51 00 45 00 41 00}
		$b = {30 00 79 00 33 00 4e 00 79 00 79 00 78 00 4c 00 4c 00 53 00 70 00 4f 00 7a 00 49 00 6c 00 50 00 54 00 67 00 51 00 41 00}
		$c = {30 00 30 00 31 00 4f 00 42 00 41 00 41 00 3d 00}
		$d = {30 00 79 00 30 00 6f 00 79 00 73 00 78 00 4e 00 4c 00 4b 00 71 00 4d 00 54 00 30 00 34 00 45 00 41 00 41 00 3d 00 3d 00}
		$e = {30 00 79 00 33 00 4a 00 7a 00 45 00 30 00 74 00 4c 00 6b 00 6e 00 4d 00 4c 00 51 00 41 00 41 00}
		$f = {30 00 30 00 33 00 50 00 79 00 55 00 39 00 4b 00 7a 00 41 00 45 00 41 00}
		$h = {30 00 79 00 31 00 4f 00 54 00 53 00 34 00 74 00 53 00 6b 00 31 00 4f 00 42 00 41 00 41 00 3d 00}
		$i = {4b 00 38 00 6a 00 4f 00 31 00 45 00 38 00 75 00 79 00 74 00 47 00 76 00 4e 00 71 00 69 00 74 00 4e 00 71 00 79 00 74 00 4e 00 71 00 72 00 56 00 41 00 2f 00 49 00 41 00}
		$j = {63 00 38 00 72 00 50 00 53 00 51 00 45 00 41 00}
		$k = {63 00 38 00 72 00 50 00 53 00 66 00 45 00 73 00 53 00 63 00 7a 00 4a 00 54 00 41 00 59 00 41 00}
		$l = {63 00 36 00 30 00 6f 00 4b 00 55 00 70 00 30 00 79 00 73 00 39 00 4a 00 41 00 51 00 41 00 3d 00}
		$m = {63 00 36 00 30 00 6f 00 4b 00 55 00 70 00 30 00 79 00 73 00 39 00 4a 00 38 00 53 00 78 00 4a 00 7a 00 4d 00 6c 00 4d 00 42 00 67 00 41 00 3d 00}
		$n = {38 00 79 00 78 00 4a 00 7a 00 4d 00 6c 00 4d 00 42 00 67 00 41 00 3d 00}
		$o = {38 00 38 00 6c 00 4d 00 7a 00 79 00 67 00 42 00 41 00 41 00 3d 00 3d 00}
		$p = {38 00 38 00 6c 00 4d 00 7a 00 79 00 6a 00 78 00 4c 00 45 00 6e 00 4d 00 79 00 55 00 77 00 47 00 41 00 41 00 3d 00 3d 00}
		$q = {43 00 30 00 70 00 4e 00 4c 00 38 00 31 00 4a 00 4c 00 41 00 49 00 41 00}
		$r = {43 00 30 00 37 00 4e 00 7a 00 58 00 54 00 4b 00 7a 00 30 00 6b 00 42 00 41 00 41 00 3d 00 3d 00}
		$s = {43 00 30 00 37 00 4e 00 7a 00 58 00 54 00 4b 00 7a 00 30 00 6e 00 78 00 4c 00 45 00 6e 00 4d 00 79 00 55 00 77 00 47 00 41 00 41 00 3d 00 3d 00}
		$t = {79 00 79 00 39 00 49 00 7a 00 53 00 74 00 4f 00 7a 00 43 00 73 00 47 00 41 00 41 00 3d 00 3d 00}
		$u = {79 00 38 00 73 00 76 00 79 00 51 00 63 00 41 00}
		$v = {53 00 79 00 74 00 4b 00 54 00 55 00 33 00 4c 00 7a 00 79 00 73 00 42 00 41 00 41 00 3d 00 3d 00}
		$w = {43 00 38 00 34 00 76 00 4c 00 55 00 70 00 4f 00 64 00 63 00 35 00 50 00 53 00 51 00 30 00 6f 00 79 00 67 00 63 00 41 00}
		$x = {43 00 38 00 34 00 76 00 4c 00 55 00 70 00 4f 00 44 00 55 00 34 00 74 00 79 00 6b 00 77 00 4c 00 4b 00 4d 00 6f 00 48 00 41 00 41 00 3d 00 3d 00}
		$y = {43 00 38 00 34 00 76 00 4c 00 55 00 70 00 4f 00 39 00 55 00 6a 00 4d 00 43 00 30 00 37 00 4d 00 4b 00 77 00 59 00 41 00}
		$z = {43 00 38 00 34 00 76 00 4c 00 55 00 70 00 4f 00 39 00 55 00 6a 00 4d 00 43 00 30 00 34 00 74 00 79 00 6b 00 77 00 44 00 41 00 41 00 3d 00 3d 00}

	condition:
		($a and $b and $c and $d and $e and $f and $h and $i ) or ( $j and $k and $l and $m and $n and $o and $p and $q and $r and $s and ( $aa or $ab ) ) or ( $t and $u and $v and $w and $x and $y and $z and ( $aa or $ab ) ) or ( $ac and $ad and $ae and $af and $ag and $ah and ( $am or $an ) ) or ( $ai and $aj and $ak and $al and ( $am or $an ) )
}

rule APT_HackTool_PS1_COSMICGALE_1 : hardened limited
{
	meta:
		author = "FireEye"
		description = "This rule detects various unique strings related to COSMICGALE. COSMICGALE is a credential theft and reconnaissance PowerShell script that collects credentials using the publicly available Get-PassHashes routine. COSMICGALE clears log files, writes acquired data to a hard coded path, and encrypts the file with a password."
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		date = "2020-12-14"
		score = 85
		id = "c094943c-288e-5835-8066-8e95a992c76c"

	strings:
		$sr1 = /\[byte\[\]\]@\([\x09\x20]{0,32}0xaa[\x09\x20]{0,32},[\x09\x20]{0,32}0xd3[\x09\x20]{0,32},[\x09\x20]{0,32}0xb4[\x09\x20]{0,32},[\x09\x20]{0,32}0x35[\x09\x20]{0,32},/ ascii nocase wide
		$sr2 = /\[bitconverter\]::toint32\(\$\w{1,64}\[0x0c..0x0f\][\x09\x20]{0,32},[\x09\x20]{0,32}0\)[\x09\x20]{0,32}\+[\x09\x20]{0,32}0xcc\x3b/ ascii nocase wide
		$sr3 = /\[byte\[\]\]\(\$\w{1,64}\.padright\(\d{1,2}\)\.substring\([\x09\x20]{0,32}0[\x09\x20]{0,32},[\x09\x20]{0,32}\d{1,2}\)\.tochararray\(\)\)/ ascii nocase wide
		$ss1 = {((5b 74 65 78 74 2e 65 6e 63 6f 64 69 6e 67 5d 3a 3a 61 73 63 69 69 2e 67 65 74 62 79 74 65 73 28 22 6e 74 70 61 73 73 77 6f 72 64 60 30 22 29 3b) | (5b 00 74 00 65 00 78 00 74 00 2e 00 65 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 61 00 73 00 63 00 69 00 69 00 2e 00 67 00 65 00 74 00 62 00 79 00 74 00 65 00 73 00 28 00 22 00 6e 00 74 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 60 00 30 00 22 00 29 00 3b 00))}
		$ss2 = {((73 79 73 74 65 6d 5c 63 75 72 72 65 6e 74 63 6f 6e 74 72 6f 6c 73 65 74 5c 63 6f 6e 74 72 6f 6c 5c 6c 73 61 5c 24 5f) | (73 00 79 00 73 00 74 00 65 00 6d 00 5c 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 73 00 65 00 74 00 5c 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 6c 00 73 00 61 00 5c 00 24 00 5f 00))}
		$ss3 = {((5b 73 65 63 75 72 69 74 79 2e 63 72 79 70 74 6f 67 72 61 70 68 79 2e 6d 64 35 5d 3a 3a 63 72 65 61 74 65 28 29) | (5b 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 63 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 79 00 2e 00 6d 00 64 00 35 00 5d 00 3a 00 3a 00 63 00 72 00 65 00 61 00 74 00 65 00 28 00 29 00))}
		$ss4 = {((5b 73 79 73 74 65 6d 2e 73 65 63 75 72 69 74 79 2e 70 72 69 6e 63 69 70 61 6c 2e 77 69 6e 64 6f 77 73 69 64 65 6e 74 69 74 79 5d 3a 3a 67 65 74 63 75 72 72 65 6e 74 28 29 2e 6e 61 6d 65) | (5b 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 70 00 72 00 69 00 6e 00 63 00 69 00 70 00 61 00 6c 00 2e 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 69 00 64 00 65 00 6e 00 74 00 69 00 74 00 79 00 5d 00 3a 00 3a 00 67 00 65 00 74 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 28 00 29 00 2e 00 6e 00 61 00 6d 00 65 00))}
		$ss5 = {((6f 75 74 2d 66 69 6c 65) | (6f 00 75 00 74 00 2d 00 66 00 69 00 6c 00 65 00))}
		$ss6 = {((63 6f 6e 76 65 72 74 74 6f 2d 73 65 63 75 72 65 73 74 72 69 6e 67) | (63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 74 00 6f 00 2d 00 73 00 65 00 63 00 75 00 72 00 65 00 73 00 74 00 72 00 69 00 6e 00 67 00))}

	condition:
		all of them
}

rule APT_Dropper_Raw64_TEARDROP_1 : hardened
{
	meta:
		author = "FireEye"
		description = "This rule looks for portions of the TEARDROP backdoor that are vital to how it functions. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		date = "2020-12-14"
		score = 85
		id = "88adad58-ba16-5996-9ea8-ea356c3ed5b2"

	strings:
		$sb1 = { C7 44 24 ?? 80 00 00 00 [0-64] BA 00 00 00 80 [0-32] 48 8D 0D [4-32] FF 15 [4] 48 83 F8 FF [2-64] 41 B8 40 00 00 00 [0-64] FF 15 [4-5] 85 C0 7? ?? 80 3D [4] FF }
		$sb2 = { 80 3D [4] D8 [2-32] 41 B8 04 00 00 00 [0-32] C7 44 24 ?? 4A 46 49 46 [0-32] E8 [4-5] 85 C0 [2-32] C6 05 [4] 6A C6 05 [4] 70 C6 05 [4] 65 C6 05 [4] 67 }
		$sb3 = { BA [4] 48 89 ?? E8 [4] 41 B8 [4] 48 89 ?? 48 89 ?? E8 [4] 85 C0 7? [1-32] 8B 44 24 ?? 48 8B ?? 24 [1-16] 48 01 C8 [0-32] FF D0 }

	condition:
		all of them
}

rule APT_Dropper_Win64_TEARDROP_1 : hardened
{
	meta:
		author = "FireEye"
		description = "This rule is intended match specific sequences of opcode found within TEARDROP, including those that decode the embedded payload. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory. (comment by Nextron: prone to False Positives)"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		date = "2020-12-14"
		score = 70
		id = "15dfdb74-5ca3-5bc6-be7a-730333b03ba5"

	strings:
		$loc_4218FE24A5 = { 48 89 C8 45 0F B6 4C 0A 30 }
		$loc_4218FE36CA = { 48 C1 E0 04 83 C3 01 48 01 E8 8B 48 28 8B 50 30 44 8B 40 2C 48 01 F1 4C 01 FA }
		$loc_4218FE2747 = { C6 05 ?? ?? ?? ?? 6A C6 05 ?? ?? ?? ?? 70 C6 05 ?? ?? ?? ?? 65 C6 05 ?? ?? ?? ?? 67 }
		$loc_5551D725A0 = { 48 89 C8 45 0F B6 4C 0A 30 48 89 CE 44 89 CF 48 F7 E3 48 C1 EA 05 48 8D 04 92 48 8D 04 42 48 C1 E0 04 48 29 C6 }
		$loc_5551D726F6 = { 53 4F 46 54 57 41 52 45 ?? ?? ?? ?? 66 74 5C 43 ?? ?? ?? ?? 00 }

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

