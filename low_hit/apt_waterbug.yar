rule WaterBug_wipbot_2013_core_PDF : hardened
{
	meta:
		description = "Symantec Waterbug Attack - Trojan.Wipbot 2014 core PDF"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"
		id = "2e8ccce9-d8ba-573d-b532-76d8e2ed5442"

	strings:
		$a = /\+[A-Za-z]{1}\. _ _ \$\+[A-Za-z]{1}\. _ \$ _ \+/
		$b = /\+[A-Za-z]{1}\.\$\$\$ _ \+/

	condition:
		uint32( 0 ) == 0x46445025 and #a > 150 and #b > 200
}

rule WaterBug_wipbot_2013_dll : hardened
{
	meta:
		description = "Symantec Waterbug Attack - Trojan.Wipbot 2014 Down.dll component"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"
		id = "2aae09a3-6e59-5951-941e-c1f82aada979"

	strings:
		$string1 = {2f 25 73 3f 72 61 6e 6b 3d 25 73}
		$string2 = {4d 6f 64 75 6c 65 53 74 61 72 74 00 4d 6f 64 75 6c 65 53 74 6f 70 00 73 74 61 72 74}
		$string3 = {31 31 35 36 66 64 32 32 2d 33 34 34 33 2d 34 33 34 34 2d 63 34 66 66 66 66}
		$string4 = {72 65 61 64 20 66 69 6c 65 2e 2e 2e 20 65 72 72 6f 72 00 00}

	condition:
		2 of them
}

rule WaterBug_wipbot_2013_core : hardened
{
	meta:
		description = "Symantec Waterbug Attack - Trojan.Wipbot core + core; garbage appended data (PDF Exploit leftovers) + wipbot dropper; fake AdobeRd32 Error"
		author = "Symantec Security Response"
		date = "2015-01-22"
		modified = "2023-01-27"
		reference = "http://t.co/rF35OaAXrl"
		id = "2e8ccce9-d8ba-573d-b532-76d8e2ed5442"

	strings:
		$code1 = { 89 47 0C C7 47 10 90 C2 04 00 C7 47 14 90 C2 10 00 C7 47 18 90 90 60 68 89 4F 1C C7 47 20 90 90 90 B8 89 4F 24 C7 47 28 90 FF D0 61 C7 47 2C 90 C2 04 00}
		$code2 = { 85 C0 75 25 8B 0B BF ?? ?? ?? ?? EB 17 69 D7 0D 66 19 00 8D BA 5F F3 6E 3C 89 FE C1 EE 10 89 F2 30 14 01 40 3B 43 04 72 E4}
		$code3 = {90 90 90 ?? B9 00 4D 5A 90 00 03 00 00 00 82 04}
		$code4 = {55 89 E5 5D C3 55 89 E5 83 EC 18 8B 45 08 85 C0}

	condition:
		uint16( 0 ) == 0x5A4D and ( ( $code1 or $code2 ) or ( $code3 and $code4 ) )
}

rule WaterBug_turla_dropper : hardened
{
	meta:
		description = "Symantec Waterbug Attack - Trojan Turla Dropper"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"
		id = "f9683ac7-36f3-5a2a-8b76-e8e2527f4e0d"

	strings:
		$a = {0F 31 14 31 20 31 3C 31 85 31 8C 31 A8 31 B1 31 D1 31 8B 32 91 32 B6 32 C4 32 6C 33 AC 33 10 34}
		$b = {48 41 4C 2E 64 6C 6C 00 6E 74 64 6C 6C 00 00 00 57 8B F9 8B 0D ?? ?? ?? ?? ?? C9 75 26 56 0F 20 C6 8B C6 25 FF FF FE FF 0F 22 C0 E8}

	condition:
		all of them
}

rule WaterBug_fa_malware : hardened
{
	meta:
		description = "Symantec Waterbug Attack - FA malware variant"
		author = "Symantec Security Response"
		date = "2015-01-22"
		modified = "2023-01-27"
		reference = "http://t.co/rF35OaAXrl"
		id = "b09f798a-2875-59ca-b880-971d8f973c76"

	strings:
		$string1 = {43 3a 5c 70 72 6f 6a 5c 64 72 69 76 65 72 73 5c 66 61 20 5f 20 32 30 30 39 5c 6f 62 6a 66 72 65 5c 69 33 38 36 5c 61 74 6d 61 72 70 64 2e 70 64 62}
		$string2 = {64 3a 5c 70 72 6f 6a 5c 63 6e 5c 66 61 36 34 5c}
		$string3 = {73 65 6e 67 6f 6b 75 5f 57 69 6e 33 32 2e 73 79 73 00}
		$string4 = {72 6b 5f 6e 74 73 79 73 74 65 6d 2e 63}
		$string5 = {5c 75 72 6f 62 6f 72 6f 73 5c}
		$string6 = {73 68 65 6c 6c 2e 7b 46 32 31 45 44 43 30 39 2d 38 35 44 33 2d 34 65 62 39 2d 39 31 35 46 2d 31 41 46 41 32 46 46 32 38 31 35 33 7d}

	condition:
		uint16( 0 ) == 0x5A4D and ( any of ( $string* ) )
}

rule WaterBug_sav : hardened
{
	meta:
		description = "Symantec Waterbug Attack - SAV Malware"
		author = "Symantec Security Response"
		date = "2015-01-22"
		modified = "2023-01-27"
		reference = "http://t.co/rF35OaAXrl"
		id = "685849de-9892-56bf-8215-21b08d8b2d7c"

	strings:
		$code1a = { 8B 75 18 31 34 81 40 3B C2 72 F5 33 F6 39 7D 14 76 1B 8A 04 0E 88 04 0F 6A 0F 33 D2 8B C7 5B F7 F3 85 D2 75 01 }
		$code1b = { 8B 45 F8 40 89 45 F8 8B 45 10 C1 E8 02 39 45 F8 73 17 8B 45 F8 8B 4D F4 8B 04 81 33 45 20 8B 4D F8 8B 55 F4 89 04 8A EB D7 83 65 F8 00 83 65 EC 00 EB 0E 8B 45 F8 40 89 45 F8 8B 45 EC 40 89 45 EC 8B 45 EC	3B 45 10 73 27 8B 45 F4 03 45 F8 8B 4D F4 03 4D EC 8A 09 88 08 8B 45 F8 33 D2 6A 0F 59 F7 F1 85 D2 75 07 }
		$code1c = { 8A 04 0F 88 04 0E 6A 0F 33 D2 8B C6 5B F7 F3 85 D2 75 01 47 8B 45 14 46 47 3B F8 72 E3 EB 04 C6 04 08 00 48 3B C6 73 F7 33 C0 C1 EE 02 74 0B 8B 55 18 31 14 81 40 3B C6 72 F5 }
		$code2 = { 29 5D 0C 8B D1 C1 EA 05 2B CA 8B 55 F4 2B C3 3D 00 00 00 01 89 0F 8B 4D 10 8D 94 91 00 03 00 00 73 17 8B 7D F8 8B 4D 0C 0F B6 3F C1 E1 08 0B CF C1 E0 08 FF 45 F8 89 4D 0C 8B 0A 8B F8 C1 EF 0B}

	condition:
		uint16( 0 ) == 0x5A4D and ( ( $code1a or $code1b or $code1c ) and $code2 )
}

