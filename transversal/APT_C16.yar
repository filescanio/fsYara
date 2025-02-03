rule apt_c16_win_memory_pcclient : hardened
{
	meta:
		author = "@dragonthreatlab"
		md5 = "ec532bbe9d0882d403473102e9724557"
		description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
		date = "2015/01/11"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

	strings:
		$str1 = {4b 69 6c 6c 20 59 6f 75}
		$str2 = {25 34 64 2d 25 30 32 64 2d 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64}
		$str3 = {25 34 2e 32 66 20 20 4b 42}
		$encodefunc = {8A 08 32 CA 02 CA 88 08 40 4E 75 F4}

	condition:
		all of them
}

rule apt_c16_win_disk_pcclient : hardened
{
	meta:
		author = "@dragonthreatlab"
		md5 = "55f84d88d84c221437cd23cdbc541d2e"
		description = "Encoded version of pcclient found on disk"
		date = "2015/01/11"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

	strings:
		$header = {51 5C 96 06 03 06 06 06 0A 06 06 06 FF FF 06 06 BE 06 06 06 06 06 06 06 46 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 EE 06 06 06 10 1F BC 10 06 BA 0D D1 25 BE 05 52 D1 25 5A 6E 6D 73 26 76 74 6F 67 74 65 71 26 63 65 70 70 6F 7A 26 64 69 26 74 79 70 26 6D 70 26 4A 4F 53 26 71 6F 6A 69 30 11 11 0C 2A 06 06 06 06 06 06 06 73 43 96 1B 37 24 00 4E 37 24 00 4E 37 24 00 4E BA 40 F6 4E 39 24 00 4E 5E 41 FA 4E 33 24 00 4E 5E 41 FC 4E 39 24 00 4E 37 24 FF 4E 0D 24 00 4E FA 31 A3 4E 40 24 00 4E DF 41 F9 4E 36 24 00 4E F6 2A FE 4E 38 24 00 4E DF 41 FC 4E 38 24 00 4E 54 6D 63 6E 37 24 00 4E 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 56 49 06 06 52 05 09 06 5D 87 8C 5A 06 06 06 06 06 06 06 06 E6 06 10 25 0B 05 08 06 06 1C 06 06 06 1A 06 06 06 06 06 06 E5 27 06 06 06 16 06 06 06 36 06 06 06 06 06 16 06 16 06 06 06 04 06 06 0A 06 06 06 06 06 06 06 0A 06 06 06 06 06 06 06 06 76 06 06 06 0A 06 06 06 06 06 06 04 06 06 06 06 06 16 06 06 16 06 06}

	condition:
		$header at 0
}

rule apt_c16_win32_dropper : hardened
{
	meta:
		author = "@dragonthreatlab"
		md5 = "ad17eff26994df824be36db246c8fb6a"
		description = "APT malware used to drop PcClient RAT"
		date = "2015/01/11"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

	strings:
		$mz = {4D 5A}
		$str1 = {63 6c 62 63 61 69 71 2e 64 6c 6c}
		$str2 = {70 72 6f 66 61 70 69 5f 31 30 34}
		$str3 = {2f 53 68 6f 77 57 55}
		$str4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c}
		$str5 = {8A 08 2A CA 32 CA 88 08 40 4E 75 F4 5E}

	condition:
		$mz at 0 and all of ( $str* )
}

rule apt_c16_win_swisyn : hardened
{
	meta:
		author = "@dragonthreatlab"
		md5 = "a6a18c846e5179259eba9de238f67e41"
		description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
		date = "2015/01/11"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

	strings:
		$mz = {4D 5A}
		$str1 = {2f 53 68 6f 77 57 55}
		$str2 = {49 73 57 6f 77 36 34 50 72 6f 63 65 73 73}
		$str3 = {72 65 67 73 76 72 33 32 20}
		$str4 = {8A 11 2A 55 FC 8B 45 08 88 10 8B 4D 08 8A 11 32 55 FC 8B 45 08 88 10}

	condition:
		$mz at 0 and all of ( $str* )
}

rule apt_c16_win_wateringhole : refined hardened
{
	meta:
		author = "@dragonthreatlab"
		description = "Detects code from APT wateringhole"
		date = "2015/01/11"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

	strings:
		$str1 = {66 75 6e 63 74 69 6f 6e 20 72 75 6e 6d 75 6d 61 61 28 29}
		$str3 = {66 75 6e 63 74 69 6f 6e 20 4d 6f 53 61 6b 6c 67 45 73 37 28 6b 29}

	condition:
		any of ( $str* )
}

rule apt_c16_win64_dropper : hardened
{
	meta:
		author = "@dragonthreatlab"
		date = "2015/01/11"
		description = "APT malware used to drop PcClient RAT"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

	strings:
		$mz = { 4D 5A }
		$str1 = {63 6c 62 63 61 69 71 2e 64 6c 6c}
		$str2 = {70 72 6f 66 61 70 69 5f 31 30 34}
		$str3 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 77 75 61 75 63 6c 74 5c 77 75 61 75 63 6c 74 2e 64 61 74}
		$str4 = { 0F B6 0A 48 FF C2 80 E9 03 80 F1 03 49 FF C8 88 4A FF 75 EC }

	condition:
		$mz at 0 and all of ( $str* )
}

