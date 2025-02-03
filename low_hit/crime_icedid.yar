rule MAL_IcedID_Fake_GZIP_Bokbot_202104 : hardened
{
	meta:
		author = "Thomas Barabosch, Telekom Security"
		date = "2021-04-20"
		description = "Detects fake gzip provided by CC"
		reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
		id = "538d84d8-aff2-571c-ba60-102f18262434"

	strings:
		$gzip = {1f 8b 08 08 00 00 00 00 00 00 75 70 64 61 74 65}

	condition:
		$gzip at 0
}

rule MAL_IcedID_GZIP_LDR_202104 : hardened
{
	meta:
		author = "Thomas Barabosch, Telekom Security"
		date = "2021-04-12"
		modified = "2023-01-27"
		description = "2021 initial Bokbot / Icedid loader for fake GZIP payloads"
		reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
		id = "fbf578e7-c318-5f67-82df-f93232362a23"

	strings:
		$internal_name = {6c 6f 61 64 65 72 5f 64 6c 6c 5f 36 34 2e 64 6c 6c}
		$string0 = {5f 00 67 00 61 00 74 00 3d 00}
		$string1 = {5f 00 67 00 61 00 3d 00}
		$string2 = {5f 00 67 00 69 00 64 00 3d 00}
		$string4 = {5f 00 69 00 6f 00 3d 00}
		$string5 = {47 65 74 41 64 61 70 74 65 72 73 49 6e 66 6f}
		$string6 = {57 49 4e 48 54 54 50 2e 64 6c 6c}
		$string7 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}
		$string8 = {50 6c 75 67 69 6e 49 6e 69 74}
		$string9 = {50 00 4f 00 53 00 54 00}
		$string10 = {61 00 77 00 73 00 2e 00 61 00 6d 00 61 00 7a 00 6f 00 6e 00 2e 00 63 00 6f 00 6d 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 5000KB and ( $internal_name or all of ( $s* ) ) or all of them
}

rule MAL_IcedId_Core_LDR_202104 : hardened
{
	meta:
		author = "Thomas Barabosch, Telekom Security"
		date = "2021-04-13"
		description = "2021 loader for Bokbot / Icedid core (license.dat)"
		reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
		id = "f096e18d-3a31-5236-b3c3-0df39b408d9a"

	strings:
		$internal_name = {73 61 64 6c 5f 36 34 2e 64 6c 6c}
		$string0 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41}
		$string1 = {4c 6f 61 64 4c 69 62 72 61 72 79 41}
		$string2 = {50 72 6f 67 72 61 6d 44 61 74 61}
		$string3 = {53 48 4c 57 41 50 49 2e 64 6c 6c}
		$string4 = {53 48 47 65 74 46 6f 6c 64 65 72 50 61 74 68 41}
		$string5 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}
		$string6 = {75 70 64 61 74 65}
		$string7 = {53 48 45 4c 4c 33 32 2e 64 6c 6c}
		$string8 = {43 72 65 61 74 65 54 68 72 65 61 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 5000KB and ( $internal_name and 5 of them ) or all of them
}

rule MAL_IceId_Core_202104 : hardened
{
	meta:
		author = "Thomas Barabosch, Telekom Security"
		date = "2021-04-12"
		description = "2021 Bokbot / Icedid core"
		reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
		id = "526a73da-415f-58fe-bb5f-4c3df6b2e647"

	strings:
		$internal_name = {66 69 78 65 64 5f 6c 6f 61 64 65 72 36 34 2e 64 6c 6c}
		$string0 = {6d 00 61 00 69 00 6c 00 5f 00 76 00 61 00 75 00 6c 00 74 00}
		$string1 = {69 00 65 00 5f 00 72 00 65 00 67 00}
		$string2 = {6f 00 75 00 74 00 6c 00 6f 00 6f 00 6b 00}
		$string3 = {75 00 73 00 65 00 72 00 5f 00 6e 00 75 00 6d 00}
		$string4 = {63 00 72 00 65 00 64 00}
		$string5 = {41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 3a 20 42 61 73 69 63}
		$string6 = {56 61 75 6c 74 4f 70 65 6e 56 61 75 6c 74}
		$string7 = {73 71 6c 69 74 65 33 5f 66 72 65 65}
		$string8 = {63 6f 6f 6b 69 65 2e 74 61 72}
		$string9 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}
		$string10 = {50 00 54 00 30 00 53 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 5000KB and ( $internal_name or all of ( $s* ) ) or all of them
}

