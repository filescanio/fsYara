rule FourElementSword_Config_File : hardened
{
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "f05cd0353817bf6c2cab396181464c31c352d6dea07e2d688def261dd6542b27"
		id = "488a2344-3d8d-5769-aca8-9e14f38f5eb0"

	strings:
		$s0 = {30 31 2c 2c 68 63 63 75 74 69 6c 73 2e 64 6c 6c 2c 32}
		$s1 = {52 65 67 69 73 74 65 72 44 6c 6c 73 3d 4f 75 72 44 6c 6c}
		$s2 = {5b 4f 75 72 44 6c 6c 5d}
		$s3 = {5b 44 65 66 61 75 6c 74 49 6e 73 74 61 6c 6c 5d}
		$s4 = {53 69 67 6e 61 74 75 72 65 3d 22 24 57 69 6e 64 6f 77 73 20 4e 54 24 22}

	condition:
		4 of them
}

rule FourElementSword_T9000 : hardened
{
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
		id = "35ae844e-52e1-5e6f-984d-aa75ebd2f60f"

	strings:
		$x1 = {44 3a 5c 57 4f 52 4b 5c 54 39 30 30 30 5c}
		$x2 = {25 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 48 00 48 00 48 00 48 00 2e 00 64 00 61 00 74 00}
		$s1 = {45 00 6c 00 65 00 76 00 61 00 74 00 65 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {52 00 65 00 73 00 4e 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 20 00 28 00 63 00 6f 00 6d 00 70 00 61 00 74 00 69 00 62 00 6c 00 65 00 3b 00 20 00 4d 00 53 00 49 00 45 00 20 00 36 00 2e 00 30 00 3b 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 35 00 2e 00 31 00 3b 00 20 00 53 00 56 00 31 00 29 00}
		$s4 = {69 00 67 00 66 00 78 00 74 00 72 00 61 00 79 00 2e 00 65 00 78 00 65 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 500KB and 1 of ( $x* ) ) or ( all of them )
}

rule FourElementSword_32DLL : hardened
{
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "7a200c4df99887991c638fe625d07a4a3fc2bdc887112437752b3df5c8da79b6"
		id = "fc801364-9f40-50eb-90e1-99f8605014c7"

	strings:
		$x1 = {25 74 65 6d 70 25 5c 74 6d 70 30 39 32 2e 74 6d 70}
		$s1 = {5c 53 79 73 74 65 6d 33 32 5c 63 74 66 6d 6f 6e 2e 65 78 65}
		$s2 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c}
		$s3 = {33 32 2e 64 6c 6c}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 660KB and $x1 ) or ( all of them )
}

rule FourElementSword_Keyainst_EXE : hardened
{
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "cf717a646a015ee72f965488f8df2dd3c36c4714ccc755c295645fe8d150d082"
		id = "175fe2b0-3c76-5464-9a1a-218a09b25a5a"

	strings:
		$x1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4b 65 79 61 69 6e 73 74 2e 65 78 65}
		$s1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41}
		$s2 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41}
		$s3 = {53 48 45 4c 4c 33 32 2e 64 6c 6c}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 48KB and $x1 ) or ( all of them )
}

rule FourElementSword_ElevateDLL_2 : hardened
{
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "9c23febc49c7b17387767844356d38d5578727ee1150956164883cf555fe7f95"
		id = "06879d75-18a3-5d49-a963-fa4bee379387"

	strings:
		$s1 = {45 6c 65 76 61 74 65 2e 64 6c 6c}
		$s2 = {47 65 74 53 6f 6d 65 46}
		$s3 = {47 65 74 4e 61 74 69 76 65 53 79 73 74 65 6d 49 6e 66 6f}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 25KB and $s1 ) or ( all of them )
}

rule FourElementSword_fslapi_dll_gui : hardened
{
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "2a6ef9dde178c4afe32fe676ff864162f104d85fac2439986de32366625dc083"
		id = "1cc73eaf-7463-5070-97e5-6ea4c7735371"

	strings:
		$s1 = {66 00 73 00 6c 00 61 00 70 00 69 00 2e 00 64 00 6c 00 6c 00 2e 00 67 00 75 00 69 00}
		$s2 = {49 6d 6d 47 65 74 44 65 66 61 75 6c 74 49 4d 45 57 6e 64}
		$s3 = {52 69 63 68 4f 58}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 12KB and all of them )
}

rule FourElementSword_PowerShell_Start : hardened
{
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "9b6053e784c5762fdb9931f9064ba6e52c26c2d4b09efd6ff13ca87bbb33c692"
		id = "62affc03-a408-5d8f-99da-58dead8646c5"

	strings:
		$s0 = {73 74 61 72 74 20 2f 6d 69 6e 20 70 6f 77 65 72 73 68 65 6c 6c 20 43 3a 5c 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 5c 77 67 65 74 2e 65 78 65}
		$s1 = {73 74 61 72 74 20 2f 6d 69 6e 20 70 6f 77 65 72 73 68 65 6c 6c 20 43 3a 5c 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 5c 69 75 73 6f 2e 65 78 65}

	condition:
		1 of them
}

rule FourElementSword_ResN32DLL : hardened
{
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "bf1b00b7430899d33795ef3405142e880ef8dcbda8aab0b19d80875a14ed852f"
		id = "3e1f6d8d-53ea-542f-ba49-39b4c86f3124"

	strings:
		$s1 = {5c 52 65 6c 65 61 73 65 5c 42 79 70 61 73 73 55 41 43 2e 70 64 62}
		$s2 = {5c 00 52 00 65 00 73 00 4e 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {45 00 75 00 70 00 64 00 61 00 74 00 65 00}

	condition:
		all of them
}

rule FourElementSword_ElevateDLL : hardened
{
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		super_rule = 1
		hash1 = "3dfc94605daf51ebd7bbccbb3a9049999f8d555db0999a6a7e6265a7e458cab9"
		hash2 = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
		id = "06879d75-18a3-5d49-a963-fa4bee379387"

	strings:
		$x1 = {45 00 6c 00 65 00 76 00 61 00 74 00 65 00 2e 00 64 00 6c 00 6c 00}
		$x2 = {52 00 65 00 73 00 4e 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}
		$s1 = {4b 00 69 00 6e 00 67 00 73 00 6f 00 66 00 74 00 5c 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00}
		$s2 = {4b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 4c 00 61 00 62 00 5c 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00}
		$s3 = {53 00 6f 00 70 00 68 00 6f 00 73 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 500KB and 1 of ( $x* ) and all of ( $s* ) ) or ( all of them )
}

