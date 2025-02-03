rule Rombertik_CarbonGrabber : hardened
{
	meta:
		description = "Detects CarbonGrabber alias Rombertik - file Copy#064046.scr"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash1 = "2f9b26b90311e62662c5946a1ac600d2996d3758"
		hash2 = "aeb94064af2a6107a14fd32f39cb502e704cd0ab"
		hash3 = "c2005c8d1a79da5e02e6a15d00151018658c264c"
		hash4 = "98223d4ec272d3a631498b621618d875dd32161d"
		id = "b3aee336-9f3b-5fae-928d-8357408a7b69"

	strings:
		$x1 = {5a 77 47 65 74 57 72 69 74 65 57 61 74 63 68}
		$x2 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41}
		$x3 = {6d 61 6c 77 61 72}
		$x4 = {73 61 6d 70 6c}
		$x5 = {76 69 72 75}
		$x6 = {73 61 6e 64 62}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 5MB and all of them
}

rule Rombertik_CarbonGrabber_Panel_InstallScript : hardened
{
	meta:
		description = "Detects CarbonGrabber alias Rombertik panel install script - file install.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash = "cd6c152dd1e0689e0bede30a8bd07fef465fbcfa"
		id = "f6c04e27-bbab-5012-a4f9-71d49d252b83"

	strings:
		$s0 = {24 69 6e 73 65 72 74 20 3d 20 22 49 4e 53 45 52 54 20 49 4e 54 4f 20 60 6c 6f 67 73 60 20 28 60 69 64 60 2c 20 60 69 70 60 2c 20 60 6e 61 6d 65 60 2c 20 60 68 6f 73 74 60 2c 20 60 70 6f 73 74 60 2c 20 60 74 69 6d 65 60 2c 20 60 62 72 6f}
		$s3 = {60 70 6f 73 74 60 20 74 65 78 74 20 4e 4f 54 20 4e 55 4c 4c 2c}
		$s4 = {60 68 6f 73 74 60 20 74 65 78 74 20 4e 4f 54 20 4e 55 4c 4c 2c}
		$s5 = {29 20 45 4e 47 49 4e 45 3d 49 6e 6e 6f 44 42 20 20 44 45 46 41 55 4c 54 20 43 48 41 52 53 45 54 3d 6c 61 74 69 6e 31 20 41 55 54 4f 5f 49 4e 43 52 45 4d 45 4e 54 3d 35 20 3b 22 20 3b}
		$s6 = {24 64 62 2d 3e 65 78 65 63 28 24 63 6f 6c 75 6d 6e 73 29 3b 20 2f 2f 6f 72 20 64 69 65 28 70 72 69 6e 74 5f 72 28 24 64 62 2d 3e 65 72 72 6f 72 49 6e 66 6f 28 29 2c 20 74 72 75 65 29 29 3b 3b}
		$s9 = {24 64 62 2d 3e 65 78 65 63 28 24 69 6e 73 65 72 74 29 3b}
		$s10 = {60 62 72 6f 77 73 65 72 60 20 74 65 78 74 20 4e 4f 54 20 4e 55 4c 4c 2c}
		$s13 = {60 69 70 60 20 74 65 78 74 20 4e 4f 54 20 4e 55 4c 4c 2c}

	condition:
		filesize < 3KB and all of them
}

rule Rombertik_CarbonGrabber_Panel : hardened
{
	meta:
		description = "Detects CarbonGrabber alias Rombertik Panel - file index.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash = "e6e9e4fc3772ff33bbeeda51f217e9149db60082"
		id = "f6c04e27-bbab-5012-a4f9-71d49d252b83"

	strings:
		$s0 = {65 63 68 6f 20 27 3c 6d 65 74 61 20 68 74 74 70 2d 65 71 75 69 76 3d 22 72 65 66 72 65 73 68 22 20 63 6f 6e 74 65 6e 74 3d 22 30 3b 75 72 6c 3d 69 6e 64 65 78 2e 70 68 70 3f 61 3d 6c 6f 67 69 6e 22 3e 27 3b}
		$s1 = {65 63 68 6f 20 27 3c 6d 65 74 61 20 68 74 74 70 2d 65 71 75 69 76 3d 22 72 65 66 72 65 73 68 22 20 63 6f 6e 74 65 6e 74 3d 22 32 3b 75 72 6c 3d 27 2e 24 77 65 62 73 69 74 65 2e 27 2f 69 6e 64 65 78 2e 70 68 70 3f 61 3d 6c 6f 67 69 6e}
		$s2 = {68 65 61 64 65 72 28 22 6c 6f 63 61 74 69 6f 6e 3a 20 24 77 65 62 73 69 74 65 2f 69 6e 64 65 78 2e 70 68 70 3f 61 3d 6c 6f 67 69 6e 22 29 3b}
		$s3 = {24 69 6e 73 65 72 74 4c 6f 67 53 51 4c 20 2d 3e 20 65 78 65 63 75 74 65 28 61 72 72 61 79 28 27 3a 69 64 27 20 3d 3e 20 4e 55 4c 4c 2c 20 27 3a 69 70 27 20 3d 3e 20 24 69 70 2c 20 27 3a 6e 61 6d 65 27 20 3d 3e 20 24 6e 61 6d 65 2c 20 27 3a}
		$s16 = {69 66 28 24 5f 50 4f 53 54 5b 27 75 73 65 72 6e 61 6d 65 27 5d 20 3d 3d 20 24 75 73 65 72 6e 61 6d 65 20 26 26 20 24 5f 50 4f 53 54 5b 27 70 61 73 73 77 6f 72 64 27 5d 20 3d 3d 20 24 70 61 73 73 77 6f 72 64 29 7b}
		$s17 = {24 53 51 4c 20 3d 20 24 64 62 20 2d 3e 20 70 72 65 70 61 72 65 28 22 54 52 55 4e 43 41 54 45 20 54 41 42 4c 45 20 60 6c 6f 67 73 60 22 29 3b}

	condition:
		filesize < 46KB and all of them
}

rule Rombertik_CarbonGrabber_Builder : hardened
{
	meta:
		description = "Detects CarbonGrabber alias Rombertik Builder - file Builder.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash = "b50ecc0ba3d6ec19b53efe505d14276e9e71285f"
		id = "3233c139-ac06-576c-9870-51306d5aa385"

	strings:
		$s0 = {63 3a 5c 75 73 65 72 73 5c 69 64 65 6e 5c 64 6f 63 75 6d 65 6e 74 73 5c 76 69 73 75 61 6c 20 73 74 75 64 69 6f 20 32 30 31 30 5c 50 72 6f 6a 65 63 74 73 5c 46 6f 72 6d 47 72 61 62 62 65 72 42 75 69 6c 64 65 72 43 2b 2b}
		$s1 = {48 6f 73 74 28 77 77 77 2e 70 61 6e 65 6c 2e 63 6f 6d 29 3a 20}
		$s2 = {50 61 74 68 28 2f 66 6f 72 6d 2f 69 6e 64 65 78 2e 70 68 70 3f 61 3d 69 6e 73 65 72 74 29 3a 20}
		$s3 = {46 69 6c 65 4e 61 6d 65 3a 20}
		$s4 = {7e 52 69 63 68 38}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 35KB and all of them
}

rule Rombertik_CarbonGrabber_Builder_Server : hardened
{
	meta:
		description = "Detects CarbonGrabber alias Rombertik Builder Server - file Server.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash = "895fab8d55882eac51d4b27a188aa67205ff0ae5"
		id = "742003a2-3716-5ad9-a720-b9e2be71554a"

	strings:
		$s0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65}
		$s3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65}
		$s4 = {63 68 72 6f 6d 65 2e 65 78 65}
		$s5 = {66 69 72 65 66 6f 78 2e 65 78 65}
		$s6 = {63 68 72 6f 6d 65 2e 64 6c 6c}
		$s7 = {40 00 4b 00 45 00 52 00 4e 00 45 00 4c 00 33 00 32 00 2e 00 44 00 4c 00 4c 00}
		$s8 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 30 3b 20 57 4f 57 36 34 29 20 41 70 70 6c 65 57 65 62 4b 69 74 2f 35 33 37 2e 33 36 20 28 4b 48 54 4d 4c 2c 20 6c 69 6b 65 20 47 65 63 6b 6f 29 20 43 68 72 6f 6d 65}
		$s10 = {26 70 6f 73 74 3d}
		$s11 = {26 68 6f 73 74 3d}
		$s12 = {57 73 32 5f 33 32 2e 64 6c 6c}
		$s16 = {26 62 72 6f 77 73 65 72 3d}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 250KB and 8 of them
}

