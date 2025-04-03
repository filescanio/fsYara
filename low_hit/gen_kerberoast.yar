rule GetUserSPNs_VBS : hardened limited
{
	meta:
		description = "Auto-generated rule - file GetUserSPNs.vbs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/skelsec/PyKerberoast"
		date = "2016-05-21"
		hash1 = "8dcb568d475fd8a0557e70ca88a262b7c06d0f42835c855b52e059c0f5ce9237"
		id = "5576c1b9-4670-52c5-b23c-64adcc8709de"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 57 73 63 72 69 70 74 2e 45 63 68 6f 20 22 55 73 65 72 20 4c 6f 67 6f 6e 3a 20 22 20 26 20 6f 52 65 63 6f 72 64 73 65 74 2e 46 69 65 6c 64 73 28 22 73 61 6d 41 63 63 6f 75 6e 74 4e 61 6d 65 22 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 57 73 63 72 69 70 74 2e 45 63 68 6f 20 22 20 55 53 41 47 45 3a 20 20 20 20 20 20 20 20 22 20 26 20 57 53 63 72 69 70 74 2e 53 63 72 69 70 74 4e 61 6d 65 20 26 20 22 20 53 70 6e 54 6f 46 69 6e 64 20 5b 47 43 20 53 65 72 76 65 72 6e 61 6d 65 20 6f 72 20 46 6f 72 65 73 74 6e 61 6d 65 5d 22 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 74 72 41 44 4f 51 75 65 72 79 20 3d 20 22 3c 22 20 2b 20 73 74 72 47 43 50 61 74 68 20 2b 20 22 3e 3b 28 26 28 21 6f 62 6a 65 63 74 43 6c 61 73 73 3d 63 6f 6d 70 75 74 65 72 29 28 73 65 72 76 69 63 65 50 72 69 6e 63 69 70 61 6c 4e 61 6d 65 3d 2a 29 29 3b 22 20 26 20 5f (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		2 of them
}

rule GetUserSPNs_PS1 : hardened limited
{
	meta:
		description = "Auto-generated rule - file GetUserSPNs.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/skelsec/PyKerberoast"
		date = "2016-05-21"
		hash1 = "1b69206b8d93ac86fe364178011723f4b1544fff7eb1ea544ab8912c436ddc04"
		id = "a2fba75c-264f-5e89-afaf-9d19a4a90784"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 46 6f 72 65 73 74 49 6e 66 6f 20 3d 20 5b 53 79 73 74 65 6d 2e 44 69 72 65 63 74 6f 72 79 53 65 72 76 69 63 65 73 2e 41 63 74 69 76 65 44 69 72 65 63 74 6f 72 79 2e 46 6f 72 65 73 74 5d 3a 3a 47 65 74 43 75 72 72 65 6e 74 46 6f 72 65 73 74 28 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 40 7b 4e 61 6d 65 3d 22 50 61 73 73 77 6f 72 64 4c 61 73 74 53 65 74 22 3b 20 20 20 20 20 20 45 78 70 72 65 73 73 69 6f 6e 3d 7b 5b 64 61 74 65 74 69 6d 65 5d 3a 3a 66 72 6f 6d 46 69 6c 65 54 69 6d 65 28 24 72 65 73 75 6c 74 2e 50 72 6f 70 65 72 74 69 65 73 5b 22 70 77 64 6c 61 73 74 73 65 74 22 5d 5b 30 5d 29 7d 20 7d 20 23 2c 20 60 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 57 72 69 74 65 2d 48 6f 73 74 20 22 4e 6f 20 47 6c 6f 62 61 6c 20 43 61 74 61 6c 6f 67 73 20 46 6f 75 6e 64 21 22 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 73 65 61 72 63 68 65 72 2e 50 72 6f 70 65 72 74 69 65 73 54 6f 4c 6f 61 64 2e 41 64 64 28 22 70 77 64 6c 61 73 74 73 65 74 22 29 20 7c 20 4f 75 74 2d 4e 75 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		2 of them
}

rule kerberoast_PY : hardened limited
{
	meta:
		description = "Auto-generated rule - file kerberoast.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/skelsec/PyKerberoast"
		date = "2016-05-21"
		hash1 = "73155949b4344db2ae511ec8cab85da1ccbf2dfec3607fb9acdc281357cdf380"
		id = "cea6cdb2-cd1a-5701-a9d1-27c788a962a7"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6e 65 77 65 6e 63 73 65 72 76 65 72 74 69 63 6b 65 74 20 3d 20 6b 65 72 62 65 72 6f 73 2e 65 6e 63 72 79 70 74 28 6b 65 79 2c 20 32 2c 20 65 6e 63 6f 64 65 72 2e 65 6e 63 6f 64 65 28 64 65 63 73 65 72 76 65 72 74 69 63 6b 65 74 29 2c 20 6e 6f 6e 63 65 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6b 65 79 20 3d 20 6b 65 72 62 65 72 6f 73 2e 6e 74 6c 6d 68 61 73 68 28 61 72 67 73 2e 70 61 73 73 77 6f 72 64 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 68 65 6c 70 3d 27 74 68 65 20 70 61 73 73 77 6f 72 64 20 75 73 65 64 20 74 6f 20 64 65 63 72 79 70 74 2f 65 6e 63 72 79 70 74 20 74 68 65 20 74 69 63 6b 65 74 27 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6e 65 77 65 6e 63 73 65 72 76 65 72 74 69 63 6b 65 74 20 3d 20 6b 65 72 62 65 72 6f 73 2e 65 6e 63 72 79 70 74 28 6b 65 79 2c 20 32 2c 20 65 2c 20 6e 6f 6e 63 65 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		2 of them
}

