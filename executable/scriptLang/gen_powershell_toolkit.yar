rule ps1_toolkit_PowerUp : hardened
{
	meta:
		description = "Auto-generated rule - file PowerUp.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "fc65ec85dbcd49001e6037de9134086dd5559ac41ac4d1adf7cab319546758ad"
		id = "ff3eeec3-602d-5824-8a50-aed2081f49bc"

	strings:
		$s1 = {69 65 78 20 22 24 45 6e 76 3a 53 79 73 74 65 6d 52 6f 6f 74 5c 53 79 73 74 65 6d 33 32 5c 69 6e 65 74 73 72 76 5c 61 70 70 63 6d 64 2e 65 78 65 20 6c 69 73 74 20 76 64 69 72 20 2f 74 65 78 74 3a 76 64 69 72 2e 6e 61 6d 65 22 20 7c 20 25 20 7b 20}
		$s2 = {69 65 78 20 22 24 45 6e 76 3a 53 79 73 74 65 6d 52 6f 6f 74 5c 53 79 73 74 65 6d 33 32 5c 69 6e 65 74 73 72 76 5c 61 70 70 63 6d 64 2e 65 78 65 20 6c 69 73 74 20 61 70 70 70 6f 6f 6c 73 20 2f 74 65 78 74 3a 6e 61 6d 65 22 20 7c 20 25 20 7b 20}
		$s3 = {69 66 20 28 24 45 6e 76 3a 50 52 4f 43 45 53 53 4f 52 5f 41 52 43 48 49 54 45 43 54 55 52 45 20 2d 65 71 20 24 28 5b 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 5d 3a 3a 55 6e 69 63 6f 64 65 2e 47 65 74 53 74 72 69 6e 67 28 5b 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 51 51 42 4e 41 45 51 41 4e 67 41 30 41 41 3d 3d 27 29 29 29 29 20 7b}
		$s4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 49 6e 65 74 53 52 56 5c 61 70 70 63 6d 64 2e 65 78 65 20 6c 69 73 74 20 76 64 69 72 20 2f 74 65 78 74 3a 70 68 79 73 69 63 61 6c 70 61 74 68 20 7c 20}
		$s5 = {69 66 20 28 54 65 73 74 2d 50 61 74 68 20 20 28 22 24 45 6e 76 3a 53 79 73 74 65 6d 52 6f 6f 74 5c 53 79 73 74 65 6d 33 32 5c 69 6e 65 74 73 72 76 5c 61 70 70 63 6d 64 2e 65 78 65 22 29 29}
		$s6 = {69 66 20 28 54 65 73 74 2d 50 61 74 68 20 20 28 22 24 45 6e 76 3a 53 79 73 74 65 6d 52 6f 6f 74 5c 53 79 73 74 65 6d 33 32 5c 49 6e 65 74 53 52 56 5c 61 70 70 63 6d 64 2e 65 78 65 22 29 29 20 7b}
		$s7 = {57 72 69 74 65 2d 56 65 72 62 6f 73 65 20 22 45 78 65 63 75 74 69 6e 67 20 63 6f 6d 6d 61 6e 64 20 27 24 43 6d 64 27 22}
		$s8 = {57 72 69 74 65 2d 57 61 72 6e 69 6e 67 20 22 5b 21 5d 20 54 61 72 67 65 74 20 73 65 72 76 69 63 65}

	condition:
		( uint16( 0 ) == 0xbbef and filesize < 4000KB and 1 of them ) or ( 3 of them )
}

rule ps1_toolkit_Inveigh_BruteForce : hardened
{
	meta:
		description = "Auto-generated rule - file Inveigh-BruteForce.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
		id = "cdc298d3-f9ac-5472-bdc9-0dc51ad91e4a"

	strings:
		$s1 = {49 6d 70 6f 72 74 2d 4d 6f 64 75 6c 65 20 2e 5c 49 6e 76 65 69 67 68 2e 70 73 64 31 3b 49 6e 76 6f 6b 65 2d 49 6e 76 65 69 67 68 42 72 75 74 65 46 6f 72 63 65 20 2d 53 70 6f 6f 66 65 72 54 61 72 67 65 74 20 31 39 32 2e 31 36 38 2e 31 2e 31 31 20}
		$s2 = {24 28 47 65 74 2d 44 61 74 65 20 2d 66 6f 72 6d 61 74 20 27 73 27 29 20 2d 20 41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 73 74 6f 70 20 48 54 54 50 20 6c 69 73 74 65 6e 65 72 22 29 7c 4f 75 74 2d 4e 75 6c 6c}
		$s3 = {49 6e 76 6f 6b 65 2d 49 6e 76 65 69 67 68 42 72 75 74 65 46 6f 72 63 65 20 2d 53 70 6f 6f 66 65 72 54 61 72 67 65 74 20 31 39 32 2e 31 36 38 2e 31 2e 31 31 20 2d 48 6f 73 74 6e 61 6d 65 20 73 65 72 76 65 72 31}

	condition:
		( uint16( 0 ) == 0xbbef and filesize < 300KB and 1 of them ) or ( 2 of them )
}

rule ps1_toolkit_Invoke_Shellcode : hardened
{
	meta:
		description = "Auto-generated rule - file Invoke-Shellcode.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "24abe9f3f366a3d269f8681be80c99504dea51e50318d83ee42f9a4c7435999a"
		id = "193d64b6-ffba-55fb-ab95-9c78552b8d68"

	strings:
		$s1 = {47 65 74 2d 50 72 6f 63 41 64 64 72 65 73 73 20 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 20 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79}
		$s2 = {47 65 74 2d 50 72 6f 63 41 64 64 72 65 73 73 20 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 20 4f 70 65 6e 50 72 6f 63 65 73 73}
		$s3 = {6d 73 66 70 61 79 6c 6f 61 64 20 77 69 6e 64 6f 77 73 2f 65 78 65 63 20 43 4d 44 3d 22 63 6d 64 20 2f 6b 20 63 61 6c 63 22 20 45 58 49 54 46 55 4e 43 3d 74 68 72 65 61 64 20 43 20 7c 20 73 65 64 20 27 31 2c 36 64 3b 73 2f 5b 22 3b 5d 2f 2f 67 3b 73 2f 5c 5c 2f 2c 30 2f 67 27 20 7c 20 74 72 20 2d 64 20 27 5c 6e 27 20 7c 20 63 75 74 20 2d 63 32 2d 20}
		$s4 = {69 6e 6a 65 63 74 20 73 68 65 6c 6c 63 6f 64 65 20 69 6e 74 6f}
		$s5 = {49 6e 6a 65 63 74 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65}

	condition:
		( uint16( 0 ) == 0xbbef and filesize < 90KB and 1 of them ) or ( 3 of them )
}

rule ps1_toolkit_Invoke_Mimikatz : hardened
{
	meta:
		description = "Auto-generated rule - file Invoke-Mimikatz.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "5c31a2e3887662467cfcb0ac37e681f1d9b0f135e6dfff010aae26587e03d8c8"
		id = "7c0252a1-fbe4-5519-949b-285073abb21f"

	strings:
		$s1 = {47 65 74 2d 50 72 6f 63 41 64 64 72 65 73 73 20 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 20 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79}
		$s2 = {70 73 20 7c 20 77 68 65 72 65 20 7b 20 24 5f 2e 4e 61 6d 65 20 2d 65 71 20 24 50 72 6f 63 4e 61 6d 65 20 7d 20 7c 20 73 65 6c 65 63 74 20 50 72 6f 63 65 73 73 4e 61 6d 65 2c 20 49 64 2c 20 53 65 73 73 69 6f 6e 49 64}
		$s3 = {70 72 69 76 69 6c 65 67 65 3a 3a 64 65 62 75 67 20 65 78 69 74}
		$s4 = {47 65 74 2d 50 72 6f 63 41 64 64 72 65 73 73 20 41 64 76 61 70 69 33 32 2e 64 6c 6c 20 41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73}
		$s5 = {49 6e 76 6f 6b 65 2d 4d 69 6d 69 6b 61 74 7a 20 2d 44 75 6d 70 43 72 65 64 73}
		$s6 = {7c 20 41 64 64 2d 4d 65 6d 62 65 72 20 2d 4d 65 6d 62 65 72 54 79 70 65 20 4e 6f 74 65 50 72 6f 70 65 72 74 79 20 2d 4e 61 6d 65 20 49 4d 41 47 45 5f 46 49 4c 45 5f 45 58 45 43 55 54 41 42 4c 45 5f 49 4d 41 47 45 20 2d 56 61 6c 75 65 20 30 78 30 30 30 32}

	condition:
		( uint16( 0 ) == 0xbbef and filesize < 10000KB and 1 of them ) or ( 3 of them )
}

rule ps1_toolkit_Invoke_RelfectivePEInjection : hardened
{
	meta:
		description = "Auto-generated rule - file Invoke-RelfectivePEInjection.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "510b345f821f93c1df5f90ac89ad91fcd0f287ebdabec6c662b716ec9fddb03a"
		id = "75ceb01e-103f-55b2-8362-42d22a35a36a"

	strings:
		$x1 = {49 6e 76 6f 6b 65 2d 52 65 66 6c 65 63 74 69 76 65 50 45 49 6e 6a 65 63 74 69 6f 6e 20 2d 50 45 42 79 74 65 73 20 24 50 45 42 79 74 65 73 20 2d 46 75 6e 63 52 65 74 75 72 6e 54 79 70 65 20 57 53 74 72 69 6e 67 20 2d 43 6f 6d 70 75 74 65 72 4e 61 6d 65 20 28 47 65 74 2d 43 6f 6e 74 65 6e 74 20 74 61 72 67 65 74 6c 69 73 74 2e 74 78 74 29}
		$x2 = {49 6e 76 6f 6b 65 2d 52 65 66 6c 65 63 74 69 76 65 50 45 49 6e 6a 65 63 74 69 6f 6e 20 2d 50 45 42 79 74 65 73 20 24 50 45 42 79 74 65 73 20 2d 46 75 6e 63 52 65 74 75 72 6e 54 79 70 65 20 57 53 74 72 69 6e 67 20 2d 43 6f 6d 70 75 74 65 72 4e 61 6d 65 20 54 61 72 67 65 74 2e 6c 6f 63 61 6c}
		$x3 = {7d 20 3d 20 47 65 74 2d 50 72 6f 63 41 64 64 72 65 73 73 20 41 64 76 61 70 69 33 32 2e 64 6c 6c 20 4f 70 65 6e 54 68 72 65 61 64 54 6f 6b 65 6e}
		$x4 = {49 6e 76 6f 6b 65 2d 52 65 66 6c 65 63 74 69 76 65 50 45 49 6e 6a 65 63 74 69 6f 6e 20 2d 50 45 42 79 74 65 73 20 24 50 45 42 79 74 65 73 20 2d 50 72 6f 63 4e 61 6d 65 20 6c 73 61 73 73 20 2d 43 6f 6d 70 75 74 65 72 4e 61 6d 65 20 54 61 72 67 65 74 2e 4c 6f 63 61 6c}
		$s5 = {24 50 45 42 79 74 65 73 20 3d 20 5b 49 4f 2e 46 69 6c 65 5d 3a 3a 52 65 61 64 41 6c 6c 42 79 74 65 73 28 27 44 65 6d 6f 44 4c 4c 5f 52 65 6d 6f 74 65 50 72 6f 63 65 73 73 2e 64 6c 6c 27 29}
		$s6 = {3d 20 47 65 74 2d 50 72 6f 63 41 64 64 72 65 73 73 20 41 64 76 61 70 69 33 32 2e 64 6c 6c 20 41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73}

	condition:
		( uint16( 0 ) == 0xbbef and filesize < 700KB and 2 of them ) or ( all of them )
}

rule ps1_toolkit_Persistence : hardened
{
	meta:
		description = "Auto-generated rule - file Persistence.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "e1a4dd18b481471fc25adea6a91982b7ffed1c2d393c8c17e6e542c030ac6cbd"
		id = "38115391-75ac-5ba8-b31b-dcf4c66179b0"

	strings:
		$s1 = {22 60 22 60 60 60 24 46 69 6c 74 65 72 3d 53 65 74 2d 57 6d 69 49 6e 73 74 61 6e 63 65 20 2d 43 6c 61 73 73 20 5f 5f 45 76 65 6e 74 46 69 6c 74 65 72 20 2d 4e 61 6d 65 73 70 61 63 65 20 60 60 60 22 72 6f 6f 74 5c 73 75 62 73 63 72 69 70 74 69 6f 6e 60 60 60}
		$s2 = {7d 3d 24 50 52 4f 46 49 4c 45 2e 41 6c 6c 55 73 65 72 73 41 6c 6c 48 6f 73 74 73 3b 24 7b}
		$s3 = {43 3a 5c 50 53 3e 20 24 45 6c 65 76 61 74 65 64 4f 70 74 69 6f 6e 73 20 3d 20 4e 65 77 2d 45 6c 65 76 61 74 65 64 50 65 72 73 69 73 74 65 6e 63 65 4f 70 74 69 6f 6e 20 2d 52 65 67 69 73 74 72 79 20 2d 41 74 53 74 61 72 74 75 70}
		$s4 = {3d 20 67 77 6d 69 20 57 69 6e 33 32 5f 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d 20 7c 20 73 65 6c 65 63 74 20 2d 45 78 70 61 6e 64 50 72 6f 70 65 72 74 79 20 4f 53 41 72 63 68 69 74 65 63 74 75 72 65}
		$s5 = {2d 65 71 20 24 28 5b 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 5d 3a 3a 55 6e 69 63 6f 64 65 2e 47 65 74 53 74 72 69 6e 67 28 5b 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 4d 41 41 78 41 44 51 41 51 77 41 3d 27 29 29 29 29}
		$s6 = {7d 3d 24 50 52 4f 46 49 4c 45 2e 43 75 72 72 65 6e 74 55 73 65 72 41 6c 6c 48 6f 73 74 73 3b 24 7b}
		$s7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 55 77 42 6a 41 47 67 41 5a 51 42 6b 41 48 55 41 62 41 42 6c 41 47 51 41 56 41 42 68 41 48 4d 41 61 77 42 50 41 47 34 41 53 51 42 6b 41 47 77 41 5a 51 41 3d 27 29}
		$s8 = {5b 53 79 73 74 65 6d 2e 54 65 78 74 2e 41 73 63 69 69 45 6e 63 6f 64 69 6e 67 5d 3a 3a 41 53 43 49 49 2e 47 65 74 53 74 72 69 6e 67 28 24 4d 5a 48 65 61 64 65 72 29}

	condition:
		( uint16( 0 ) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_Invoke_Mimikatz_RelfectivePEInjection : hardened
{
	meta:
		description = "Auto-generated rule - from files Invoke-Mimikatz.ps1, Invoke-RelfectivePEInjection.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		super_rule = 1
		hash1 = "5c31a2e3887662467cfcb0ac37e681f1d9b0f135e6dfff010aae26587e03d8c8"
		hash2 = "510b345f821f93c1df5f90ac89ad91fcd0f287ebdabec6c662b716ec9fddb03a"
		id = "e9471f95-48e1-57e0-b0be-f916c574a6a7"

	strings:
		$s1 = {5b 49 6e 74 50 74 72 5d 24 44 6c 6c 41 64 64 72 65 73 73 20 3d 20 5b 53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 2e 4d 61 72 73 68 61 6c 5d 3a 3a 50 74 72 54 6f 53 74 72 75 63 74 75 72 65 28 24 52 65 74 75 72 6e 56 61 6c 4d 65 6d 2c 20 5b 54 79 70 65 5d 5b 49 6e 74 50 74 72 5d 29}
		$s2 = {69 66 20 28 24 47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41 41 64 64 72 20 2d 65 71 20 5b 49 6e 74 50 74 72 5d 3a 3a 5a 65 72 6f 20 2d 6f 72 20 24 47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 57 41 64 64 72 20 2d 65 71 20 5b 49 6e 74 50 74 72 5d 3a 3a 5a 65 72 6f 29}
		$s3 = {5b 42 79 74 65 5b 5d 5d 24 53 68 65 6c 6c 63 6f 64 65 32 20 3d 20 40 28 30 78 63 36 2c 20 30 78 30 33 2c 20 30 78 30 31 2c 20 30 78 34 38 2c 20 30 78 38 33 2c 20 30 78 65 63 2c 20 30 78 32 30 2c 20 30 78 36 36 2c 20 30 78 38 33 2c 20 30 78 65 34 2c 20 30 78 63 30 2c 20 30 78 34 38 2c 20 30 78 62 62 29}
		$s4 = {46 75 6e 63 74 69 6f 6e 20 49 6d 70 6f 72 74 2d 44 6c 6c 49 6e 52 65 6d 6f 74 65 50 72 6f 63 65 73 73}
		$s5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 51 77 42 76 41 47 34 41 64 41 42 70 41 47 34 41 64 51 42 6c 41 41 3d 3d 27 29 29 29}
		$s6 = {5b 42 79 74 65 5b 5d 5d 24 53 68 65 6c 6c 63 6f 64 65 32 20 3d 20 40 28 30 78 63 36 2c 20 30 78 30 33 2c 20 30 78 30 31 2c 20 30 78 38 33 2c 20 30 78 65 63 2c 20 30 78 32 30 2c 20 30 78 38 33 2c 20 30 78 65 34 2c 20 30 78 63 30 2c 20 30 78 62 62 29}
		$s7 = {5b 53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 2e 4d 61 72 73 68 61 6c 5d 3a 3a 46 72 65 65 48 47 6c 6f 62 61 6c 28 24 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 4d 65 6d 29}
		$s8 = {5b 53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 2e 4d 61 72 73 68 61 6c 5d 3a 3a 53 74 72 75 63 74 75 72 65 54 6f 50 74 72 28 24 43 75 72 72 41 64 64 72 2c 20 24 46 69 6e 61 6c 41 64 64 72 2c 20 24 66 61 6c 73 65 29 20 7c 20 4f 75 74 2d 4e 75 6c 6c}
		$s9 = {3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 52 41 42 76 41 47 34 41 5a 51 41 68 41 41 3d 3d 27 29 29 29}
		$s10 = {57 72 69 74 65 2d 56 65 72 62 6f 73 65 20 22 50 6f 77 65 72 53 68 65 6c 6c 20 50 72 6f 63 65 73 73 49 44 3a 20 24 50 49 44 22}
		$s11 = {5b 49 6e 74 50 74 72 5d 24 50 72 6f 63 41 64 64 72 65 73 73 20 3d 20 5b 53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 2e 4d 61 72 73 68 61 6c 5d 3a 3a 50 74 72 54 6f 53 74 72 75 63 74 75 72 65 28 24 52 65 74 75 72 6e 56 61 6c 4d 65 6d 2c 20 5b 54 79 70 65 5d 5b 49 6e 74 50 74 72 5d 29}

	condition:
		( uint16( 0 ) == 0xbbef and filesize < 10000KB and 3 of them ) or ( 6 of them )
}

rule ps1_toolkit_Inveigh_BruteForce_2 : hardened
{
	meta:
		description = "Auto-generated rule - from files Inveigh-BruteForce.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
		id = "1319b03d-67e8-5155-8037-e3375e39f6a0"

	strings:
		$s1 = {7d 2e 4e 54 4c 4d 76 32 5f 66 69 6c 65 5f 71 75 65 75 65 5b 30 5d 7c 4f 75 74 2d 46 69 6c 65 20 24 7b}
		$s2 = {7d 2e 4e 54 4c 4d 76 32 5f 66 69 6c 65 5f 71 75 65 75 65 2e 52 65 6d 6f 76 65 52 61 6e 67 65 28 30 2c 31 29}
		$s3 = {7d 2e 4e 54 4c 4d 76 32 5f 66 69 6c 65 5f 71 75 65 75 65 2e 43 6f 75 6e 74 20 2d 67 74 20 30 29}
		$s4 = {7d 2e 72 65 6c 61 79 5f 72 75 6e 6e 69 6e 67 20 3d 20 24 66 61 6c 73 65}

	condition:
		( uint16( 0 ) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_PowerUp_2 : hardened
{
	meta:
		description = "Auto-generated rule - from files PowerUp.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "fc65ec85dbcd49001e6037de9134086dd5559ac41ac4d1adf7cab319546758ad"
		id = "11322a66-67d4-574b-acef-35d06e6f95f4"

	strings:
		$s1 = {69 66 28 24 4d 79 43 6f 6e 53 74 72 69 6e 67 20 2d 6c 69 6b 65 20 24 28 5b 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 5d 3a 3a 55 6e 69 63 6f 64 65 2e 47 65 74 53 74 72 69 6e 67 28 5b 43 6f 6e 76 65 72 74 5d 3a 3a}
		$s2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 4b 67 42 77 41 47 45 41 63 77 42 7a 41 48 63 41 62 77 42 79 41 47 51 41 4b 67 41 3d 27 29 29 29 29 20 7b}
		$s3 = {24 4e 75 6c 6c 20 3d 20 49 6e 76 6f 6b 65 2d 53 65 72 76 69 63 65 53 74 61 72 74}
		$s4 = {57 72 69 74 65 2d 57 61 72 6e 69 6e 67 20 22 5b 21 5d 20 41 63 63 65 73 73 20 74 6f 20 73 65 72 76 69 63 65 20 24}
		$s5 = {7d 20 3d 20 24 4d 79 43 6f 6e 53 74 72 69 6e 67 2e 53 70 6c 69 74 28 22 3d 22 29 5b 31 5d 2e 53 70 6c 69 74 28 22 3b 22 29 5b 30 5d}
		$s6 = {7d 20 2b 3d 20 22 6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 24 7b}

	condition:
		( uint16( 0 ) == 0xbbef and filesize < 2000KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_Persistence_2 : hardened
{
	meta:
		description = "Auto-generated rule - from files Persistence.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "e1a4dd18b481471fc25adea6a91982b7ffed1c2d393c8c17e6e542c030ac6cbd"
		id = "d79c328b-4471-52bb-882c-12d2e1302c1e"

	strings:
		$s1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 55 77 42 6a 41 47 67 41 5a 51 42 6b 41 48 55 41 62 41 42 6c 41 47 51 41 56 41 42 68 41 48 4d 41 61 77 42 50 41 47 34 41 53 51 42 6b 41 47 77 41 5a 51 41 3d 27 29}
		$s2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 55 77 42 6a 41 47 67 41 5a 51 42 6b 41 48 55 41 62 41 42 6c 41 47 51 41 56 41 42 68 41 48 4d 41 61 77 42 45 41 47 45 41 61 51 42 73 41 48 6b 41 27 29}
		$s3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 55 41 42 31 41 47 49 41 62 41 42 70 41 47 4d 41 4c 41 41 67 41 46 4d 41 64 41 42 68 41 48 51 41 61 51 42 6a 41 41 3d 3d 27 29}
		$s4 = {5b 50 61 72 61 6d 65 74 65 72 28 20 50 61 72 61 6d 65 74 65 72 53 65 74 4e 61 6d 65 20 3d 20 27 53 63 68 65 64 75 6c 65 64 54 61 73 6b 41 74 4c 6f 67 6f 6e 27 2c 20 4d 61 6e 64 61 74 6f 72 79 20 3d 20 24 54 72 75 65 20 29 5d}
		$s5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 55 77 42 6a 41 47 67 41 5a 51 42 6b 41 48 55 41 62 41 42 6c 41 47 51 41 56 41 42 68 41 48 4d 41 61 77 42 42 41 48 51 41 54 41 42 76 41 47 63 41 62 77 42 75 41 41 3d 3d 27 29 29 29}
		$s6 = {5b 50 61 72 61 6d 65 74 65 72 28 20 50 61 72 61 6d 65 74 65 72 53 65 74 4e 61 6d 65 20 3d 20 27 50 65 72 6d 61 6e 65 6e 74 57 4d 49 41 74 53 74 61 72 74 75 70 27 2c 20 4d 61 6e 64 61 74 6f 72 79 20 3d 20 24 54 72 75 65 20 29 5d}
		$s7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 54 51 42 6c 41 48 51 41 61 41 42 76 41 47 51 41 27 29}
		$s8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 56 41 42 79 41 47 6b 41 5a 77 42 6e 41 47 55 41 63 67 41 3d 27 29}
		$s9 = {5b 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 2e 43 61 6c 6c 69 6e 67 43 6f 6e 76 65 6e 74 69 6f 6e 5d 3a 3a 57 69 6e 61 70 69 2c}

	condition:
		( uint16( 0 ) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_Inveigh_BruteForce_3 : hardened
{
	meta:
		description = "Auto-generated rule - from files Inveigh-BruteForce.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash3 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
		id = "d284e93b-dd65-5a39-84e2-287feb6ae05b"

	strings:
		$s1 = {3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 54 67 42 55 41 45 77 41 54 51 41 3d 27 29}
		$s2 = {3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 4b 67 42 54 41 45 30 41 51 67 41 67 41 48 49 41 5a 51 42 73 41 47 45 41 65 51 41 67 41 43 6f 41 27 29 29 29}
		$s3 = {3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 4b 67 41 67 41 47 59 41 62 77 42 79 41 43 41 41 63 67 42 6c 41 47 77 41 59 51 42 35 41 43 41 41 4b 67 41 3d 27 29 29 29}
		$s4 = {3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 4b 67 41 67 41 48 63 41 63 67 42 70 41 48 51 41 64 41 42 6c 41 47 34 41 49 41 42 30 41 47 38 41 49 41 41 71 41 41 3d 3d 27 29 29 29}
		$s5 = {5b 42 79 74 65 5b 5d 5d 20 24 48 54 54 50 5f 72 65 73 70 6f 6e 73 65 20 3d 20 28 30 78 34 38 2c 30 78 35 34 2c 30 78 35 34 2c 30 78 35 30 2c 30 78 32 66 2c 30 78 33 31 2c 30 78 32 65 2c 30 78 33 31 2c 30 78 32 30 29 60}
		$s6 = {4b 67 41 67 41 47 77 41 62 77 42 6a 41 47 45 41 62 41 41 67 41 47 45 41 5a 41 42 74 41 47 6b 41 62 67 42 70 41 48 4d 41 64 41 42 79 41 47 45 41 64 41 42 76 41 48 49 41 49 41 41 71 41 41}
		$s7 = {7d 2e 62 72 75 74 65 66 6f 72 63 65 5f 72 75 6e 6e 69 6e 67 29}

	condition:
		( uint16( 0 ) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

