rule Win_PrivEsc_gp3finder_v4_0 : hardened limited
{
	meta:
		description = "Detects a tool that can be used for privilege escalation - file gp3finder_v4.0.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://grimhacker.com/2015/04/10/gp3finder-group-policy-preference-password-finder/"
		date = "2016-06-02"
		score = 80
		hash1 = "7d34e214ef2ca33516875fb91a72d5798f89b9ea8964d3990f99863c79530c06"
		id = "3b310c12-ac69-527b-9503-1486ae5f692c"

	strings:
		$x1 = {43 68 65 63 6b 20 66 6f 72 20 61 6e 64 20 61 74 74 65 6d 70 74 20 74 6f 20 64 65 63 72 79 70 74 20 70 61 73 73 77 6f 72 64 73 20 6f 6e 20 73 68 61 72 65}
		$x2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 46 61 69 6c 65 64 20 74 6f 20 61 75 74 6f 20 67 65 74 20 61 6e 64 20 64 65 63 72 79 70 74 20 70 61 73 73 77 6f 72 64 73 2e 20 7b 30 7d 73 2f (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 47 50 50 50 46 69 6e 64 65 72 20 2d 20 47 72 6f 75 70 20 50 6f 6c 69 63 79 20 50 72 65 66 65 72 65 6e 63 65 20 50 61 73 73 77 6f 72 64 20 46 69 6e 64 65 72 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( uint16( 0 ) == 0x5a4d and 1 of ( $x* ) ) or ( all of them )
}

rule Win_PrivEsc_folderperm : hardened limited
{
	meta:
		description = "Detects a tool that can be used for privilege escalation - file folderperm.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.greyhathacker.net/?p=738"
		date = "2016-06-02"
		score = 80
		hash1 = "1aa87df34826b1081c40bb4b702750587b32d717ea6df3c29715eb7fc04db755"
		id = "131fdb57-f9ca-5247-8bb4-c939eff5b8bf"

	strings:
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 23 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 65 78 65 63 75 74 69 6f 6e 70 6f 6c 69 63 79 20 62 79 70 61 73 73 20 2d 66 69 6c 65 20 66 6f 6c 64 65 72 70 65 72 6d 2e 70 73 31 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 57 72 69 74 65 2d 48 6f 73 74 20 22 5b 69 5d 20 44 75 6d 6d 79 20 74 65 73 74 20 66 69 6c 65 20 75 73 65 64 20 74 6f 20 74 65 73 74 20 61 63 63 65 73 73 20 77 61 73 20 6e 6f 74 20 6f 75 74 70 75 74 74 65 64 3a 22 20 24 66 69 6c 65 74 6f 63 6f 70 79 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 57 72 69 74 65 2d 48 6f 73 74 20 2d 66 6f 72 65 67 72 6f 75 6e 64 43 6f 6c 6f 72 20 52 65 64 20 22 20 20 20 20 20 20 41 63 63 65 73 73 20 64 65 6e 69 65 64 20 3a 22 20 24 6d 79 61 72 72 61 79 5b 24 69 5d 20 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		1 of them
}

rule Win_PrivEsc_ADACLScan4_3 : hardened limited
{
	meta:
		description = "Detects a tool that can be used for privilege escalation - file ADACLScan4.3.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://adaclscan.codeplex.com/"
		score = 60
		date = "2016-06-02"
		hash1 = "3473ddb452de7640fab03cad3e8aaf6a527bdd6a7a311909cfef9de0b4b78333"
		id = "15867a9c-9b9b-5d29-bf51-2b3e91af556f"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 3c 4c 61 62 65 6c 20 78 3a 4e 61 6d 65 3d 22 6c 62 6c 50 6f 72 74 22 20 43 6f 6e 74 65 6e 74 3d 22 50 6f 72 74 3a 22 20 20 48 6f 72 69 7a 6f 6e 74 61 6c 41 6c 69 67 6e 6d 65 6e 74 3d 22 4c 65 66 74 22 20 48 65 69 67 68 74 3d 22 32 38 22 20 4d 61 72 67 69 6e 3d 22 31 30 2c 30 2c 30 2c 30 22 20 57 69 64 74 68 3d 22 33 35 22 2f 3e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 28 28 5b 53 79 73 74 65 6d 2e 49 63 6f 6e 45 78 74 72 61 63 74 6f 72 5d 3a 3a 45 78 74 72 61 63 74 28 22 6d 6d 63 6e 64 6d 67 72 2e 64 6c 6c 22 2c 20 31 32 36 2c 20 24 74 72 75 65 29 29 2e 54 6f 42 69 74 4d 61 70 28 29 29 2e 53 61 76 65 28 24 65 6e 76 3a 74 65 6d 70 20 2b 20 22 5c 4f 74 68 65 72 2e 70 6e 67 22 29 20 20 20 20 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 24 62 6f 6c 56 61 6c 69 64 20 3d 20 24 63 74 78 2e 56 61 6c 69 64 61 74 65 43 72 65 64 65 6e 74 69 61 6c 73 28 24 70 73 43 72 65 64 2e 55 73 65 72 4e 61 6d 65 2c 24 70 73 43 72 65 64 2e 47 65 74 4e 65 74 77 6f 72 6b 43 72 65 64 65 6e 74 69 61 6c 28 29 2e 50 61 73 73 77 6f 72 64 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		all of them
}

