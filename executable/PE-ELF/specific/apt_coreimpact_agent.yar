rule CoreImpact_sysdll_exe : hardened
{
	meta:
		description = "Detects a malware sysdll.exe from the Rocket Kitten APT"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		date = "27.12.2014"
		modified = "2023-01-06"
		hash = "f89a4d4ae5cca6d69a5256c96111e707"
		id = "bac55c00-5d14-59ca-8597-f52b4577be0c"

	strings:
		$s0 = {64 3a 5c 6e 69 67 68 74 6c 79 5c 73 61 6e 64 62 6f 78 5f 61 76 67 31 30 5f 76 63 39 5f 53 50 31 5f 32 30 31 31 5c 73 6f 75 72 63 65 5c 61 76 67 31 30 5c 61 76 67 39 5f 61 6c 6c 5f 76 73 39 30 5c 62 69 6e 5c 52 65 6c 65}
		$s1 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30}
		$s3 = {69 6e 64 65 78 2e 70 68 70 3f 63 3d 25 73 26 72 3d 25 6c 78}
		$s4 = {69 6e 64 65 78 2e 70 68 70 3f 63 3d 25 73 26 72 3d 25 78}
		$s5 = {31 32 37 2e 30 2e 30 2e 31}
		$s6 = {2f 69 6e 66 6f 2e 64 61 74}
		$s7 = {6e 65 65 64 72 6f 6f 74}
		$s8 = {2e 2f 70 6c 75 67 69 6e 73 2f}

	condition:
		$s0 or 6 of them
}

