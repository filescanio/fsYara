rule WEBSHELL_JSP_Nov21_1 : hardened
{
	meta:
		description = "Detects JSP webshells"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.ic3.gov/Media/News/2021/211117-2.pdf"
		date = "2021-11-23"
		score = 70
		id = "117eed28-c44e-5983-b4c7-b555fc06d923"

	strings:
		$x1 = {72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28 22 70 77 64 22 29}
		$x2 = {65 78 63 75 74 65 43 6d 64 28 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28}
		$x3 = {67 65 74 52 75 6e 74 69 6d 65 28 29 2e 65 78 65 63 20 28 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28}
		$x4 = {70 72 69 76 61 74 65 20 73 74 61 74 69 63 20 66 69 6e 61 6c 20 53 74 72 69 6e 67 20 50 57 20 3d 20 22 77 68 6f 61 6d 69 22}

	condition:
		filesize < 400KB and 1 of them
}

rule EXPL_POC_SpringCore_0day_Indicators_Mar22_1 : hardened
{
	meta:
		description = "Detects indicators found after SpringCore exploitation attempts and in the POC script"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/vxunderground/status/1509170582469943303"
		date = "2022-03-30"
		score = 70
		id = "297e4b57-f831-56e0-a391-1ffbc9a4d438"

	strings:
		$x1 = {6a 61 76 61 2e 69 6f 2e 49 6e 70 75 74 53 74 72 65 61 6d 25 32 30 69 6e 25 32 30 25 33 44 25 32 30 25 32 35 25 37 42 63 31 25 37 44 69}
		$x2 = {3f 70 77 64 3d 6a 26 63 6d 64 3d 77 68 6f 61 6d 69}
		$x3 = {2e 67 65 74 50 61 72 61 6d 65 74 65 72 28 25 32 32 70 77 64 25 32 32 29}
		$x4 = {63 6c 61 73 73 2e 6d 6f 64 75 6c 65 2e 63 6c 61 73 73 4c 6f 61 64 65 72 2e 72 65 73 6f 75 72 63 65 73 2e 63 6f 6e 74 65 78 74 2e 70 61 72 65 6e 74 2e 70 69 70 65 6c 69 6e 65 2e 66 69 72 73 74 2e 70 61 74 74 65 72 6e 3d 25 32 35 25 37 42}

	condition:
		1 of them
}

rule EXPL_POC_SpringCore_0day_Webshell_Mar22_1 : hardened
{
	meta:
		description = "Detects webshell found after SpringCore exploitation attempts POC script"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/vxunderground/status/1509170582469943303"
		date = "2022-03-30"
		score = 70
		id = "e7047c98-3c60-5211-9ad5-2bfdfb35d493"

	strings:
		$x1 = {2e 67 65 74 49 6e 70 75 74 53 74 72 65 61 6d 28 29 3b 20 69 6e 74 20 61 20 3d 20 2d 31 3b 20 62 79 74 65 5b 5d 20 62 20 3d 20 6e 65 77 20 62 79 74 65 5b 32 30 34 38 5d 3b}
		$x2 = {69 66 28 22 6a 22 2e 65 71 75 61 6c 73 28 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28 22 70 77 64 22 29}
		$x3 = {2e 67 65 74 52 75 6e 74 69 6d 65 28 29 2e 65 78 65 63 28 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28 22 63 6d 64 22 29 29 2e 67 65 74 49 6e 70 75 74 53 74 72 65 61 6d 28 29 3b}

	condition:
		filesize < 200KB and 1 of them
}

