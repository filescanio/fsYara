rule HawkEye_Keylogger_Feb18_1 : hardened
{
	meta:
		description = "Semiautomatically generated YARA rule"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://app.any.run/tasks/ae2521dd-61aa-4bc7-b0d8-8c85ddcbfcc9"
		date = "2018-02-12"
		modified = "2023-01-06"
		score = 90
		hash1 = "bb58922ad8d4a638e9d26076183de27fb39ace68aa7f73adc0da513ab66dc6fa"
		id = "6b4b447f-43d6-5774-a1b9-d53b40364732"

	strings:
		$s1 = {55 00 70 00 6c 00 6f 00 61 00 64 00 52 00 65 00 70 00 6f 00 72 00 74 00 4c 00 6f 00 67 00 69 00 6e 00 2e 00 61 00 73 00 6d 00 78 00}
		$s2 = {74 00 6d 00 70 00 2e 00 65 00 78 00 65 00}
		$s3 = {25 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and all of them
}

rule MAL_HawkEye_Keylogger_Gen_Dec18 : hardened
{
	meta:
		description = "Detects HawkEye Keylogger Reborn"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/James_inthe_box/status/1072116224652324870"
		date = "2018-12-10"
		hash1 = "b8693e015660d7bd791356b352789b43bf932793457d54beae351cf7a3de4dad"
		id = "1d06f364-a4e2-5632-ad3a-d53a8cddf072"

	strings:
		$s1 = {48 00 61 00 77 00 6b 00 45 00 79 00 65 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00}
		$s2 = {5f 53 63 72 65 65 6e 73 68 6f 74 4c 6f 67 67 65 72}
		$s3 = {5f 50 61 73 73 77 6f 72 64 53 74 65 61 6c 65 72}

	condition:
		2 of them
}

