rule MAL_RANSOM_RobinHood_May19_1 : hardened limited
{
	meta:
		description = "Detects RobinHood Ransomware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/BThurstonCPTECH/status/1128489465327030277"
		date = "2019-05-15"
		hash1 = "21cb84fc7b33e8e31364ff0e58b078db8f47494a239dc3ccbea8017ff60807e3"
		id = "7199c0de-c925-5399-8fa6-852604190a21"

	strings:
		$s1 = {2e 65 6e 63 5f 72 6f 62 62 69 6e 68 6f 6f 64}
		$s2 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c 70 75 62 2e 6b 65 79}
		$s3 = {63 6d 64 2e 65 78 65 20 2f 63 20 6e 65 74 20 75 73 65 20 2a 20 2f 44 45 4c 45 54 45 20 2f 59}
		$s4 = {73 63 2e 65 78 65 20 73 74 6f 70 20 53 51 4c 41 67 65 6e 74 24 53 51 4c 45 58 50 52 45 53 53}
		$s5 = {6d 61 69 6e 2e 45 6e 61 62 6c 65 53 68 61 64 6f 77 46 75 63 6b 73}
		$s6 = {6d 61 69 6e 2e 45 6e 61 62 6c 65 52 65 63 6f 76 65 72 79 46 43 4b}
		$s7 = {6d 61 69 6e 2e 45 6e 61 62 6c 65 4c 6f 67 4c 61 75 6e 64 65 72 73}
		$s8 = {6d 61 69 6e 2e 45 6e 61 62 6c 65 53 65 72 76 69 63 65 46 75 63 6b}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 8000KB and 1 of them
}

