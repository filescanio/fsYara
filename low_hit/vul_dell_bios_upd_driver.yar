rule VULN_Dell_BIOS_Update_Driver_DBUtil_May21 : hardened limited
{
	meta:
		description = "Detects vulnerable DELL BIOS update driver that allows privilege escalation as reported in CVE-2021-21551 - DBUtil_2_3.Sys - note: it's usual location is in the C:\\Windows\\Temp folder"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://labs.sentinelone.com/cve-2021-21551-hundreds-of-millions-of-dell-computers-at-risk-due-to-multiple-bios-driver-privilege-escalation-flaws/"
		date = "2021-05-05"
		score = 60
		hash1 = "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5"
		hash2 = "ddbf5ecca5c8086afde1fb4f551e9e6400e94f4428fe7fb5559da5cffa654cc1"
		id = "6d46866e-40fb-5fbf-b159-6bf688e638cb"

	strings:
		$s1 = {5c 44 42 55 74 69 6c 44 72 76 32}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 44 42 55 74 69 6c 5f 32 5f 33 2e 53 79 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5b 20 44 65 6c 6c 20 42 49 4f 53 20 55 74 69 6c 69 74 79 20 44 72 69 76 65 72 20 2d 20 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 50KB and all of them
}

