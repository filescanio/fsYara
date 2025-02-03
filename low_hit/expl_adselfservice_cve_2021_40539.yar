rule LOG_EXPL_ADSelfService_CVE_2021_40539_ADSLOG_Sep21 : LOG hardened
{
	meta:
		description = "Detects suspicious log lines produeced during the exploitation of ADSelfService vulnerability CVE-2021-40539"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://us-cert.cisa.gov/ncas/alerts/aa21-259a"
		date = "2021-09-20"
		score = 70
		id = "156317c6-e726-506d-8b07-4f74dae2807f"

	strings:
		$x1 = {((4a 61 76 61 20 74 72 61 63 65 62 61 63 6b 20 65 72 72 6f 72 73 20 74 68 61 74 20 69 6e 63 6c 75 64 65 20 72 65 66 65 72 65 6e 63 65 73 20 74 6f 20 4e 75 6c 6c 50 6f 69 6e 74 65 72 45 78 63 65 70 74 69 6f 6e 20 69 6e 20 61 64 64 53 6d 61 72 74 43 61 72 64 43 6f 6e 66 69 67 20 6f 72 20 67 65 74 53 6d 61 72 74 43 61 72 64 43 6f 6e 66 69 67) | (4a 00 61 00 76 00 61 00 20 00 74 00 72 00 61 00 63 00 65 00 62 00 61 00 63 00 6b 00 20 00 65 00 72 00 72 00 6f 00 72 00 73 00 20 00 74 00 68 00 61 00 74 00 20 00 69 00 6e 00 63 00 6c 00 75 00 64 00 65 00 20 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 73 00 20 00 74 00 6f 00 20 00 4e 00 75 00 6c 00 6c 00 50 00 6f 00 69 00 6e 00 74 00 65 00 72 00 45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 20 00 69 00 6e 00 20 00 61 00 64 00 64 00 53 00 6d 00 61 00 72 00 74 00 43 00 61 00 72 00 64 00 43 00 6f 00 6e 00 66 00 69 00 67 00 20 00 6f 00 72 00 20 00 67 00 65 00 74 00 53 00 6d 00 61 00 72 00 74 00 43 00 61 00 72 00 64 00 43 00 6f 00 6e 00 66 00 69 00 67 00))}

	condition:
		filesize < 50MB and 1 of them
}

rule LOG_EXPL_ADSelfService_CVE_2021_40539_WebLog_Sep21_1 : LOG hardened
{
	meta:
		description = "Detects suspicious log lines produeced during the exploitation of ADSelfService vulnerability CVE-2021-40539"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://us-cert.cisa.gov/ncas/alerts/aa21-259a"
		date = "2021-09-20"
		score = 60
		id = "015957a6-8778-5836-af94-6e6d3838f693"

	strings:
		$x1 = {((2f 53 65 72 76 6c 65 74 41 70 69 2f 2e 2e 2f 52 65 73 74 41 70 69 2f 4c 6f 67 6f 6e 43 75 73 74 6f 6d 69 7a 61 74 69 6f 6e) | (2f 00 53 00 65 00 72 00 76 00 6c 00 65 00 74 00 41 00 70 00 69 00 2f 00 2e 00 2e 00 2f 00 52 00 65 00 73 00 74 00 41 00 70 00 69 00 2f 00 4c 00 6f 00 67 00 6f 00 6e 00 43 00 75 00 73 00 74 00 6f 00 6d 00 69 00 7a 00 61 00 74 00 69 00 6f 00 6e 00))}
		$x2 = {((2f 53 65 72 76 6c 65 74 41 70 69 2f 2e 2e 2f 52 65 73 74 41 50 49 2f 43 6f 6e 6e 65 63 74 69 6f 6e) | (2f 00 53 00 65 00 72 00 76 00 6c 00 65 00 74 00 41 00 70 00 69 00 2f 00 2e 00 2e 00 2f 00 52 00 65 00 73 00 74 00 41 00 50 00 49 00 2f 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00))}

	condition:
		filesize < 50MB and 1 of them
}

