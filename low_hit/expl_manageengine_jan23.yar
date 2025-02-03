rule EXPL_ManageEngine_CVE_2022_47966_Jan23_1 : hardened
{
	meta:
		description = "Detects indicators of exploitation of ManageEngine vulnerability as described by Horizon3"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.horizon3.ai/manageengine-cve-2022-47966-iocs/"
		date = "2023-01-13"
		score = 75
		id = "07535b9c-8611-5a46-bcd7-f94070de2aea"

	strings:
		$ = {5d 3a 20 63 6f 6d 2e 61 64 76 65 6e 74 6e 65 74 2e 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 2e 73 61 6d 6c 2e 53 61 6d 6c 45 78 63 65 70 74 69 6f 6e 3a 20 53 69 67 6e 61 74 75 72 65 20 76 61 6c 69 64 61 74 69 6f 6e 20 66 61 69 6c 65 64 2e 20 53 41 4d 4c 20 52 65 73 70 6f 6e 73 65 20 72 65 6a 65 63 74 65 64 7c}

	condition:
		1 of them
}

