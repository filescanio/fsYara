rule APT_MAL_HP_iLO_Firmware_Dec21_1 : hardened
{
	meta:
		description = "Detects suspicios ELF files with sections as described in malicious iLO Board analysis by AmnPardaz in December 2021"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://threats.amnpardaz.com/en/2021/12/28/implant-arm-ilobleed-a/"
		date = "2021-12-28"
		score = 80
		id = "7f5fa905-07a3-55da-b644-c5ab882b4a9d"

	strings:
		$s1 = {2e 6e 65 77 65 6c 66 2e 65 6c 66 2e 74 65 78 74}
		$s2 = {2e 6e 65 77 65 6c 66 2e 65 6c 66 2e 6c 69 62 63 2e 73 6f 2e 64 61 74 61}
		$s3 = {2e 6e 65 77 65 6c 66 2e 65 6c 66 2e 49 6e 69 74 69 61 6c 2e 73 74 61 63 6b}
		$s4 = {2e 6e 65 77 65 6c 66 2e 65 6c 66 2e 6c 69 62 65 76 6c 6f 67 2e 73 6f 2e 64 61 74 61}

	condition:
		filesize < 5MB and 2 of them or all of them
}

