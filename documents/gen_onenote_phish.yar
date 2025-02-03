rule SUSP_Email_Suspicious_OneNote_Attachment_Jan23_1 : hardened
{
	meta:
		description = "Detects suspicious OneNote attachment that embeds suspicious payload, e.g. an executable (FPs possible if the PE is attached separately)"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2023-01-27"
		score = 65
		id = "492b74c2-3b81-5dff-9244-8528565338c6"

	strings:
		$ge1 = {35 78 62 6a 76 57 55 6d 45 55 57 6b 78 49 31 4e 43 33 71 65 72}
		$ge2 = {63 57 34 37 31 6c 4a 68 46 46 70 4d 53 4e 54 51 74 36 6e 71}
		$ge3 = {6e 46 75 4f 39 5a 53 59 52 52 61 54 45 6a 55 30 4c 65 70 36 73}
		$sp1 = {56 47 68 70 63 79 42 77 63 6d 39 6e 63 6d 46 74 49 47 4e 68 62 6d 35 76 64 43 42 69 5a 53 42 79 64 57 34 67 61 57 34 67 52 45 39 54 49 47 31 76 5a 47}
		$sp2 = {52 6f 61 58 4d 67 63 48 4a 76 5a 33 4a 68 62 53 42 6a 59 57 35 75 62 33 51 67 59 6d 55 67 63 6e 56 75 49 47 6c 75 49 45 52 50 55 79 42 74 62 32 52 6c}
		$sp3 = {55 61 47 6c 7a 49 48 42 79 62 32 64 79 59 57 30 67 59 32 46 75 62 6d 39 30 49 47 4a 6c 49 48 4a 31 62 69 42 70 62 69 42 45 54 31 4d 67 62 57 39 6b 5a}
		$sp4 = {56 47 68 70 63 79 42 77 63 6d 39 6e 63 6d 46 74 49 47 31 31 63 33 51 67 59 6d 55 67 63 6e 56 75 49 48 56 75 5a 47 56 79}
		$sp5 = {52 6f 61 58 4d 67 63 48 4a 76 5a 33 4a 68 62 53 42 74 64 58 4e 30 49 47 4a 6c 49 48 4a 31 62 69 42 31 62 6d 52 6c 63}
		$sp6 = {55 61 47 6c 7a 49 48 42 79 62 32 64 79 59 57 30 67 62 58 56 7a 64 43 42 69 5a 53 42 79 64 57 34 67 64 57 35 6b 5a 58}
		$se1 = {51 47 56 6a 61 47 38 67 62 32 5a 6d}
		$se2 = {42 6c 59 32 68 76 49 47 39 6d 5a}
		$se3 = {41 5a 57 4e 6f 62 79 42 76 5a 6d}
		$se4 = {50 45 68 55 51 54 70 42 55 46 42 4d 53 55 4e 42 56 45 6c 50 54 69}
		$se5 = {78 49 56 45 45 36 51 56 42 51 54 45 6c 44 51 56 52 4a 54 30 34 67}
		$se6 = {38 53 46 52 42 4f 6b 46 51 55 45 78 4a 51 30 46 55 53 55 39 4f 49}
		$se7 = {54 41 41 41 41 41 45 55 41 67}
		$se8 = {77 41 41 41 41 42 46 41 49 41}
		$se9 = {4d 41 41 41 41 41 52 51 43 41}

	condition:
		filesize < 5MB and 1 of ( $ge* ) and 1 of ( $s* )
}

rule SUSP_Email_Suspicious_OneNote_Attachment_Jan23_2 : hardened limited
{
	meta:
		description = "Detects suspicious OneNote attachment that has a file name often used in phishing attacks"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2023-01-27"
		score = 65
		id = "f8c58c73-2404-5ce6-8e8f-99b0dad84ad0"

	strings:
		$hc1 = { 2E 6F 6E 65 22 0D 0A 0D 0A 35 46 4A 63 65 }
		$x01 = {20 61 74 74 61 63 68 6d 65 6e 74 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 49 6e 76 6f 69 63 65}
		$x02 = {20 61 74 74 61 63 68 6d 65 6e 74 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 4f 52 44 45 52}
		$x03 = {20 61 74 74 61 63 68 6d 65 6e 74 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 50 55 52 43 48 41 53 45}
		$x04 = {20 61 74 74 61 63 68 6d 65 6e 74 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 53 48 49 50}

	condition:
		filesize < 5MB and $hc1 and 1 of ( $x* )
}

rule SUSP_OneNote_Embedded_FileDataStoreObject_Type_Jan23_1 : hardened
{
	meta:
		description = "Detects suspicious embedded file types in OneNote files"
		author = "Florian Roth"
		reference = "https://blog.didierstevens.com/"
		date = "2023-01-27"
		modified = "2023-02-27"
		score = 65
		id = "b8ea8c7b-052f-5a97-9577-99903462ea84"

	strings:
		$x1 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? 4d 5a }
		$x2 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 40 65 63 68 6f }
		$x3 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 40 45 43 48 4f }
		$x4 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 4F 6E 20 45 }
		$x5 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 6F 6E 20 65 }
		$x6 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? 4c 00 00 00 }
		$x7 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? 49 54 53 46 }
		$x8 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [6-200] 3C 68 74 61 3A }
		$x9 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [6-200] 3C 48 54 41 3A }
		$x10 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [6-200] 3C 6A 6F 62 20 }

	condition:
		filesize < 10MB and 1 of them
}

rule SUSP_OneNote_Embedded_FileDataStoreObject_Type_Jan23_2 : hardened
{
	meta:
		description = "Detects suspicious embedded file types in OneNote files"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.didierstevens.com/"
		date = "2023-01-27"
		score = 65
		id = "0664d202-ab4c-57b6-91ee-ea21ac08909e"

	strings:
		$a1 = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }
		$s1 = {3c 48 54 41 3a 41 50 50 4c 49 43 41 54 49 4f 4e 20}

	condition:
		filesize < 5MB and $a1 and 1 of ( $s* )
}

