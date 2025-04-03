rule MAL_Go_Modbus_Jul24_1 : hardened limited
{
	meta:
		description = "Detects characteristics reported by Dragos for FrostyGoop ICS malware"
		author = "Florian Roth"
		reference = "https://hub.dragos.com/hubfs/Reports/Dragos-FrostyGoop-ICS-Malware-Intel-Brief-0724_.pdf"
		date = "2024-07-23"
		modified = "2024-07-24"
		score = 75
		hash1 = "5d2e4fd08f81e3b2eb2f3eaae16eb32ae02e760afc36fa17f4649322f6da53fb"

	strings:
		$a1 = {47 6f 20 62 75 69 6c 64}
		$sa1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 72 6f 6c 66 6c 2f 6d 6f 64 62 75 73}
		$sb1 = {6d 61 69 6e 2e 54 61 73 6b 4c 69 73 74 2e 65 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64}
		$sb2 = {6d 61 69 6e 2e 54 61 72 67 65 74 4c 69 73 74 2e 67 65 74 54 61 72 67 65 74 49 70 4c 69 73 74}
		$sb3 = {6d 61 69 6e 2e 54 61 73 6b 4c 69 73 74 2e 67 65 74 54 61 73 6b 49 70 4c 69 73 74}
		$sb4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6d 61 69 6e 2e 43 79 63 6c 65 49 6e 66 6f (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		filesize < 30MB and ( $sa1 and 3 of ( $sb* ) ) or 4 of them
}

