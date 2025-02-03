rule MAL_Go_Modbus_Jul24_1 : hardened
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
		$sb4 = {6d 61 69 6e 2e 43 79 63 6c 65 49 6e 66 6f}

	condition:
		filesize < 30MB and ( $sa1 and 3 of ( $sb* ) ) or 4 of them
}

