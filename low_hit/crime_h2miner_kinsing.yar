rule crime_h2miner_kinsing : hardened
{
	meta:
		description = "Rule to find Kinsing malware"
		author = "Tony Lambert, Red Canary"
		date = "2020-06-09"
		id = "1cabca0d-7134-517e-b82e-f2b20b4d1c34"

	strings:
		$s1 = {2d 69 4c 20 24 49 4e 50 55 54 20 2d 2d 72 61 74 65 20 24 52 41 54 45 20 2d 70 24 50 4f 52 54 20 2d 6f 4c 20 24 4f 55 54 50 55 54}
		$s2 = {6c 69 62 70 63 61 70}
		$s3 = {6d 61 69 6e 2e 62 61 63 6b 63 6f 6e 6e 65 63 74}
		$s4 = {6d 61 69 6e 2e 6d 61 73 73 63 61 6e}
		$s5 = {6d 61 69 6e 2e 63 68 65 63 6b 48 65 61 6c 74 68}
		$s6 = {6d 61 69 6e 2e 72 65 64 69 73 42 72 75 74 65}
		$s7 = {41 63 74 69 76 65 43 32 43 55 72 6c}
		$s8 = {6d 61 69 6e 2e 52 43 34}
		$s9 = {6d 61 69 6e 2e 72 75 6e 54 61 73 6b}

	condition:
		( uint32( 0 ) == 0x464C457F ) and filesize > 1MB and all of them
}

