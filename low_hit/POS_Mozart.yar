rule Mozart : hardened limited
{
	meta:
		author = "Nick Hoffman - Morphick Inc"
		description = "Detects samples of the Mozart POS RAM scraping utility"
		reference = "http://securitykitten.github.io/the-mozart-ram-scraper/"

	strings:
		$pdb = {((7a 3a 5c 53 6c 65 6e 64 65 72 5c 6d 6f 7a 61 72 74 5c 6d 6f 7a 61 72 74 5c 52 65 6c 65 61 73 65 5c 6d 6f 7a 61 72 74 2e 70 64 62) | (7a 00 3a 00 5c 00 53 00 6c 00 65 00 6e 00 64 00 65 00 72 00 5c 00 6d 00 6f 00 7a 00 61 00 72 00 74 00 5c 00 6d 00 6f 00 7a 00 61 00 72 00 74 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 6d 00 6f 00 7a 00 61 00 72 00 74 00 2e 00 70 00 64 00 62 00))}
		$output = {67 61 72 62 61 67 65 2E 74 6D 70 00}
		$service_name = {((4e 43 52 20 53 65 6c 66 53 65 72 76 20 50 6c 61 74 66 6f 72 6d 20 52 65 6d 6f 74 65 20 4d 6f 6e 69 74 6f 72) | (4e 00 43 00 52 00 20 00 53 00 65 00 6c 00 66 00 53 00 65 00 72 00 76 00 20 00 50 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 20 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00))}
		$service_name_short = {4e 43 52 5f 52 65 6d 6f 74 65 4d 6f 6e 69 74 6f 72}
		$encode_data = {B8 08 10 00 00 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 53 55 8B AC 24 14 10 00 00 89 84 24 0C 10 00 00 56 8B C5 33 F6 33 DB 8D 50 01 8D A4 24 00 00 00 00 8A 08 40 84 C9 ?? ?? 2B C2 89 44 24 0C ?? ?? 8B 94 24 1C 10 00 00 57 8B FD 2B FA 89 7C 24 10 ?? ?? 8B 7C 24 10 8A 04 17 02 86 E0 BA 40 00 88 02 B8 ?? ?? ?? ?? 46 8D 78 01 8D A4 24 00 00 00 00 8A 08 40 84 C9 ?? ?? 2B C7 3B F0 ?? ?? 33 F6 8B C5 43 42 8D 78 01 8A 08 40 84 C9 ?? ?? 2B C7 3B D8 ?? ?? 5F 8B B4 24 1C 10 00 00 8B C5 C6 04 33 00 8D 50 01 8A 08 40 84 C9 ?? ?? 8B 8C 24 20 10 00 00 2B C2 51 8D 54 24 14 52 50 56 E8 ?? ?? ?? ?? 83 C4 10 8B D6 5E 8D 44 24 0C 8B C8 5D 2B D1 5B 8A 08 88 0C 02 40 84 C9 ?? ?? 8B 8C 24 04 10 00 00 E8 ?? ?? ?? ?? 81 C4 08 10 00 00}

	condition:
		any of ( $pdb , $output , $encode_data ) or all of ( $service* )
}

