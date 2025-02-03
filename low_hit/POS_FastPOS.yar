rule PoS_Malware_fastpos : FastPOS POS keylogger hardened limited
{
	meta:
		author = "Trend Micro, Inc."
		date = "2016-05-18"
		description = "Used to detect FastPOS keyloggger + scraper"
		reference = "http://documents.trendmicro.com/assets/fastPOS-quick-and-easy-credit-card-theft.pdf"
		sample_filetype = "exe"

	strings:
		$string1 = {75 6e 69 71 79 65 69 64 63 6c 61 78 65 6d 61 69 6e}
		$string2 = {68 74 74 70 3a 2f 2f 25 73 2f 63 64 6f 73 79 73 2e 70 68 70}
		$string3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e}
		$string4 = {5c 54 68 65 20 48 6f 6f 6b 5c 52 65 6c 65 61 73 65 5c 54 68 65 20 48 6f 6f 6b 2e 70 64 62}

	condition:
		all of ( $string* )
}

