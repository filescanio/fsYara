rule DYNOWIPER : hardened
{
	meta:
		author = "CERT Polska"
		description = "Detects DYNOWIPER data destruction malware"
		severity = "CRITICAL"
		reference = "https://mwdb.cert.pl/"

	strings:
		$a1 = {24 00 72 00 65 00 63 00 79 00 63 00 6c 00 65 00 2e 00 62 00 69 00 6e 00}
		$a2 = {70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 66 00 69 00 6c 00 65 00 73 00 28 00 78 00 38 00 36 00 29 00}
		$a3 = {70 00 65 00 72 00 66 00 6c 00 6f 00 67 00 73 00}
		$a4 = {77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 00 00}
		$b1 = {45 00 72 00 72 00 6f 00 72 00 20 00 6f 00 70 00 65 00 6e 00 69 00 6e 00 67 00 20 00 66 00 69 00 6c 00 65 00 3a 00 20 00}
		$priv = {53 00 65 00 53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00}
		$api1 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73}
		$api2 = {45 78 69 74 57 69 6e 64 6f 77 73 45 78}
		$api3 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73}

	condition:
		uint16( 0 ) == 0x5A4D and filesize < 500KB and 4 of ( $a* , $b1 ) and $priv and 2 of ( $api* )
}

