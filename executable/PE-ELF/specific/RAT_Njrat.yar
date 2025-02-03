rule network_traffic_njRAT : hardened
{
	meta:
		author = "info@fidelissecurity.com"
		descripion = "njRAT - Remote Access Trojan"
		comment = "Rule to alert on network traffic indicators"
		filetype = "PCAP - Network Traffic"
		date = "2013-07-15"
		version = "1.0"
		hash1 = "92ee1fb5df21d8cfafa2b02b6a25bd3b"
		hash2 = "3576d40ce18bb0349f9dfa42b8911c3a"
		hash3 = "24cc5b811a7f9591e7f2cb9a818be104"
		hash4 = "3ad5fded9d7fdf1c2f6102f4874b2d52"
		hash5 = "a98b4c99f64315aac9dd992593830f35"
		hash6 = "5fcb5282da1a2a0f053051c8da1686ef"
		hash7 = "a669c0da6309a930af16381b18ba2f9d"
		hash8 = "79dce17498e1997264346b162b09bde8"
		hash9 = "fc96a7e27b1d3dab715b2732d5c86f80"
		ref1 = "http://bit.ly/19tlf4s"
		ref2 = "http://www.fidelissecurity.com/threatadvisory"
		ref3 = "http://www.threatgeek.com/2013/06/fidelis-threat-advisory-1009-njrat-uncovered.html"
		ref4 = "http://threatgeek.typepad.com/files/fta-1009---njrat-uncovered.pdf"

	strings:
		$string1 = {46 4d 7c 27 7c 27 7c}
		$string2 = {6e 64 7c 27 7c 27 7c}
		$string3 = {72 6e 7c 27 7c 27 7c}
		$string4 = {73 63 7e 7c 27 7c 27 7c}
		$string5 = {73 63 50 4b 7c 27 7c 27 7c}
		$string6 = {43 41 4d 7c 27 7c 27 7c}
		$string7 = {55 53 42 20 56 69 64 65 6f 20 44 65 76 69 63 65 5b 65 6e 64 6f 66 5d}
		$string8 = {72 73 7c 27 7c 27 7c}
		$string9 = {70 72 6f 63 7c 27 7c 27 7c}
		$string10 = {6b 7c 27 7c 27 7c}
		$string11 = {52 47 7c 27 7c 27 7c 7e 7c 27 7c 27 7c}
		$string12 = {6b 6c 7c 27 7c 27 7c}
		$string13 = {72 65 74 7c 27 7c 27 7c}
		$string14 = {70 6c 7c 27 7c 27 7c}
		$string15 = {6c 76 7c 27 7c 27 7c}
		$string16 = {70 72 6f 66 7c 27 7c 27 7c 7e 7c 27 7c 27 7c}
		$string17 = {75 6e 7c 27 7c 27 7c 7e 5b 65 6e 64 6f 66 5d}
		$idle_string = {50 5b 65 6e 64 6f 66 5d}

	condition:
		any of ( $string* ) or #idle_string > 4
}

