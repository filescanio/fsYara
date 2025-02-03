rule Neuron_common_strings : hardened
{
	meta:
		description = "Rule for detection of Neuron based on commonly used strings"
		author = "NCSC UK"
		hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
		date = "2017/11/23"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		id = "168214d4-7436-531e-9c1f-48ca22215a1b"

	strings:
		$strServiceName = {4d 53 45 78 63 68 61 6e 67 65 53 65 72 76 69 63 65}
		$strReqParameter_1 = {63 00 61 00 64 00 61 00 74 00 61 00 4b 00 65 00 79 00}
		$strReqParameter_3 = {63 00 61 00 64 00 61 00 74 00 61 00}
		$strReqParameter_4 = {63 00 61 00 64 00 61 00 74 00 61 00 53 00 69 00 67 00}
		$strEmbeddedKey = {50 00 46 00 4a 00 54 00 51 00 55 00 74 00 6c 00 65 00 56 00 5a 00 68 00 62 00 48 00 56 00 6c 00 50 00 6a 00 78 00 4e 00 62 00 32 00 52 00 31 00 62 00 48 00 56 00 7a 00 50 00 6e 00 5a 00 33 00 57 00 58 00 52 00 4b 00 63 00 6e 00 4e 00 52 00 5a 00 6a 00 56 00 54 00 63 00 43 00 74 00 57 00 56 00 47 00 39 00 52 00 62 00 32 00 78 00 75 00 61 00 45 00 56 00 6b 00 4d 00 48 00 56 00 77 00 57 00 44 00 46 00 72 00 56 00 45 00 6c 00 46 00 54 00 55 00 4e 00 54 00 4e 00 45 00 46 00 6e 00 52 00 6b 00 52 00 43 00 63 00 6c 00 4e 00 6d 00 20 00 63 00 6c 00 70 00 4b 00 53 00 30 00 6f 00 77 00 4e 00 33 00 42 00 59 00 59 00 6a 00 68 00 32 00 62 00 32 00 46 00 78 00 64 00 55 00 74 00 73 00 65 00 58 00 46 00 32 00 52 00 7a 00 42 00 4a 00 63 00 48 00 56 00 30 00 59 00 58 00 68 00 44 00 4d 00 56 00 52 00 59 00 61 00 7a 00 52 00 6f 00 65 00 46 00 4e 00 72 00 64 00 45 00 70 00 7a 00 62 00 48 00 6c 00 6a 00 55 00 33 00 52 00 46 00 61 00 48 00 42 00 55 00 63 00 31 00 6c 00 34 00 4f 00 56 00 42 00 45 00 63 00 55 00 52 00 61 00 62 00 56 00 56 00 5a 00 56 00 6b 00 6c 00 56 00 62 00 20 00 48 00 6c 00 77 00 53 00 46 00 4e 00 31 00 4b 00 33 00 6c 00 6a 00 57 00 55 00 4a 00 57 00 56 00 46 00 64 00 75 00 62 00 54 00 5a 00 6d 00 4e 00 30 00 4a 00 54 00 4e 00 57 00 31 00 70 00 59 00 6e 00 4d 00 30 00 55 00 57 00 68 00 4d 00 5a 00 45 00 6c 00 52 00 62 00 6e 00 6c 00 31 00 61 00 6a 00 46 00 4d 00 51 00 79 00 74 00 36 00 54 00 55 00 68 00 77 00 5a 00 30 00 78 00 6d 00 64 00 45 00 63 00 32 00 62 00 31 00 64 00 35 00 62 00 30 00 68 00 79 00 64 00 31 00 5a 00 4e 00 61 00 7a 00 30 00 38 00 4c 00 30 00 31 00 76 00 5a 00 48 00 20 00 56 00 73 00 64 00 58 00 4d 00 2b 00 50 00 45 00 56 00 34 00 63 00 47 00 39 00 75 00 5a 00 57 00 35 00 30 00 50 00 6b 00 46 00 52 00 51 00 55 00 49 00 38 00 4c 00 30 00 56 00 34 00 63 00 47 00 39 00 75 00 5a 00 57 00 35 00 30 00 50 00 6a 00 77 00 76 00 55 00 6c 00 4e 00 42 00 53 00 32 00 56 00 35 00 56 00 6d 00 46 00 73 00 64 00 57 00 55 00 2b 00}
		$strDefaultKey = {38 00 64 00 39 00 36 00 33 00 33 00 32 00 35 00 2d 00 30 00 31 00 62 00 38 00 2d 00 34 00 36 00 37 00 31 00 2d 00 38 00 65 00 38 00 32 00 2d 00 64 00 30 00 39 00 30 00 34 00 32 00 37 00 35 00 61 00 62 00 30 00 36 00}
		$strIdentifier = {4d 00 53 00 58 00 45 00 57 00 53 00}
		$strListenEndpoint = {34 00 34 00 33 00 2f 00 65 00 77 00 73 00 2f 00 65 00 78 00 63 00 68 00 61 00 6e 00 67 00 65 00 2f 00}
		$strB64RegKeySubstring = {55 00 30 00 39 00 47 00 56 00 46 00 64 00 42 00 55 00 6b 00 56 00 63 00 54 00 57 00 6c 00 6a 00 63 00 6d 00 39 00 7a 00 62 00 32 00 5a 00 30 00 58 00 45 00 4e 00 79 00 65 00 58 00 42 00 30 00 62 00 32 00 64 00 79 00 59 00 58 00 42 00 6f 00}
		$strName = {6e 65 75 72 6f 6e 5f 73 65 72 76 69 63 65}
		$dotnetMagic = {42 53 4a 42}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and $dotnetMagic and 6 of ( $str* )
}

rule Neuron_standalone_signature : hardened
{
	meta:
		description = "Rule for detection of Neuron based on a standalone signature from .NET metadata"
		author = "NCSC UK"
		hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
		date = "2017/11/23"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		id = "e0be2fe2-32fd-5bdf-bfac-a596264be7ba"

	strings:
		$a = { eb073d151231011234080e12818d1d051281311d1281211d1281211d128121081d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281 }
		$dotnetMagic = {42 53 4a 42}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and all of them
}

rule Nautilus_modified_rc4_loop : hardened
{
	meta:
		description = "Rule for detection of Nautilus based on assembly code for a modified RC4 loop"
		author = "NCSC UK"
		hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
		date = "2017/11/23"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		id = "0c5da057-0f1d-5852-ad75-94bf40c133e4"

	strings:
		$a = {42 0F B6 14 04 41 FF C0 03 D7 0F B6 CA 8A 14 0C 43 32 14 13 41 88 12 49 FF C2 49 FF C9}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and $a
}

rule Nautilus_rc4_key : hardened
{
	meta:
		description = "Rule for detection of Nautilus based on a hardcoded RC4 key"
		author = "NCSC UK"
		hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
		date = "2017/11/23"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		id = "124c8b95-46fb-5cc1-9b10-b10536e1781d"

	strings:
		$key = {31 42 31 34 34 30 44 39 30 46 43 39 42 43 42 34 36 41 39 41 43 39 36 34 33 38 46 45 45 41 38 42}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and $key
}

rule Nautilus_common_strings : hardened
{
	meta:
		description = "Rule for detection of Nautilus based on common plaintext strings"
		author = "NCSC UK"
		hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
		date = "2017/11/23"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		id = "0e3af6ef-1a97-5324-a186-95e6f3d836f4"

	strings:
		$ = {6e 61 75 74 69 6c 75 73 2d 73 65 72 76 69 63 65 2e 64 6c 6c}
		$ = {6f 78 79 67 65 6e 2e 64 6c 6c}
		$ = {63 6f 6e 66 69 67 5f 6c 69 73 74 65 6e 2e 73 79 73 74 65 6d}
		$ = {63 74 78 2e 73 79 73 74 65 6d}
		$ = {33 46 44 41 33 39 39 38 2d 42 45 46 35 2d 34 32 36 44 2d 38 32 44 38 2d 31 41 37 31 46 32 39 41 44 44 43 33}
		$ = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 61 63 68 65 73 5c 7b 25 73 7d 2e 32 2e 76 65 72 30 78 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 2e 64 62}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and 3 of them
}

rule Nautilus_forensic_artificats : hardened
{
	meta:
		description = "Rule for detection of Nautilus related strings"
		author = "NCSC UK / Florian Roth"
		date = "2017/11/23"
		score = 60
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		id = "0c0a24da-4dbc-543a-9ec0-a5b1ec75c889"

	strings:
		$ = {41 70 70 5f 57 65 62 5f 6a 75 76 6a 65 72 66 33 2e 64 6c 6c}
		$ = {41 70 70 5f 57 65 62 5f 76 63 70 6c 72 67 38 71 2e 64 6c 6c}
		$ = {61 72 5f 61 6c 6c 32 2e 74 78 74}
		$ = {61 72 5f 73 61 2e 74 78 74}
		$ = {43 6f 6e 76 65 72 74 2e 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 74 65 6d 70 5b 31 5d 29}
		$ = {44 36 38 67 71 23 35 70 30 28 33 4e 64 73 6b 21}
		$ = {64 63 6f 6d 6e 65 74 73 72 76}
		$ = {45 52 52 4f 52 46 7e 31 2e 41 53 50}
		$ = {69 6e 74 65 6c 6c 69 41 64 6d 69 6e 52 70 63}
		$ = {4a 38 66 73 34 46 34 72 6e 50 37 6e 46 6c 23 66}
		$ = {4d 73 6e 62 2e 65 78 65}
		$ = {6e 61 75 74 69 6c 75 73 2d 73 65 72 76 69 63 65 2e 64 6c 6c}
		$ = {4e 65 75 72 6f 6e 5f 73 65 72 76 69 63 65}
		$ = {6f 77 61 5f 61 72 32 2e 62 61 74}
		$ = {70 61 79 6c 6f 61 64 2e 78 36 34 2e 64 6c 6c 2e 73 79 73 74 65 6d}
		$ = {73 65 72 76 69 63 65 2e 78 36 34 2e 64 6c 6c 2e 73 79 73 74 65 6d}

	condition:
		1 of them
}

rule APT_Neuron2_Loader_Strings : hardened
{
	meta:
		description = "Rule for detection of Neuron2 based on strings within the loader"
		author = "NCSC"
		referer = "https://otx.alienvault.com/pulse/5dad718fa5ec6c21e85c1c66"
		hash = "51616b207fde2ff1360a1364ff58270e0d46cf87a4c0c21b374a834dd9676927"
		id = "eaef4710-1971-55a2-9079-07a9b8bd86eb"

	strings:
		$ = {64 63 6f 6d 5f 61 70 69}
		$ = {68 74 74 70 3a 2f 2f 2a 3a 38 30 2f 4f 57 41 2f 4f 41 42 2f}
		$ = {68 74 74 70 73 3a 2f 2f 2a 3a 34 34 33 2f 4f 57 41 2f 4f 41 42 2f}
		$ = {64 00 63 00 6f 00 6d 00 6e 00 65 00 74 00 73 00 72 00 76 00 2e 00 63 00 70 00 70 00}
		$ = {64 63 6f 6d 6e 65 74 2e 64 6c 6c}
		$ = {44 3a 5c 44 65 76 65 6c 6f 70 5c 73 70 73 5c 6e 65 75 72 6f 6e 32 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 64 63 6f 6d 6e 65 74 2e 70 64 62}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and 2 of them
}

