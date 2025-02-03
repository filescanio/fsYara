rule Office_OLE_DDEAUTO : hardened
{
	meta:
		description = "Detects DDE in MS Office documents"
		author = "NVISO Labs"
		reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
		date = "2017-10-12"
		score = 50
		id = "2ead3cc9-f517-5916-93c9-1393362aa45d"

	strings:
		$a = /\x13\s*DDEAUTO\b[^\x14]+/ nocase

	condition:
		uint32be( 0 ) == 0xD0CF11E0 and $a
}

rule Office_OLE_DDE : hardened
{
	meta:
		description = "Detects DDE in MS Office documents"
		author = "NVISO Labs"
		reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
		date = "2017-10-12"
		score = 50
		id = "2ead3cc9-f517-5916-93c9-1393362aa45d"

	strings:
		$a = /\x13\s*DDE\b[^\x14]+/ nocase
		$r1 = { 52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 }
		$r2 = {41 64 6f 62 65 20 41 52 4d 20 49 6e 73 74 61 6c 6c 65 72}

	condition:
		uint32be( 0 ) == 0xD0CF11E0 and $a and not 1 of ( $r* )
}

