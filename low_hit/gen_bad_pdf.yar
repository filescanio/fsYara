rule SUSP_Bad_PDF : hardened
{
	meta:
		description = "Detects PDF that embeds code to steal NTLM hashes"
		author = "Florian Roth (Nextron Systems), Markus Neis"
		reference = "Internal Research"
		date = "2018-05-03"
		hash1 = "d8c502da8a2b8d1c67cb5d61428f273e989424f319cfe805541304bdb7b921a8"
		id = "149cf20c-4cfd-5b07-acc5-06ae25b209b1"

	strings:
		$s1 = {20 20 20 20 20 20 20 20 20 2f 46 20 28 68 74 74 70 2f 2f}
		$s2 = {20 20 20 20 20 20 20 20 2f 46 20 28 5c 5c 5c 5c}
		$s3 = {3c 3c 2f 46 20 28 5c 5c}

	condition:
		( uint32( 0 ) == 0x46445025 or uint32( 0 ) == 0x4450250a ) and 1 of them
}

