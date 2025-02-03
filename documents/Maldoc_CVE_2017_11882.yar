rule Maldoc_CVE_2017_11882 : Exploit refined hardened
{
	meta:
		description = "Detects maldoc With exploit for CVE_2017_11882"
		author = "Marc Salinas (@Bondey_m)"
		reference = "c63ccc5c08c3863d7eb330b69f96c1bcf1e031201721754132a4c4d0baff36f8"
		date = "2017-10-20"
		score = 75

	strings:
		$doc = {64 30 63 66 31 31 65 30 61 31 62 31 31 61 65 31}
		$s0 = {45 71 75 61 74 69 6f 6e}
		$s1 = {31 63 30 30 30 30 30 30 30 32 30}
		$h0 = {1C 00 00 00 02 00}

	condition:
		( uint32be( 0 ) == 0x7B5C7274 or $doc at 0 ) and $s0 and ( $h0 or $s1 )
}

