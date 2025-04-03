rule SUSP_CMD_Var_Expansion : hardened loosened limited
{
	meta:
		description = "Detects Office droppers that include a variable expansion string"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/asfakian/status/1044859525675843585"
		date = "2018-09-26"
		score = 60
		id = "3f3ebea0-1d33-513d-b32b-9d87607525e8"

	strings:
		$a1 = {((20 2f 56 3a 4f 4e) | (20 00 2f 00 56 00 3a 00 4f 00 4e 00))}

	condition:
		uint16( 0 ) == 0xcfd0 and filesize < 500KB and $a1
}

