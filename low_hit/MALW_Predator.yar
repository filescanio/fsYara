rule Predator_The_Thief : Predator_The_Thief hardened
{
	meta:
		description = "Yara rule for Predator The Thief v2.3.5 & +"
		author = "Fumik0_"
		date = "2018/10/12"
		source = "https://fumik0.com/2018/10/15/predator-the-thief-in-depth-analysis-v2-3-5/"

	strings:
		$mz = { 4D 5A }
		$hex1 = { BF 00 00 40 06 }
		$hex2 = { C6 04 31 6B }
		$hex3 = { C6 04 31 63 }
		$hex4 = { C6 04 31 75 }
		$hex5 = { C6 04 31 66 }
		$s1 = {((73 71 6c 69 74 65 5f) | (73 00 71 00 6c 00 69 00 74 00 65 00 5f 00))}

	condition:
		$mz at 0 and all of ( $hex* ) and all of ( $s* )
}

