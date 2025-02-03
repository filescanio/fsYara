rule LOG_EXPL_Confluence_RCE_CVE_2021_26084_Sep21 : LOG hardened
{
	meta:
		description = "Detects exploitation attempts against Confluence servers abusing a RCE reported as CVE-2021-26084"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/httpvoid/writeups/blob/main/Confluence-RCE.md"
		date = "2021-09-01"
		score = 55
		id = "bbf98ce4-d32b-541a-b727-bc35c9aaef53"

	strings:
		$xr1 = /isSafeExpression Unsafe clause found in \['[^\n]{1,64}\\u0027/ ascii wide
		$xs1 = {5b 75 74 69 6c 2e 76 65 6c 6f 63 69 74 79 2e 64 65 62 75 67 2e 44 65 62 75 67 52 65 66 65 72 65 6e 63 65 49 6e 73 65 72 74 69 6f 6e 45 76 65 6e 74 48 61 6e 64 6c 65 72 5d 20 72 65 66 65 72 65 6e 63 65 49 6e 73 65 72 74 20 72 65 73 6f 6c 76 69 6e 67 20 72 65 66 65 72 65 6e 63 65 20 5b 24 21 71 75 65 72 79 53 74 72 69 6e 67 5d}
		$xs2 = {75 73 65 72 4e 61 6d 65 3a 20 61 6e 6f 6e 79 6d 6f 75 73 20 7c 20 61 63 74 69 6f 6e 3a 20 63 72 65 61 74 65 70 61 67 65 2d 65 6e 74 65 72 76 61 72 69 61 62 6c 65 73 20 6f 67 6e 6c 2e 45 78 70 72 65 73 73 69 6f 6e 53 79 6e 74 61 78 45 78 63 65 70 74 69 6f 6e 3a 20 4d 61 6c 66 6f 72 6d 65 64 20 4f 47 4e 4c 20 65 78 70 72 65 73 73 69 6f 6e 3a 20 27 5c 27 20 5b 6f 67 6e 6c 2e 54 6f 6b 65 6e 4d 67 72 45 72 72 6f 72 3a 20 4c 65 78 69 63 61 6c 20 65 72 72 6f 72 20 61 74 20 6c 69 6e 65 20 31}
		$sa1 = {47 45 54 20 2f 70 61 67 65 73 2f 64 6f 65 6e 74 65 72 70 61 67 65 76 61 72 69 61 62 6c 65 73 2e 61 63 74 69 6f 6e}
		$sb1 = {25 35 63 25 37 35 25 33 30 25 33 30 25 33 32 25 33 37}
		$sb2 = {5c 75 30 30 32 37}
		$sc1 = {20 45 52 52 4f 52 20}
		$sc2 = {20 7c 20 75 73 65 72 4e 61 6d 65 3a 20 61 6e 6f 6e 79 6d 6f 75 73 20 7c 20 61 63 74 69 6f 6e 3a 20 63 72 65 61 74 65 70 61 67 65 2d 65 6e 74 65 72 76 61 72 69 61 62 6c 65 73}
		$re1 = /\[confluence\.plugins\.synchrony\.SynchronyContextProvider\] getContextMap (\n )?-- url: \/pages\/createpage-entervariables\.action/

	condition:
		1 of ( $x* ) or ( $sa1 and 1 of ( $sb* ) ) or ( all of ( $sc* ) and $re1 )
}

