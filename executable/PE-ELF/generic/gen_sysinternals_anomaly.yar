rule SysInternals_Tool_Anomaly : hardened
{
	meta:
		description = "SysInternals Tool Anomaly - does not contain Mark Russinovich as author"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 50
		reference = "Internal Research"
		date = "2016-12-06"
		id = "b676726b-7ecd-52ed-bdec-3d81b7596246"

	strings:
		$s1 = {53 6f 66 74 77 61 72 65 5c 53 79 73 69 6e 74 65 72 6e 61 6c 73 5c 25 73}
		$n1 = {((4d 61 72 6b 20 52 75 73 73 69 6e 6f 76 69 63 68) | (4d 00 61 00 72 00 6b 00 20 00 52 00 75 00 73 00 73 00 69 00 6e 00 6f 00 76 00 69 00 63 00 68 00))}
		$nfp1 = {3c 00 3c 00 3c 00 4f 00 62 00 73 00 6f 00 6c 00 65 00 74 00 65 00 3e 00 3e 00 3e 00}
		$nfp2 = {42 00 47 00 49 00 6e 00 66 00 6f 00 20 00 2d 00 20 00 57 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 20 00 74 00 65 00 78 00 74 00 20 00 63 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 6f 00 72 00}
		$nfp3 = {75 00 73 00 61 00 67 00 65 00 3a 00 20 00 6d 00 6f 00 76 00 65 00 66 00 69 00 6c 00 65 00 20 00 5b 00 73 00 6f 00 75 00 72 00 63 00 65 00 5d 00 20 00 5b 00 64 00 65 00 73 00 74 00 5d 00}
		$nfp4 = {4c 00 6f 00 61 00 64 00 4f 00 72 00 64 00 65 00 72 00 20 00 69 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 63 00 6f 00 70 00 69 00 65 00 64 00}
		$nfp5 = {43 00 61 00 63 00 68 00 65 00 20 00 77 00 6f 00 72 00 6b 00 69 00 6e 00 67 00 20 00 73 00 65 00 74 00 20 00 63 00 6c 00 65 00 61 00 72 00 65 00 64 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and $s1 and not $n1 and not 1 of ( $nfp* ) )
}

