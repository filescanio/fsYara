rule Generic_Dropper : hardened
{
	meta:
		description = "Detects Dropper PDB string in file"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/JAHZVL"
		date = "2018-03-03"
		id = "60ce6a5c-2e12-515b-b8cb-8c87500cb37b"

	strings:
		$s1 = {5c 52 65 6c 65 61 73 65 5c 44 72 6f 70 70 65 72 2e 70 64 62}
		$s2 = {5c 52 65 6c 65 61 73 65 5c 64 72 6f 70 70 65 72 2e 70 64 62}
		$s3 = {5c 44 65 62 75 67 5c 44 72 6f 70 70 65 72 2e 70 64 62}
		$s4 = {5c 44 65 62 75 67 5c 64 72 6f 70 70 65 72 2e 70 64 62}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 900KB and 1 of them
}

