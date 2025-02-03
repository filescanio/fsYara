rule MyWScript_CompiledScript : hardened
{
	meta:
		description = "Detects a scripte with default name Mywscript compiled with Script2Exe (can also be a McAfee tool https://community.mcafee.com/docs/DOC-4124)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-07-27"
		score = 65
		hash1 = "515f5188ba6d039b8c38f60d3d868fa9c9726e144f593066490c7c97bf5090c8"
		id = "a0480a8a-5a7e-5829-851b-7301cfc9da60"

	strings:
		$x1 = {43 3a 5c 50 72 6f 6a 65 74 73 5c 76 62 73 65 64 69 74 5f 73 6f 75 72 63 65 5c 73 63 72 69 70 74 32 65 78 65 5c 52 65 6c 65 61 73 65 5c 6d 79 77 73 63 72 69 70 74 2e 70 64 62}
		$s1 = {6d 00 79 00 77 00 73 00 63 00 72 00 69 00 70 00 74 00 32 00}
		$s2 = {4d 00 59 00 57 00 53 00 43 00 52 00 49 00 50 00 54 00 32 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 800KB and ( $x1 or 2 of them )
}

