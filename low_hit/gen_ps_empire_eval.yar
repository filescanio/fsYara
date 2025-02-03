rule PowerShell_Emp_Eval_Jul17_A1 : hardened
{
	meta:
		description = "Detects suspicious sample with PowerShell content "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "PowerShell Empire Eval"
		date = "2017-07-27"
		hash1 = "4d10e80c7c80ef040efc680424a429558c7d76a965685bbc295908cb71137eba"
		id = "1699f153-f972-5e06-a94b-eb95af637e6b"

	strings:
		$s1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00}
		$s2 = {70 73 68 63 6d 64}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 30KB and all of them )
}

rule PowerShell_Emp_Eval_Jul17_A2 : hardened
{
	meta:
		description = "Detects suspicious sample with PowerShell content "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "PowerShell Empire Eval"
		date = "2017-07-27"
		hash1 = "e14c139159c23fdc18969afe57ec062e4d3c28dd42a20bed8ddde37ab4351a51"
		id = "8f299fcd-156c-5ce1-8582-c2a4ff2c0cfc"

	strings:
		$x1 = {5c 73 75 70 70 6f 72 74 5c 52 65 6c 65 61 73 65 5c 61 62 2e 70 64 62}
		$s2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

