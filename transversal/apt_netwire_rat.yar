rule Susp_Indicators_EXE : hardened
{
	meta:
		description = "Detects packed NullSoft Inst EXE with characteristics of NetWire RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://pastebin.com/8qaiyPxs"
		date = "2018-01-05"
		score = 60
		hash1 = "6de7f0276afa633044c375c5c630740af51e29b6a6f17a64fbdd227c641727a4"
		id = "b4015c24-d18e-51eb-9854-8cc0e6dba4d0"

	strings:
		$s1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e}
		$s2 = {45 72 72 6f 72 21 20 42 61 64 20 74 6f 6b 65 6e 20 6f 72 20 69 6e 74 65 72 6e 61 6c 20 65 72 72 6f 72}
		$s3 = {43 52 59 50 54 42 41 53 45}
		$s4 = {55 58 54 48 45 4d 45}
		$s5 = {50 52 4f 50 53 59 53}
		$s6 = {41 50 50 48 45 4c 50}

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3c ) ) == 0x4550 and filesize < 700KB and all of them
}

rule Suspicious_BAT_Strings : hardened
{
	meta:
		description = "Detects a string also used in Netwire RAT auxilliary"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 60
		reference = "https://pastebin.com/8qaiyPxs"
		date = "2018-01-05"
		id = "5fe28555-96c8-54da-b047-7d0a7532a6d2"

	strings:
		$s1 = {70 69 6e 67 20 31 39 32 2e 30 2e 32 2e 32 20 2d 6e 20 31}

	condition:
		filesize < 600KB and 1 of them
}

rule Malicious_BAT_Strings : hardened
{
	meta:
		description = "Detects a string also used in Netwire RAT auxilliary"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 60
		reference = "https://pastebin.com/8qaiyPxs"
		date = "2018-01-05"
		id = "6e197d05-62eb-535d-8cd6-db8550e51588"

	strings:
		$s1 = {63 61 6c 6c 20 3a 64 65 6c 65 74 65 53 65 6c 66 26 65 78 69 74 20 2f 62}

	condition:
		filesize < 600KB and 1 of them
}

