rule ProjectM_DarkComet_1 : hardened
{
	meta:
		description = "Detects ProjectM Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://researchcenter.paloaltonetworks.com/2016/03/unit42-projectm-link-found-between-pakistani-actor-and-operation-transparent-tribe/"
		date = "2016-03-26"
		modified = "2023-01-27"
		score = 60
		hash = "cc488690ce442e9f98bac651218f4075ca36c355d8cd83f7a9f5230970d24157"
		id = "6de74d73-f9b2-5e7f-b15e-f850425d849c"

	strings:
		$x1 = {44 61 72 6b 4f 5c 5f 32}
		$a1 = {41 56 49 43 41 50 33 32 2e 44 4c 4c}
		$a2 = {49 44 69 73 70 61 74 63 68 34}
		$a3 = {46 4c 4f 4f 44 2f}
		$a4 = {54 3c 2d 2f 48 54 54 50 3a 2f 2f}
		$a5 = {69 6e 66 6f 65 73}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 600KB and 4 of them ) or ( all of them )
}

rule ProjectM_CrimsonDownloader : hardened
{
	meta:
		description = "Detects ProjectM Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://researchcenter.paloaltonetworks.com/2016/03/unit42-projectm-link-found-between-pakistani-actor-and-operation-transparent-tribe/"
		date = "2016-03-26"
		hash = "dc8bd60695070152c94cbeb5f61eca6e4309b8966f1aa9fdc2dd0ab754ad3e4c"
		id = "2e0658c9-a93d-5eef-93a2-eb1ab29acaee"

	strings:
		$x1 = {45 3a 5c 50 72 6f 6a 65 63 74 73 5c 6d 5f 70 72 6f 6a 65 63 74 5c 6d 61 69 6e 5c 6d 6a 20 73 68 6f 61 69 62}
		$s1 = {5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c 73 65 63 75 72 65 5f 73 63 61 6e 2e 70 64 62}
		$s2 = {73 00 65 00 63 00 75 00 72 00 65 00 5f 00 73 00 63 00 61 00 6e 00 2e 00 65 00 78 00 65 00}
		$s3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 7c 00 6d 00 73 00 77 00 61 00 6c 00 6c 00}
		$s4 = {73 00 65 00 63 00 75 00 72 00 65 00 5f 00 73 00 63 00 61 00 6e 00 7c 00 6d 00 73 00 77 00 61 00 6c 00 6c 00}
		$s5 = {5b 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2d 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2d 00 45 00 73 00 73 00 65 00 6e 00 74 00 69 00 61 00 6c 00 73 00 5d 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 400KB and $x1 ) or ( all of them )
}

