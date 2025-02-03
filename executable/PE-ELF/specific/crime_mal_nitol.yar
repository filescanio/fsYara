import "pe"

rule MAL_Nitol_Malware_Jan19_1 : hardened
{
	meta:
		description = "Detects Nitol Malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/shotgunner101/status/1084602413691166721"
		date = "2019-01-14"
		score = 60
		hash1 = "fe65f6a79528802cb61effc064476f7b48233fb0f245ddb7de5b7cc8bb45362e"
		id = "5b9968a8-31ba-593b-9e01-b69a4e31fe65"

	strings:
		$xc1 = { 00 25 75 20 25 73 00 00 00 30 2E 30 2E 30 2E 30
               00 25 75 20 4D 42 00 00 00 25 64 2A 25 75 25 73
               00 7E 4D 48 7A }
		$xc2 = {47 45 54 20 5e 26 26 25 24 25 24 5e}
		$n1 = {2e 68 74 6d 47 45 54 20}
		$s1 = {55 73 65 72 2d 41 67 65 6e 74 3a 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 25 64 2e 30 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 25 64 2e 30 3b 20 4d 79 49 45 20 33 2e 30 31 29}
		$s2 = {55 73 65 72 2d 41 67 65 6e 74 3a 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 25 64 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 25 64 2e 31 3b 20 53 56 31 29}
		$s3 = {55 73 65 72 2d 41 67 65 6e 74 3a 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 58 31 31 3b 20 55 3b 20 4c 69 6e 75 78 20 69 36 38 36 3b 20 65 6e 2d 55 53 3b 20 72 65 3a 31 2e 34 2e 30 29 20 47 65 63 6b 6f 2f 32 30 30 38 30 38 30 38 20 46 69 72 65 66 6f 78 2f 25 64 2e 30}
		$s4 = {55 73 65 72 2d 41 67 65 6e 74 3a 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 53 56 31 29}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( pe.imphash ( ) == "286870a926664a5129b8b68ed0d4a8eb" or 1 of ( $x* ) or #n1 > 4 or 4 of them )
}

