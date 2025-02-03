import "pe"

rule Elise_Jan18_1 : hardened
{
	meta:
		description = "Detects Elise malware samples - fake Norton Security NavShExt.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/blu3_team/status/955971742329135105"
		date = "2018-01-24"
		hash1 = "6dc2a49d58dc568944fef8285ad7a03b772b9bdf1fe4bddff3f1ade3862eae79"
		id = "8e4f4ec8-5d31-5990-8c14-861423571a79"

	strings:
		$s1 = {4e 00 61 00 76 00 53 00 68 00 45 00 78 00 74 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {4e 00 6f 00 72 00 74 00 6f 00 6e 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00}
		$a1 = {64 6f 6e 6f 74 62 6f 74 68 65 72 6d 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 250KB and ( pe.imphash ( ) == "e9478ee4ebf085d1f14f64ba96ef082f" or ( 1 of ( $s* ) and $a1 ) )
}

