import "pe"

rule KasperMalware_Oct17_1 : hardened
{
	meta:
		description = "Detects Kasper Backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-10-24"
		hash1 = "758bdaf26a0bd309a5458cb4569fe1c789cf5db087880d6d1676dec051c3a28d"
		id = "7201d8ee-50ee-5a5c-a5b8-ee36c78b0d6e"

	strings:
		$x1 = {5c 52 65 6c 65 61 73 65 5c 6b 61 73 70 65 72 2e 70 64 62}
		$x2 = {43 00 3a 00 5c 00 44 00 40 00 6f 00 63 00 40 00 75 00 6d 00 40 00 65 00 6e 00 40 00 74 00 73 00 20 00 61 00 40 00 6e 00 64 00 20 00 53 00 65 00 74 00 40 00 74 00 69 00 6e 00 67 00 73 00 5c 00 41 00 6c 00 40 00 6c 00 20 00 55 00 73 00 65 00 72 00 73 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 7000KB and ( pe.imphash ( ) == "2bceb64cf37acd34bc33b38f2cddfb61" or 1 of them )
}

