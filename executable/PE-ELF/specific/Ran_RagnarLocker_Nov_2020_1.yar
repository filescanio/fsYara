rule Ran_Mem_RagnarLocker_Nov_2020_1 : hardened
{
	meta:
		description = "Detect memory artefacts of the Ragnarlocker ransomware (Nov 2020)"
		author = "Arkbird_SOLG"
		reference = "Internal Research"
		date = "2020-11-26"
		hash1 = "041fd213326dd5c10a16caf88ff076bb98c68c052284430fba5f601023d39a14"
		hash2 = "dd79b2abc21e766fe3076038482ded43e5069a1af9e0ad29e06dce387bfae900"
		score = 75

	strings:
		$s1 = {5c 00 5c 00 2e 00 5c 00 50 00 48 00 59 00 53 00 49 00 43 00 41 00 4c 00 44 00 52 00 49 00 56 00 45 00 25 00 64 00}
		$s2 = {62 00 6f 00 6f 00 74 00 66 00 6f 00 6e 00 74 00 2e 00 62 00 69 00 6e 00}
		$s3 = {62 00 6f 00 6f 00 74 00 73 00 65 00 63 00 74 00 2e 00 62 00 61 00 6b 00}
		$s4 = {62 00 6f 00 6f 00 74 00 6d 00 67 00 72 00 2e 00 65 00 66 00 69 00}
		$s5 = {2d 2d 2d 52 41 47 4e 41 52 20 53 45 43 52 45 54 2d 2d 2d}
		$s6 = {4d 6f 7a 69 6c 6c 61}
		$s7 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00}
		$s8 = {20 20 3c 2f 74 72 75 73 74 49 6e 66 6f 3e}
		$s9 = {54 00 6f 00 72 00 20 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00}
		$s10 = {4f 00 70 00 65 00 72 00 61 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00}
		$s11 = {2d 2d 2d 45 4e 44 20 52 41 47 4e 20 4b 45 59 2d 2d 2d}
		$s12 = {2d 2d 2d 42 45 47 49 4e 20 52 41 47 4e 20 4b 45 59 2d 2d 2d}
		$s13 = {25 00 73 00 2d 00 25 00 73 00 2d 00 25 00 73 00 2d 00 25 00 73 00 2d 00 25 00 73 00}
		$s14 = {24 00 52 00 65 00 63 00 79 00 63 00 6c 00 65 00 2e 00 42 00 69 00 6e 00}
		$s15 = {2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a}
		$s16 = {4b 3c 5e 5f 5b 5d}
		$s17 = {53 44 3b 53 44 77}
		$s18 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2e 00 6f 00 6c 00 64 00}
		$s19 = {69 00 63 00 6f 00 6e 00 63 00 61 00 63 00 68 00 65 00 2e 00 64 00 62 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 30KB and 12 of them
}

import "pe"

rule Ran_Cert_RagnarLocker_Nov_2020_1 : hardened
{
	meta:
		description = "Detect certificates and VMProtect used for the Ragnarlocker ransomware (Nov 2020)"
		author = "Arkbird_SOLG"
		reference = "Internal Research"
		date = "2020-11-26"
		level = "Experimental"
		hash1 = "afab912c41c920c867f1b2ada34114b22dcc9c5f3666edbfc4e9936c29a17a68"
		hash2 = "9416e5a57e6de00c685560fa9fee761126569d123f62060792bf2049ebba4151"

	strings:
		$vmp0 = { 2E 76 6D 70 30 00 00 00 }
		$vmp1 = { 2E 76 6D 70 31 00 00 00 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 5000KB and for any i in ( 0 .. pe.number_of_signatures ) : ( pe.signatures [ i ] . issuer contains "GlobalSign" and pe.signatures [ i ] . serial == "68:65:29:4f:67:f0:c3:bb:2e:19:1f:75" ) and $vmp0 in ( 0x100 .. 0x300 ) and $vmp1 in ( 0x100 .. 0x300 )
}

