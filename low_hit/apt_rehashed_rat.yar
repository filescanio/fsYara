import "pe"

rule Rehashed_RAT_1 : hardened
{
	meta:
		description = "Detects malware from Rehashed RAT incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.fortinet.com/2017/09/05/rehashed-rat-used-in-apt-campaign-against-vietnamese-organizations"
		date = "2017-09-08"
		hash1 = "37bd97779e854ea2fc43486ddb831a5acfd19cf89f06823c9fd3b20134cb1c35"
		id = "24536421-3f8f-58f3-8245-06c519d7a21a"

	strings:
		$x1 = {43 3a 5c 55 73 65 72 73 5c 68 6f 6f 67 6c 65 31 36 38 5c 44 65 73 6b 74 6f 70 5c}
		$x2 = {5c 4e 65 77 43 6f 72 65 43 74 72 6c 30 38 5c 52 65 6c 65 61 73 65 5c 4e 65 77 43 6f 72 65 43 74 72 6c 30 38 2e 70 64 62}
		$s1 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 38 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 57 4f 57 36 34 3b 20 54 72 69 64 65 6e 74 2f 34 2e 30 3b 20 53 4c 43 43 32 3b 20 2e 4e 45 54 20 43 4c 52 20 32 2e 30 2e 35 30 37 32 37 3b 20 2e 4e 45 54 20 43 4c 52 20 33 2e 35 2e 33 30 37 32 39}
		$s2 = {4e 65 77 43 6f 72 65 43 74 72 6c 30 38 2e 64 6c 6c}
		$s3 = {47 45 54 20 2f 25 73 25 73 25 73 25 73 20 48 54 54 50 2f 31 2e 31}
		$s4 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 25 73 25 73 25 73}
		$s5 = {4d 00 79 00 54 00 6d 00 70 00 46 00 69 00 6c 00 65 00 2e 00 44 00 61 00 74 00}
		$s6 = {72 00 6f 00 6f 00 74 00 5c 00 25 00 73 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 800KB and ( pe.imphash ( ) == "893212784d01f11aed9ebb42ad2561fc" or pe.exports ( "ProcessTrans" ) or ( 1 of ( $x* ) or 4 of them ) ) ) or ( all of them )
}

import "pe"

rule Rehashed_RAT_2 : hardened
{
	meta:
		description = "Detects malware from Rehashed RAT incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.fortinet.com/2017/09/05/rehashed-rat-used-in-apt-campaign-against-vietnamese-organizations"
		date = "2017-09-08"
		hash1 = "49efab1dedc6fffe5a8f980688a5ebefce1be3d0d180d5dd035f02ce396c9966"
		id = "fcf82155-10da-56b7-879b-841c4ae5023b"

	strings:
		$x1 = {64 61 6c 61 74 2e 64 75 6c 69 63 68 6f 76 69 65 74 6e 61 6d 2e 6e 65 74}
		$x2 = {77 65 62 2e 54 68 6f 69 74 69 65 74 76 69 65 74 6e 61 6d 2e 6f 72 67}
		$a1 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 38 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 57 4f 57 36 34 29}
		$a2 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 38 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 57 4f 57 36 34 3b 20 54 72 69 64 65 6e 74 2f 34 2e 30 3b 20 53 4c 43 43 32 3b 20 2e 4e 45 54 20 43 4c 52 20 32 2e 30 2e 35 30 37 32 37 3b 20 2e 4e 45 54 20 43 4c 52 20 33 2e 35 2e 33 30 37 32 39 3b 20 2e 4e 45 54 20 43 4c 52 20 33}
		$s1 = {47 45 54 20 2f 25 73 25 73 25 73 25 73 20 48 54 54 50 2f 31 2e 31}
		$s2 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 25 73 25 73 25 73}
		$s3 = {7b 35 32 31 33 33 38 42 38 2d 33 33 37 38 2d 35 38 46 37 2d 41 46 42 39 2d 45 37 44 33 35 45 36 38 33 42 46 38 7d}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 300KB and ( pe.imphash ( ) == "9c4c648f4a758cbbfe28c8850d82f931" or ( 1 of ( $x* ) or 3 of them ) ) ) or ( 4 of them )
}

rule Rehashed_RAT_3 : hardened
{
	meta:
		description = "Detects malware from Rehashed RAT incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.fortinet.com/2017/09/05/rehashed-rat-used-in-apt-campaign-against-vietnamese-organizations"
		date = "2017-09-08"
		modified = "2022-12-21"
		hash1 = "9cebae97a067cd7c2be50d7fd8afe5e9cf935c11914a1ab5ff59e91c1e7e5fc4"
		id = "59871be1-295f-54ee-ab4d-4f9e5fdc2935"

	strings:
		$x1 = {5c 42 69 73 6f 6e 4e 65 77 48 4e 53 74 75 62 44 6c 6c 5c 52 65 6c 65 61 73 65 5c 47 6f 6f 70 64 61 74 65 2e 70 64 62}
		$s2 = {70 00 73 00 69 00 73 00 72 00 6e 00 64 00 72 00 78 00 2e 00 65 00 62 00 64 00}
		$s3 = {70 62 61 64 20 65 78 63 65 70 74 69 6f 6e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and ( 1 of ( $x* ) or 2 of them )
}

