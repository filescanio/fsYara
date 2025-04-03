import "pe"

rule MAL_Floxif_Generic : hardened
{
	meta:
		description = "Detects Floxif Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-05-11"
		score = 80
		hash1 = "de055a89de246e629a8694bde18af2b1605e4b9b493c7e4aef669dd67acf5085"
		id = "5ddd6a6c-b02a-518b-bbe3-8f528b3d7eae"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and ( pe.imphash ( ) == "2f4ddcfebbcad3bacadc879747151f6f" or pe.exports ( "FloodFix" ) or pe.exports ( "FloodFix2" ) )
}

import "pe"

rule MAL_CN_FlyStudio_May18_1 : hardened limited
{
	meta:
		description = "Detects malware / hacktool detected in May 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-05-11"
		hash1 = "b85147366890598518d4f277d44506eef871fd7fc6050d8f8e68889cae066d9e"
		id = "b78b9ea0-5eef-5922-b5d7-d3c5ddce7fad"

	strings:
		$s1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 57 54 4e 45 20 2f 20 4d 41 44 45 20 42 59 20 45 20 43 4f 4d 50 49 4c 45 52 20 2d 20 57 55 54 41 4f 20 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 77 77 77 2e 63 66 79 68 61 63 6b 2e 63 6e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 5000KB and ( pe.imphash ( ) == "65ae5cf17140aeaf91e3e9911da0ee3e" or 1 of them )
}

