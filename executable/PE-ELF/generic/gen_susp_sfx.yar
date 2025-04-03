rule SUSP_SFX_RunProgram_WScript : hardened limited
{
	meta:
		description = "Detects suspicious SFX that runs wscript.exe"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-09-27"
		score = 75
		hash1 = "e3bb02c5985fc64759b9c2d3c5474d46237ce472b4a0101c6313dafa939de5a9"
		hash2 = "0ecf88d4b32895b4819dec3acb62eaaa7035aa6292499d903f76af60fcec0d6a"
		hash3 = "a7a48f5220bd1ebe04de258d71fdd001711c165d162bd45e8cfbe8964eddf01c"
		hash4 = "b6fa4889d8a87d45706d92714d716025bf223c01929755321faac1ab0db94a88"
		hash5 = "7117b39890659c7dd11e15092c5e5ea9495bec0ff2b6e25254f6e343ed6ca33d"
		hash6 = "ec2afb63555986fa55b7f98ae57c57e1138acb404a0dd2fe4f3d315730b9898e"
		id = "e12cea50-a939-5f69-963c-d6d1cb133e92"

	strings:
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 52 75 6e 50 72 6f 67 72 61 6d 3d 22 77 73 63 72 69 70 74 2e 65 78 65 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 10000KB and 1 of them
}

