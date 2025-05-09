rule HKTL_Keyword_InjectDLL : hardened limited
{
	meta:
		description = "Detects suspicious InjectDLL keyword found in hacktools or possibly unwanted applications"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/zerosum0x0/koadic"
		date = "2019-04-04"
		score = 60
		hash1 = "2e7b4141e1872857904a0ef2d87535fd913cbdd9f964421f521b5a228a492a29"
		id = "422eed76-7dfa-5490-a866-d337434eaddc"

	strings:
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 49 6e 6a 65 63 74 44 4c 4c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 4b 65 72 6e 65 6c 33 32 2e 64 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule HKTL_Python_sectools : hardened
{
	meta:
		description = "Detects code which uses the python lib sectools"
		author = "Arnim Rupp"
		date = "2023-01-27"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		reference = "https://github.com/p0dalirius/sectools"
		hash = "814ba1aa62bbb7aba886edae0f4ac5370818de15ca22a52a6ab667b4e93abf84"
		hash = "b3328ac397d311e6eb79f0a5b9da155c4d1987e0d67487ea681ea59d93641d9e"
		hash = "8cd205d5380278cff6673520439057e78fb8bf3d2b1c3c9be8463e949e5be4a1"
		score = 50
		id = "89a5e0ba-5547-53e4-84a3-d07ee779596e"

	strings:
		$import1 = {66 72 6f 6d 20 73 65 63 74 6f 6f 6c 73}
		$import2 = {69 6d 70 6f 72 74 20 73 65 63 74 6f 6f 6c 73}

	condition:
		any of ( $import* )
}

