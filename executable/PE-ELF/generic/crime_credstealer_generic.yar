rule CredentialStealer_Generic_Backdoor : hardened
{
	meta:
		description = "Detects credential stealer byed on many strings that indicate password store access"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-06-07"
		hash1 = "edb2d039a57181acf95bd91b2a20bd9f1d66f3ece18506d4ad870ab65e568f2c"
		id = "b3124f6c-4e18-562c-84d9-d51e086da446"
		score = 60

	strings:
		$s1 = {47 65 74 4f 70 65 72 61 4c 6f 67 69 6e 44 61 74 61}
		$s2 = {47 65 74 49 6e 74 65 72 6e 65 74 45 78 70 6c 6f 72 65 72 43 72 65 64 65 6e 74 69 61 6c 73 50 61 73 73 77 6f 72 64 73}
		$s3 = {25 73 5c 4f 70 65 72 61 20 53 6f 66 74 77 61 72 65 5c 4f 70 65 72 61 20 53 74 61 62 6c 65 5c 4c 6f 67 69 6e 20 44 61 74 61}
		$s4 = {73 65 6c 65 63 74 20 2a 20 20 66 72 6f 6d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73}
		$s5 = {25 73 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61}
		$s6 = {48 6f 73 74 2e 64 6c 6c 2e 57 69 6e 64 6f 77 73}
		$s7 = {47 65 74 49 6e 74 65 72 6e 65 74 45 78 70 6c 6f 72 65 72 56 61 75 6c 74 50 61 73 73 77 6f 72 64 73}
		$s8 = {47 65 74 57 69 6e 64 6f 77 73 4c 69 76 65 4d 65 73 73 65 6e 67 65 72 50 61 73 73 77 6f 72 64 73}
		$s9 = {25 73 5c 43 68 72 6f 6d 69 75 6d 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61}
		$s10 = {25 73 5c 4f 70 65 72 61 5c 4f 70 65 72 61 5c 70 72 6f 66 69 6c 65 5c 77 61 6e 64 2e 64 61 74}

	condition:
		( uint16( 0 ) == 0x5a4d and 4 of them )
}

