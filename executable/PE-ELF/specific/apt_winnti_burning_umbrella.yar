import "pe"

rule MAL_BurningUmbrella_Sample_1 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "fcfe8fcf054bd8b19226d592617425e320e4a5bb4798807d6f067c39dfc6d1ff"
		id = "9f8a6831-172b-5310-9763-43657b79b91d"

	strings:
		$s1 = { 40 00 00 E0 75 68 66 61 6F 68 6C 79 }
		$s2 = { 40 00 00 E0 64 6A 7A 66 63 6D 77 62 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 4000KB and ( pe.imphash ( ) == "baa93d47220682c04d92f7797d9224ce" and $s1 in ( 0 .. 1024 ) and $s2 in ( 0 .. 1024 ) )
}

rule MAL_BurningUmbrella_Sample_2 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "801a64a730fc8d80e17e59e93533c1455686ca778e6ba99cf6f1971a935eda4c"
		id = "926b4a29-ce47-559b-94e3-1fabd90f3fbe"

	strings:
		$s1 = { 40 00 00 E0 63 68 72 6F 6D 67 75 78 }
		$s2 = { 40 00 00 E0 77 62 68 75 74 66 6F 61 }
		$s3 = {41 00 63 00 74 00 69 00 76 00 65 00 58 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and $s1 in ( 0 .. 1024 ) and $s2 in ( 0 .. 1024 ) and $s3
}

rule MAL_BurningUmbrella_Sample_3 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "92efbecc24fbb5690708926b6221b241b10bdfe3dd0375d663b051283d0de30f"
		id = "b997822a-3f62-51b4-bd96-e780ffe60812"

	strings:
		$s1 = {48 4b 45 59 5f 43 4c 41 53 53 45 53 5f 52 4f 4f 54 5c 57 6f 72 64 2e 44 6f 63 75 6d 65 6e 74 2e 38 5c 73 68 65 6c 6c 5c 4f 70 65 6e 5c 63 6f 6d 6d 61 6e 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and 1 of them
}

import "pe"

rule MAL_BurningUmbrella_Sample_4 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "a1629e8abce9d670fdb66fa1ef73ad4181706eefb8adc8a9fd257b6a21be48c6"
		id = "3489f64b-7ebc-55b8-bd11-afaa719e572b"

	strings:
		$x1 = {64 75 6d 70 6f 64 62 63 2e 65 78 65}
		$x2 = {70 68 6f 74 6f 5f 42 75 6e 64 6c 65 2e 65 78 65}
		$x3 = {43 6f 6e 6e 65 63 74 20 32 20 66 61 69 6c 73 20 3a 20 25 64 2c 25 73 3a 25 64}
		$x4 = {43 6f 6e 6e 65 63 74 20 66 61 69 6c 73 20 31 20 3a 20 25 64 20 25 73 3a 25 64}
		$x5 = {4e 65 77 20 49 50 20 3a 20 25 73 2c 4e 65 77 20 50 6f 72 74 3a 20 25 64}
		$x6 = {4d 00 69 00 63 00 72 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00}
		$x7 = {4e 65 77 20 43 6f 6e 46 61 69 6c 73 20 3a 20 25 64}
		$s1 = {63 6d 64 20 2f 63 20 6e 65 74 20 73 74 6f 70 20 73 74 69 73 76 63}
		$s2 = {63 6d 64 20 2f 63 20 6e 65 74 20 73 74 6f 70 20 73 70 6f 6f 6c 65 72}
		$s3 = {5c 74 65 6d 70 5c 73 25 64 2e 64 61 74}
		$s4 = {63 6d 64 20 2f 63 20 6e 65 74 20 73 74 6f 70 20 77 75 61 75 73 65 72 76}
		$s5 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 79 41 70 70 2f 30 2e 31}
		$s6 = {25 73 2d 3e 25 73 20 46 61 69 6c 73 20 3a 20 25 64}
		$s7 = {45 6e 74 65 72 20 57 6f 72 6b 54 68 72 65 61 64 2c 43 75 72 72 65 6e 74 20 73 6f 63 6b 3a 25 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 50KB and ( ( pe.exports ( "Print32" ) and 2 of them ) or 1 of ( $x* ) or 4 of them )
}

rule MAL_BurningUmbrella_Sample_6 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "49ef2b98b414c321bcdbab107b8fa71a537958fe1e05ae62aaa01fe7773c3b4b"
		id = "7198a734-fd54-5cb5-9966-b91796a415c7"

	strings:
		$s1 = {45 78 65 63 75 74 65 46 69 6c 65 3d 22 68 69 64 63 6f 6e 3a 6e 6f 77 61 69 74 3a 5c 5c 22 57 6f 72 64 5c 5c 72 2e 62 61 74 5c 5c 22 22}
		$s2 = {49 6e 73 74 61 6c 6c 50 61 74 68 3d 22 25 41 70 70 64 61 74 61 25 5c 5c 4d 69 63 72 6f 73 6f 66 74 22}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}

import "pe"

rule MAL_BurningUmbrella_Sample_7 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "a4ce3a356d61fbbb067e1430b8ceedbe8965e0cfedd8fb43f1f719e2925b094a"
		hash2 = "a8bfc1e013f15bc395aa5c047f22ff2344c343c22d420804b6d2f0a67eb6db64"
		hash3 = "959612f2a9a8ce454c144d6aef10dd326b201336a85e69a604e6b3892892d7ed"
		id = "7e427512-a8ee-53ae-a141-e995e74ca845"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and pe.imphash ( ) == "f5b113d6708a3927b5cc48f2215fcaff"
}

rule MAL_BurningUmbrella_Sample_8 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "73270fe9bca94fead1b5b38ddf69fae6a42e574e3150d3e3ab369f5d37d93d88"
		id = "1b89d5a1-1425-5cb7-b429-563769bc0943"

	strings:
		$s1 = {63 6d 64 20 2f 63 20 6f 70 65 6e 20 25 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and 1 of them
}

rule MAL_BurningUmbrella_Sample_10 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "70992a72412c5d62d003a29c3967fcb0687189d3290ebbc8671fa630829f6694"
		hash2 = "48f0bbc3b679aac6b1a71c06f19bb182123e74df8bb0b6b04ebe99100c57a41e"
		hash3 = "5475ae24c4eeadcbd49fcd891ce64d0fe5d9738f1c10ba2ac7e6235da97d3926"
		id = "e4cb2211-efbe-55f9-99e3-c01601904509"

	strings:
		$s1 = {72 65 76 6a 6a 2e 73 79 73 68 65 6c 6c 2e 6f 72 67}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and all of them
}

rule MAL_BurningUmbrella_Sample_11 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "278e9d130678615d0fee4d7dd432f0dda6d52b0719649ee58cbdca097e997c3f"
		id = "9762c68c-4d69-5d38-aaf4-0048e7404147"

	strings:
		$s1 = {52 65 73 75 6d 65 2e 61 70 70 2f 43 6f 6e 74 65 6e 74 73 2f 4a 61 76 61 2f 52 65 73 75 6d 65 2e 6a 61 72 50 4b}

	condition:
		uint16( 0 ) == 0x4b50 and filesize < 700KB and 1 of them
}

import "pe"

rule MAL_BurningUmbrella_Sample_12 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "b9aba520eeaf6511877c1eec5f7d71e0eea017312a104f30d3b8f17c89db47e8"
		id = "805a00e7-2959-53d8-b769-0f8e54e1bbd5"

	strings:
		$s1 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 71 6d 67 72 2e 64 6c 6c}
		$s2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 53 74 61 72 74 75 70}
		$s3 = {6e 00 76 00 73 00 76 00 63 00 73 00 2e 00 64 00 6c 00 6c 00}
		$s4 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 73 65 72 76 69 63 65 73 5c 42 49 54 53 5c 50 61 72 61 6d 65 74 65 72 73}
		$s5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 67 69 6e 74 65 72 6e 65 74 2e 6e 65 74 20 30}
		$s6 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 80KB and ( pe.exports ( "SvcServiceMain" ) and 5 of them )
}

import "pe"

rule MAL_BurningUmbrella_Sample_13 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "d31374adc0b96a8a8b56438bbbc313061fd305ecee32a12738dd965910c8890f"
		hash2 = "c74a8e6c88f8501fb066ae07753efe8d267afb006f555811083c51c7f546cb67"
		id = "38c73425-bbdd-5b74-8ad4-5e0052039dd8"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and pe.imphash ( ) == "75f201aa8b18e1c4f826b2fe0963b84f"
}

rule MAL_BurningUmbrella_Sample_14 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "388ef4b4e12a04eab451bd6393860b8d12948f2bce12e5c9022996a9167f4972"
		id = "a2b3a4bb-ca60-5dc2-8124-17e654e326b8"

	strings:
		$s1 = {43 3a 5c 74 6d 70 5c 47 6f 6f 67 6c 65 5f 75 70 64 61 74 61 2e 65 78 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 40KB and 1 of them
}

import "pe"

rule MAL_BurningUmbrella_Sample_15 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "be6bea22e909bd772d21647ffee6d15e208e386e8c3c95fd22816c6b94196ae8"
		hash2 = "72a8fa454f428587d210cba0e74735381cd0332f3bdcbb45eecb7e271e138501"
		hash3 = "9cc38ea106efd5c8e98c2e8faf97c818171c52fa3afa0c4c8f376430fa556066"
		hash4 = "1a4a64f01b101c16e8b5928b52231211e744e695f125e056ef7a9412da04bb91"
		hash5 = "3cd42e665e21ed4815af6f983452cbe7a4f2ac99f9ea71af4480a9ebff5aa048"
		id = "4dc840c1-e6fa-5b21-bfcd-ef07cd85272a"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 50KB and pe.imphash ( ) == "cc33b1500354cf785409a3b428f7cd2a"
}

rule MAL_BurningUmbrella_Sample_16 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "58bb3859e02b8483e9f84cc56fbd964486e056ef28e94dd0027d361383cc4f4a"
		id = "8b1970bd-571e-5c53-9170-1605c69d9d6d"

	strings:
		$s1 = {68 74 74 70 3a 2f 2f 6e 65 74 69 6d 6f 2e 6e 65 74 20 30}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and all of them
}

rule MAL_BurningUmbrella_Sample_17 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "fa380dac35e16da01242e456f760a0e75c2ce9b68ff18cfc7cfdd16b2f4dec56"
		hash2 = "854b64155f9ceac806b49f3e352949cc292e5bc33f110d965cf81a93f78d2f07"
		hash3 = "1e462d8968e8b6e8784d7ecd1d60249b41cf600975d2a894f15433a7fdf07a0f"
		hash4 = "3cdc149e387ec4a64cce1191fc30b8588df4a2947d54127eae43955ce3d08a01"
		hash5 = "a026b11e15d4a81a449d20baf7cbd7b8602adc2644aa4bea1e55ff1f422c60e3"
		id = "d79d3f65-f27c-582b-9258-7c84dc7682a6"

	strings:
		$s1 = {73 00 79 00 73 00 68 00 65 00 6c 00 6c 00}
		$s2 = {4e 6f 72 6d 61 6c 2e 64 6f 74 6d}
		$s3 = {4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 20 57 6f 72 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and all of them
}

import "pe"

rule MAL_BurningUmbrella_Sample_18 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "d8df60524deb6df4f9ddd802037a248f9fbdd532151bb00e647b233e845b1617"
		hash2 = "c55cb6b42cfabf0edf1499d383817164d1b034895e597068e019c19d787ea313"
		hash3 = "32144ba8370826e069e5f1b6745a3625d10f50a809f3f2a72c4c7644ed0cab03"
		hash4 = "ae616003d85a12393783eaff9778aba20189e423c11c852e96c29efa6ecfce81"
		hash5 = "95b6e427883f402db73234b84a84015ad7f3456801cb9bb19df4b11739ea646d"
		hash6 = "1419ba36aae1daecc7a81a2dfb96631537365a5b34247533d59a70c1c9f58da2"
		hash7 = "6a5a9b0ae10ce6a0d5e1f7d21d8ea87894d62d0cda00db005d8d0de17cae7743"
		hash8 = "74e348068f8851fec1b3de54550fe09d07fb85b7481ca6b61404823b473885bb"
		hash9 = "adb9c2fe930fae579ce87059b4b9e15c22b6498c42df01db9760f75d983b93b2"
		hash0 = "23f28b5c4e94d0ad86341c0b9054f197c63389133fcd81dd5e0cf59f774ce54b"
		id = "d08f4676-ff28-59be-9fd4-b5a824e577d9"

	strings:
		$s1 = {63 3a 5c 74 6d 70 5c 74 72 61 6e 2e 65 78 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and ( pe.imphash ( ) == "11675b4db0e7df7b29b1c1ef6f88e2e1" or pe.imphash ( ) == "364e1f68e2d412db34715709c68ba467" or pe.exports ( "deKernel" ) or 1 of them )
}

rule MAL_BurningUmbrella_Sample_19 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "05e2912f2a593ba16a5a094d319d96715cbecf025bf88bb0293caaf6beb8bc20"
		hash2 = "e7bbdb275773f43c8e0610ad75cfe48739e0a2414c948de66ce042016eae0b2e"
		id = "8ab55e80-5d28-5a5f-a1cc-725ba6720e4b"

	strings:
		$s1 = {43 72 79 70 74 69 6f 6e 2e 64 6c 6c}
		$s2 = {74 72 61 6e 2e 65 78 65}
		$s3 = {4b 65 72 6e 65 6c 2e 64 6c 6c}
		$s4 = {4e 6f 77 20 72 65 61 64 79 20 74 6f 20 67 65 74 20 74 68 65 20 66 69 6c 65 20 25 73 21}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and 3 of them
}

import "pe"

rule MAL_BurningUmbrella_Sample_20 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		modified = "2023-01-06"
		hash1 = "5c12379cd7ab3cb03dac354d0e850769873d45bb486c266a893c0daa452aa03c"
		hash2 = "172cd90fd9e31ba70e47f0cc76c07d53e512da4cbfd197772c179fe604b75369"
		hash3 = "1ce88e98c8b37ea68466657485f2c01010a4d4a88587ba0ae814f37680a2e7a8"
		id = "1a39a76a-31e2-5d6e-82cb-ea38d503b6a9"

	strings:
		$s1 = {57 00 6f 00 72 00 64 00 70 00 61 00 64 00 2e 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 2e 00 31 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 5c 00}
		$s2 = {25 00 73 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 4f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00}
		$s3 = {65 78 70 61 6e 64 69 6e 67 20 63 6f 6d 70 75 74 65 72}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and ( pe.imphash ( ) == "bac338bfe2685483c201e15eae4352d5" or 2 of them )
}

rule MAL_BurningUmbrella_Sample_21 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "4b7b9c2a9d5080ccc4e9934f2fd14b9d4e8f6f500889bf9750f1d672c8724438"
		id = "2193e4b6-b71c-5031-8e43-fdd7177ad05c"

	strings:
		$s1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 69 6d 65 5c 73 65 74 75 70 2e 65 78 65}
		$s2 = {77 73 2e 72 75 6e 20 22 6c 61 74 65 72 2e 62 61 74 20 2f 73 74 61 72 74 22 2c 30 43 65 74 20}
		$s3 = {64 65 6c 20 6c 61 74 65 72 2e 62 61 74}
		$s4 = {6d 79 63 72 73 2e 78 6c 73}
		$a1 = {2d 65 6c 20 2d 73 32 20 22 2d 64 25 73 22 20 22 2d 70 25 73 22 20 22 2d 73 70 25 73 22}
		$a2 = {3c 73 65 74 20 77 73 3d 77 73 63 72 69 70 74 2e 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and 2 of them
}

rule MAL_BurningUmbrella_Sample_22 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "fa116cf9410f1613003ca423ad6ca92657a61b8e9eda1b05caf4f30ca650aee5"
		id = "90c6cda9-95a0-5de7-b1cd-110c238d993d"

	strings:
		$s1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c}
		$s3 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 74 78 74 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22}
		$s4 = {46 61 69 6c 20 54 6f 20 45 6e 75 6d 20 53 65 72 76 69 63 65}
		$s5 = {48 6f 73 74 20 50 6f 77 65 72 20 4f 4e 20 54 69 6d 65}
		$s6 = {25 64 20 48 6f 75 72 73 20 25 32 64 20 4d 69 6e 75 74 65 73 20 25 32 64 20 53 65 63 6f 6e 64 73 20}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and 4 of them
}

rule MAL_AirdViper_Sample_Apr18_1 : hardened
{
	meta:
		description = "Detects Arid Viper malware sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-05-04"
		hash1 = "9f453f1d5088bd17c60e812289b4bb0a734b7ad2ba5a536f5fd6d6ac3b8f3397"
		id = "00f118d1-be1c-5f50-a50f-591f824a1a53"
		score = 80

	strings:
		$x1 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 6e 20 31 20 2d 77 20 33 30 30 30 20 3e 20 4e 75 6c 20 26 20 44 65 6c 20 22 25 73 22}
		$x2 = {64 61 65 6e 65 72 79 73 3d 25 73 26}
		$x3 = {62 65 74 72 69 65 62 73 73 79 73 74 65 6d 3d 25 73 26 61 6e 77 65 6e 64 75 6e 67 3d 25 73 26 41 56 3d 25 73}
		$s1 = {54 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 20 25 73 20 2f 46 20 26 20 20 25 73}
		$s2 = {2f 61 70 69 2f 70 72 69 6d 65 77 69 72 65 2f 25 73 2f 72 65 71 75 65 73 74 73 2f 6d 61 63 4b 65 6e 7a 69 65 2f 64 65 6c 65 74 65}
		$s3 = {5c 54 61 73 6b 57 69 6e 64 6f 77 73 2e 65 78 65}
		$s4 = {4d 69 63 72 6f 73 6f 66 74 4f 6e 65 44 72 69 76 65 73 2e 65 78 65}
		$s5 = {5c 53 65 61 6e 53 61 6e 73 6f 6d 2e 74 78 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 6000KB and ( 1 of ( $x* ) or 4 of them )
}

rule MAL_Winnti_Sample_May18_1 : hardened
{
	meta:
		description = "Detects malware sample from Burning Umbrella report - Generic Winnti Rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "528d9eaaac67716e6b37dd562770190318c8766fa1b2f33c0974f7d5f6725d41"
		id = "c2f3339e-269f-5a51-8db6-06e54a707b3a"

	strings:
		$s1 = {77 00 69 00 72 00 65 00 73 00 68 00 61 00 72 00 6b 00}
		$s2 = {70 00 72 00 6f 00 63 00 65 00 78 00 70 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and all of them
}

import "pe"

rule MAL_Visel_Sample_May18_1 : hardened
{
	meta:
		description = "Detects Visel malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "35db8e6a2eb5cf09cd98bf5d31f6356d0deaf4951b353fc513ce98918b91439c"
		id = "a244461a-380c-56e6-a891-131f6e13c280"

	strings:
		$s2 = {70 72 69 6e 74 33 32 2e 64 6c 6c}
		$s3 = {63 3a 5c 61 5c 62 2e 74 78 74}
		$s4 = {5c 00 74 00 65 00 6d 00 70 00 5c 00 73 00 25 00 64 00 2e 00 64 00 61 00 74 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and ( pe.exports ( "szFile" ) or 2 of them )
}

