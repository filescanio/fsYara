rule IronGate_APT_Step7ProSim_Gen : hardened
{
	meta:
		description = "Detects IronGate APT Malware - Step7ProSim DLL"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/Mr6M2J"
		date = "2016-06-04"
		score = 90
		hash1 = "0539af1a0cc7f231af8f135920a990321529479f6534c3b64e571d490e1514c3"
		hash2 = "fa8400422f3161206814590768fc1a27cf6420fc5d322d52e82899ac9f49e14f"
		hash3 = "5ab1672b15de9bda84298e0bb226265af09b70a9f0b26d6dfb7bdd6cbaed192d"
		id = "a73cf9e2-c24f-5553-92e2-3a1a882a4a06"

	strings:
		$x1 = {5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 53 74 65 70 37 50 72 6f 53 69 6d 2e 70 64 62}
		$s1 = {53 74 65 70 37 50 72 6f 53 69 6d 2e 49 6e 74 65 72 66 61 63 65 73}
		$s2 = {70 61 79 6c 6f 61 64 45 78 65 63 75 74 69 6f 6e 54 69 6d 65 49 6e 4d 69 6c 6c 69 53 65 63 6f 6e 64 73}
		$s3 = {50 00 61 00 63 00 6b 00 61 00 67 00 69 00 6e 00 67 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 2e 00 53 00 74 00 65 00 70 00 37 00 50 00 72 00 6f 00 53 00 69 00 6d 00 2e 00 64 00 6c 00 6c 00}
		$s4 = {3c 4b 69 6c 6c 50 72 6f 63 65 73 73 3e 62 5f 5f 30}
		$s5 = {6e 65 77 44 6c 6c 46 69 6c 65 6e 61 6d 65}
		$s6 = {50 00 61 00 63 00 6b 00 61 00 67 00 69 00 6e 00 67 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 2e 00 65 00 78 00 65 00}
		$s7 = {24 38 36 33 64 38 61 66 30 2d 63 65 65 36 2d 34 36 37 36 2d 39 36 61 64 2d 31 33 65 38 35 34 30 66 34 64 34 37}
		$s8 = {52 75 6e 50 6c 63 53 69 6d}
		$s9 = {24 63 63 63 36 34 62 63 35 2d 65 66 39 35 2d 34 32 31 37 2d 61 64 63 34 2d 35 62 66 30 64 34 34 38 63 32 37 32}
		$s10 = {49 6e 73 74 61 6c 6c 50 72 6f 78 79}
		$s11 = {44 6c 6c 50 72 6f 78 79 49 6e 73 74 61 6c 6c 65 72}
		$s12 = {46 69 6e 64 46 69 6c 65 49 6e 44 72 69 76 65}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 50KB and ( $x1 or 3 of ( $s* ) ) ) or ( 6 of them )
}

rule IronGate_PyInstaller_update_EXE : hardened
{
	meta:
		description = "Detects a PyInstaller file named update.exe as mentioned in the IronGate APT"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/Mr6M2J"
		date = "2016-06-04"
		modified = "2023-01-06"
		score = 60
		hash1 = "2044712ceb99972d025716f0f16aa039550e22a63000d2885f7b7cd50f6834e0"
		id = "f8d1b97e-86d9-547f-a212-a84fb068af3c"

	strings:
		$s1 = {62 70 79 74 68 6f 6e 32 37 2e 64 6c 6c}
		$s5 = {25 73 25 73 2e 65 78 65}
		$s6 = {62 75 70 64 61 74 65 2e 65 78 65 2e 6d 61 6e 69 66 65 73 74}
		$s9 = {62 75 6e 69 63 6f 64 65 64 61 74 61 2e 70 79 64}
		$s11 = {64 69 73 74 75 74 69 6c 73 2e 73 79 73 63 6f 6e 66 69 67 28}
		$s16 = {64 69 73 74 75 74 69 6c 73 2e 64 65 62 75 67 28}
		$s18 = {73 75 70 64 61 74 65}

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule Nirsoft_NetResView : hardened
{
	meta:
		description = "Detects NirSoft NetResView - utility that displays the list of all network resources"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/Mr6M2J"
		date = "2016-06-04"
		score = 40
		hash1 = "83f0352c14fa62ae159ab532d85a2b481900fed50d32cc757aa3f4ccf6a13bee"
		id = "bf786432-3ecf-510e-8d95-50aff09826ce"

	strings:
		$s1 = {4e 00 65 00 74 00 52 00 65 00 73 00 56 00 69 00 65 00 77 00 2e 00 65 00 78 00 65 00}
		$s2 = {32 00 30 00 30 00 35 00 20 00 2d 00 20 00 32 00 30 00 31 00 33 00 20 00 4e 00 69 00 72 00 20 00 53 00 6f 00 66 00 65 00 72 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and all of them
}

