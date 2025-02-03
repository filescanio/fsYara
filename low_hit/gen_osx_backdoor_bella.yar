rule OSX_backdoor_Bella : hardened
{
	meta:
		description = "Bella MacOS/OSX backdoor"
		author = "John Lambert @JohnLaTwC"
		reference = "https://twitter.com/JohnLaTwC/status/911998777182924801"
		date = "2018-02-23"
		hash = "4288a81779a492b5b02bad6e90b2fa6212fa5f8ee87cc5ec9286ab523fc02446 cec7be2126d388707907b4f9d681121fd1e3ca9f828c029b02340ab1331a5524 e1cf136be50c4486ae8f5e408af80b90229f3027511b4beed69495a042af95be"
		id = "d2a994f9-acff-5de4-8f70-453b5d4d7947"

	strings:
		$h1 = {23 21 2f 75 73 72 2f 62 69 6e 2f 65 6e 76}
		$s0 = {73 75 62 70 72 6f 63 65 73 73}
		$s1 = {69 6d 70 6f 72 74 20 73 79 73}
		$s2 = {73 68 75 74 69 6c}
		$p0 = {63 72 65 61 74 65 5f 62 65 6c 6c 61 5f 68 65 6c 70 65 72 73}
		$p1 = {69 73 5f 74 68 65 72 65 5f 53 55 49 44 5f 73 68 65 6c 6c}
		$p2 = {42 45 4c 4c 41 20 49 53 20 4e 4f 57 20 52 55 4e 4e 49 4e 47}
		$p3 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 62 65 6c 6c 61 20 57 48 45 52 45 20 69 64}
		$subpart1_a = {69 6e 6a 65 63 74 5f 70 61 79 6c 6f 61 64 73}
		$subpart1_b = {63 68 65 63 6b 5f 69 66 5f 70 61 79 6c 6f 61 64 73}
		$subpart1_c = {75 70 64 61 74 65 44 42}
		$subpart2_a = {61 70 70 6c 65 49 44 50 68 69 73 68 48 65 6c 70}
		$subpart2_b = {61 70 70 6c 65 49 44 50 68 69 73 68}
		$subpart2_c = {69 54 75 6e 65 73}

	condition:
		uint32( 0 ) == 0x752f2123 and $h1 at 0 and filesize < 120KB and @s0 [ 1 ] < 100 and @s1 [ 1 ] < 100 and @s2 [ 1 ] < 100 and 1 of ( $p* ) or all of ( $subpart1_* ) or all of ( $subpart2_* )
}

