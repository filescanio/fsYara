rule Anthem_DeepPanda_sl_txt_packed : hardened
{
	meta:
		description = "Anthem Hack Deep Panda - ScanLine sl-txt-packed"
		author = "Florian Roth"
		date = "2015/02/08"
		hash = "ffb1d8ea3039d3d5eb7196d27f5450cac0ea4f34"

	strings:
		$s0 = {43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 6c 00 69 00 6e 00 65 00 20 00 70 00 6f 00 72 00 74 00 20 00 73 00 63 00 61 00 6e 00 6e 00 65 00 72 00}
		$s1 = {73 00 6c 00 2e 00 65 00 78 00 65 00}
		$s2 = {43 50 70 6f 72 74 73 2e 74 78 74}
		$s3 = {2c 47 45 54 20 2f 20 48 54 54 50 2f 2e 7d}
		$s4 = {46 00 6f 00 75 00 6e 00 64 00 73 00 74 00 6f 00 6e 00 65 00 20 00 49 00 6e 00 63 00 2e 00}
		$s9 = {20 00 32 00 30 00 30 00 32 00 20 00 46 00 6f 00 75 00 6e 00 64 00 73 00 74 00 6f 00 6e 00 65 00 20 00 49 00 6e 00 63 00 2e 00}
		$s15 = {2c 20 49 6e 63 2e 20 32 30 30 32}
		$s20 = {49 43 4d 50 20 54 69 6d 65}

	condition:
		all of them
}

rule Anthem_DeepPanda_lot1 : hardened
{
	meta:
		description = "Anthem Hack Deep Panda - lot1.tmp-pwdump"
		author = "Florian Roth"
		date = "2015/02/08"
		hash = "5d201a0fb0f4a96cefc5f73effb61acff9c818e1"
		score = 60

	strings:
		$s0 = {55 6e 61 62 6c 65 20 74 6f 20 6f 70 65 6e 20 74 61 72 67 65 74 20 70 72 6f 63 65 73 73 3a 20 25 64 2c 20 70 69 64 20 25 64}
		$s1 = {43 6f 75 6c 64 6e 27 74 20 64 65 6c 65 74 65 20 74 61 72 67 65 74 20 65 78 65 63 75 74 61 62 6c 65 20 66 72 6f 6d 20 72 65 6d 6f 74 65 20 6d 61 63 68 69 6e 65 3a 20 25 64}
		$s2 = {54 61 72 67 65 74 3a 20 46 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 20 53 41 4d 20 66 75 6e 63 74 69 6f 6e 73 2e}
		$s5 = {45 72 72 6f 72 20 77 72 69 74 69 6e 67 20 74 68 65 20 74 65 73 74 20 66 69 6c 65 20 25 73 2c 20 73 6b 69 70 70 69 6e 67 20 74 68 69 73 20 73 68 61 72 65}
		$s6 = {46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 73 65 72 76 69 63 65 20 28 25 73 2f 25 73 29 2c 20 65 72 72 6f 72 20 25 64}
		$s8 = {53 65 72 76 69 63 65 20 73 74 61 72 74 20 66 61 69 6c 65 64 3a 20 25 64 20 28 25 73 2f 25 73 29}
		$s12 = {50 77 44 75 6d 70 2e 65 78 65}
		$s13 = {47 65 74 41 76 61 69 6c 61 62 6c 65 57 72 69 74 65 61 62 6c 65 53 68 61 72 65 20 72 65 74 75 72 6e 65 64 20 61 6e 20 65 72 72 6f 72 20 6f 66 20 25 6c 64}
		$s14 = {3a 5c 5c 2e 5c 70 69 70 65 5c 25 73}
		$s15 = {43 6f 75 6c 64 6e 27 74 20 63 6f 70 79 20 25 73 20 74 6f 20 64 65 73 74 69 6e 61 74 69 6f 6e 20 25 73 2e 20 28 45 72 72 6f 72 20 25 64 29}
		$s16 = {64 75 6d 70 20 6c 6f 67 6f 6e 20 73 65 73 73 69 6f 6e}
		$s17 = {54 69 6d 65 64 20 6f 75 74 20 77 61 69 74 69 6e 67 20 74 6f 20 67 65 74 20 6f 75 72 20 70 69 70 65 20 62 61 63 6b}
		$s19 = {53 65 74 4e 61 6d 65 64 50 69 70 65 48 61 6e 64 6c 65 53 74 61 74 65 20 66 61 69 6c 65 64 2c 20 65 72 72 6f 72 20 25 64}
		$s20 = {25 73 5c 25 73 2e 65 78 65}

	condition:
		10 of them
}

rule Anthem_DeepPanda_htran_exe : hardened
{
	meta:
		description = "Anthem Hack Deep Panda - htran-exe"
		author = "Florian Roth"
		date = "2015/02/08"
		hash = "38e21f0b87b3052b536408fdf59185f8b3d210b9"
		score = 100

	strings:
		$s0 = {25 73 20 2d 3c 6c 69 73 74 65 6e 7c 74 72 61 6e 7c 73 6c 61 76 65 3e 20 3c 6f 70 74 69 6f 6e 3e 20 5b 2d 6c 6f 67 20 6c 6f 67 66 69 6c 65 5d}
		$s1 = {5b 2d 5d 20 47 65 74 68 6f 73 74 62 79 6e 61 6d 65 28 25 73 29 20 65 72 72 6f 72 3a 25 73}
		$s2 = {65 3a 5c 56 53 20 32 30 30 38 20 50 72 6f 6a 65 63 74 5c 68 74 72 61 6e 5c 52 65 6c 65 61 73 65 5c 68 74 72 61 6e 2e 70 64 62}
		$s3 = {5b 53 45 52 56 45 52 5d 63 6f 6e 6e 65 63 74 69 6f 6e 20 74 6f 20 25 73 3a 25 64 20 65 72 72 6f 72}
		$s4 = {2d 74 72 61 6e 20 20 3c 43 6f 6e 6e 65 63 74 50 6f 72 74 3e 20 3c 54 72 61 6e 73 6d 69 74 48 6f 73 74 3e 20 3c 54 72 61 6e 73 6d 69 74 50 6f 72 74 3e}
		$s5 = {5b 2d 5d 20 45 52 52 4f 52 3a 20 4d 75 73 74 20 73 75 70 70 6c 79 20 6c 6f 67 66 69 6c 65 20 6e 61 6d 65 2e}
		$s6 = {5b 2d 5d 20 54 68 65 72 65 20 69 73 20 61 20 65 72 72 6f 72 2e 2e 2e 43 72 65 61 74 65 20 61 20 6e 65 77 20 63 6f 6e 6e 65 63 74 69 6f 6e 2e}
		$s7 = {5b 2b 5d 20 41 63 63 65 70 74 20 61 20 43 6c 69 65 6e 74 20 6f 6e 20 70 6f 72 74 20 25 64 20 66 72 6f 6d 20 25 73}
		$s8 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 20 68 74 72 61 6e 20 56 25 73 20 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d}
		$s9 = {5b 2d 5d 20 53 6f 63 6b 65 74 20 4c 69 73 74 65 6e 20 65 72 72 6f 72 2e}
		$s10 = {5b 2d 5d 20 45 52 52 4f 52 3a 20 6f 70 65 6e 20 6c 6f 67 66 69 6c 65}
		$s11 = {2d 73 6c 61 76 65 20 20 3c 43 6f 6e 6e 65 63 74 48 6f 73 74 3e 20 3c 43 6f 6e 6e 65 63 74 50 6f 72 74 3e 20 3c 54 72 61 6e 73 6d 69 74 48 6f 73 74 3e 20 3c 54 72 61 6e 73 6d 69 74 50 6f 72 74 3e}
		$s12 = {5b 2b 5d 20 4d 61 6b 65 20 61 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 74 6f 20 25 73 3a 25 64 20 2e 2e 2e 2e 2e 2e}
		$s14 = {52 65 63 76 20 25 35 64 20 62 79 74 65 73 20 66 72 6f 6d 20 25 73 3a 25 64}
		$s15 = {5b 2b 5d 20 4f 4b 21 20 49 20 43 6c 6f 73 65 64 20 54 68 65 20 54 77 6f 20 53 6f 63 6b 65 74 2e}
		$s16 = {5b 2b 5d 20 57 61 69 74 69 6e 67 20 61 6e 6f 74 68 65 72 20 43 6c 69 65 6e 74 20 6f 6e 20 70 6f 72 74 3a 25 64 2e 2e 2e 2e}
		$s17 = {5b 2b 5d 20 41 63 63 65 70 74 20 61 20 43 6c 69 65 6e 74 20 6f 6e 20 70 6f 72 74 20 25 64 20 66 72 6f 6d 20 25 73 20 2e 2e 2e 2e 2e 2e}
		$s20 = {2d 6c 69 73 74 65 6e 20 3c 43 6f 6e 6e 65 63 74 50 6f 72 74 3e 20 3c 54 72 61 6e 73 6d 69 74 50 6f 72 74 3e}

	condition:
		10 of them
}

rule Anthem_DeepPanda_Trojan_Kakfum : hardened
{
	meta:
		description = "Anthem Hack Deep Panda - Trojan.Kakfum sqlsrv32.dll"
		author = "Florian Roth"
		date = "2015/02/08"
		hash1 = "ab58b6aa7dcc25d8f6e4b70a24e0ccede0d5f6129df02a9e61293c1d7d7640a2"
		hash2 = "c6c3bb72896f8f0b9a5351614fd94e889864cf924b40a318c79560bbbcfa372f"

	strings:
		$s0 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 73 71 6c 73 65 72 76 65 72}
		$s1 = {25 73 5c 73 71 6c 73 72 76 33 32 2e 64 6c 6c}
		$s2 = {25 73 5c 73 71 6c 73 72 76 36 34 2e 64 6c 6c}
		$s3 = {25 73 5c 25 64 2e 74 6d 70}
		$s4 = {53 65 72 76 69 63 65 4d 61 69 78}
		$s15 = {73 71 6c 73 65 72 76 65 72}

	condition:
		all of them
}

