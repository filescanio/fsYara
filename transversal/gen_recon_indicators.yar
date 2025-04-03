rule Recon_Commands_Windows_Gen1 : hardened limited
{
	meta:
		description = "Detects a set of reconnaissance commands on Windows systems"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-07-10"
		score = 60
		reference = "https://goo.gl/MSJCxP"
		id = "bc95265c-780d-5451-bd12-d14495877e46"

	strings:
		$s1 = {6e 65 74 73 74 61 74 20 2d 61 6e}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6e 65 74 20 76 69 65 77 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6e 65 74 20 75 73 65 72 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = {77 68 6f 61 6d 69}
		$s5 = {74 61 73 6b 6c 69 73 74 20 2f 76}
		$s6 = {73 79 73 74 65 6d 69 6e 66 6f}
		$s7 = {6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73}
		$s8 = {6e 65 74 20 75 73 65 72 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72}
		$s9 = {72 65 67 65 64 69 74 20 2d 65 20}
		$s10 = {74 61 73 6b 6c 69 73 74 20 2f 73 76 63}
		$s11 = {72 65 67 73 76 72 33 32 20 2f 73 20 2f 75 20}
		$s12 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 65 67 57 72 69 74 65}
		$s13 = {62 69 74 73 61 64 6d 69 6e 20 2f 72 61 77 72 65 74 75 72 6e 20 2f 74 72 61 6e 73 66 65 72 20 67 65 74 66 69 6c 65}
		$s14 = {77 6d 69 63 20 71 66 65 20 6c 69 73 74 20 66 75 6c 6c}
		$s15 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 63 72 65 61 74 65 20}
		$s16 = {77 6d 69 63 20 73 68 61 72 65 20 67 65 74}
		$s17 = {77 6d 69 63 20 6e 74 65 76 65 6e 74 6c 6f 67 20 67 65 74}
		$s18 = {77 65 76 74 75 74 69 6c 20 63 6c 20}
		$s19 = {73 63 20 71 75 65 72 79 20 74 79 70 65 3d 20 73 65 72 76 69 63 65}
		$s20 = {61 72 70 20 2d 61 20}
		$fp1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 61 00 76 00 64 00 61 00 70 00 70 00 2e 00 64 00 6c 00 6c 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$fp2 = {6b 65 79 77 6f 72 64 2e 63 6f 6d 6d 61 6e 64 2e 62 61 74 63 68 66 69 6c 65}
		$fp3 = {2e 73 75 62 6c 69 6d 65 2d 73 65 74 74 69 6e 67 73}

	condition:
		filesize < 1000KB and 4 of them and not 1 of ( $fp* )
}

rule SUSP_Recon_Outputs_Jun20_1 : hardened
{
	meta:
		description = "Detects outputs of many different commands often used for reconnaissance purposes"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/cycldek-bridging-the-air-gap/97157/"
		date = "2020-06-04"
		score = 60
		id = "ec3759aa-212f-52ce-9f38-636accd35749"

	strings:
		$s1 = {2e 20 2e 20 2e 20 2e 20 3a 20 59 65 73}
		$s2 = {77 69 74 68 20 33 32 20 62 79 74 65 73 20 6f 66 20 64 61 74 61 3a}
		$s3 = {66 66 2d 66 66 2d 66 66 2d 66 66 2d 66 66 2d 66 66 20 20 20 20 20 73 74 61 74 69 63}
		$s4 = {20 20 54 43 50 20 20 20 20 30 2e 30 2e 30 2e 30 3a 34 34 35}
		$s5 = {53 79 73 74 65 6d 20 49 64 6c 65 20 50 72 6f 63 65 73 73}

	condition:
		filesize < 150KB and 4 of them
}

