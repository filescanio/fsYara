rule Emissary_APT_Malware_1 : hardened
{
	meta:
		description = "Detect Emissary Malware - from samples A08E81B411.DAT, ishelp.dll"
		author = "Florian Roth"
		reference = "http://goo.gl/V0epcf"
		date = "2016-01-02"
		score = 75
		hash1 = "9420017390c598ee535c24f7bcbd39f40eca699d6c94dc35bcf59ddf918c59ab"
		hash2 = "70561f58c9e5868f44169854bcc906001947d98d15e9b4d2fbabd1262d938629"
		hash3 = "0e64e68f6f88b25530699a1cd12f6f2790ea98e6e8fa3b4bc279f8e5c09d7290"
		hash4 = "69caa2a4070559d4cafdf79020c4356c721088eb22398a8740dea8d21ae6e664"
		hash5 = "675869fac21a94c8f470765bc6dd15b17cc4492dd639b878f241a45b2c3890fc"
		hash6 = "e817610b62ccd00bdfc9129f947ac7d078d97525e9628a3aa61027396dba419b"
		hash7 = "a8b0d084949c4f289beb4950f801bf99588d1b05f68587b245a31e8e82f7a1b8"
		hash8 = "acf7dc5a10b00f0aac102ecd9d87cd94f08a37b2726cb1e16948875751d04cc9"
		hash9 = "e21b47dfa9e250f49a3ab327b7444902e545bed3c4dcfa5e2e990af20593af6d"
		hash10 = "e369417a7623d73346f6dff729e68f7e057f7f6dae7bb03d56a7510cb3bfe538"
		hash11 = "29d8dc863427c8e37b75eb738069c2172e79607acc7b65de6f8086ba36abf051"
		hash12 = "98fb1d2975babc18624e3922406545458642e01360746870deee397df93f50e0"
		hash13 = "fbcb401cf06326ab4bb53fb9f01f1ca647f16f926811ea66984f1a1b8cf2f7bb"

	strings:
		$s1 = {63 6d 64 2e 65 78 65 20 2f 63 20 25 73 20 3e 20 25 73}
		$s2 = {65 78 65 63 75 74 65 20 63 6d 64 20 74 69 6d 65 6f 75 74 2e}
		$s3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 53 65 74 74 69 6e 67}
		$s4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 20 2d 20 65 78 63 65 70 74 69 6f 6e 3a 25 73 2e}
		$s5 = {43 44 6c 6c 41 70 70 3a 3a 49 6e 69 74 49 6e 73 74 61 6e 63 65 28 29 20 2d 20 45 76 6e 65 74 20 63 72 65 61 74 65 20 73 75 63 63 65 73 73 66 75 6c 2e}
		$s6 = {55 70 6c 6f 61 64 46 69 6c 65 20 2d 20 45 6e 63 72 79 70 74 42 75 66 66 65 72 20 45 72 72 6f 72}
		$s7 = {57 00 69 00 6e 00 44 00 4c 00 4c 00 2e 00 64 00 6c 00 6c 00}
		$s8 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 20 2d 20 65 78 63 65 70 74 69 6f 6e 3a 25 73 2c 63 6f 64 65 3a 30 78 25 30 38 78 2e}
		$s9 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 37 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 29}
		$s10 = {43 44 6c 6c 41 70 70 3a 3a 49 6e 69 74 49 6e 73 74 61 6e 63 65 28 29 20 2d 20 45 76 6e 65 74 20 61 6c 72 65 61 64 79 20 65 78 69 73 74 73 2e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 250KB and 3 of them
}

