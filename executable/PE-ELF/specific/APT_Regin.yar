rule Regin_APT_KernelDriver_Generic_A : hardened
{
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		date = "23.11.14"
		hash1 = "187044596bc1328efa0ed636d8aa4a5c"
		hash2 = "06665b96e293b23acc80451abb413e50"
		hash3 = "d240f06e98c8d3e647cbf4d442d79475"
		score = 75

	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 }
		$m1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }
		$s0 = {61 00 74 00 61 00 70 00 69 00 2e 00 73 00 79 00 73 00}
		$s1 = {64 00 69 00 73 00 6b 00 2e 00 73 00 79 00 73 00}
		$s3 = {68 2e 64 61 74 61}
		$s4 = {5c 73 79 73 74 65 6d 33 32}
		$s5 = {5c 53 79 73 74 65 6d 52 6f 6f 74}
		$s6 = {73 79 73 74 65 6d}
		$s7 = {74 65 6d 70}
		$s8 = {77 69 6e 64 6f 77 73}
		$x1 = {4c 52 69 63 68 36}
		$x2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65}

	condition:
		$m0 at 0 and $m1 and all of ( $s* ) and 1 of ( $x* )
}

rule Regin_APT_KernelDriver_Generic_B : hardened limited
{
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		date = "23.11.14"
		hash1 = "ffb0b9b5b610191051a7bdf0806e1e47"
		hash2 = "bfbe8c3ee78750c3a520480700e440f8"
		hash3 = "b29ca4f22ae7b7b25f79c1d4a421139d"
		hash4 = "06665b96e293b23acc80451abb413e50"
		hash5 = "2c8b9d2885543d7ade3cae98225e263b"
		hash6 = "4b6b86c7fec1c574706cecedf44abded"
		hash7 = "187044596bc1328efa0ed636d8aa4a5c"
		hash8 = "d240f06e98c8d3e647cbf4d442d79475"
		hash9 = "6662c390b2bbbd291ec7987388fc75d7"
		hash10 = "1c024e599ac055312a4ab75b3950040a"
		hash11 = "ba7bb65634ce1e30c1e5415be3d1db1d"
		hash12 = "b505d65721bb2453d5039a389113b566"
		hash13 = "b269894f434657db2b15949641a67532"
		score = 75

	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 }
		$s1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }
		$s2 = {48 2e 64 61 74 61}
		$s3 = {49 4e 49 54}
		$s4 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65}
		$v1 = {5c 73 79 73 74 65 6d 33 32}
		$v2 = {5c 53 79 73 74 65 6d 52 6f 6f 74}
		$v3 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65}
		$w1 = {5c 73 79 73 74 65 6d 33 32}
		$w2 = {5c 53 79 73 74 65 6d 52 6f 6f 74}
		$w3 = {4c 52 69 63 68 36}
		$x1 = {5f 73 6e 70 72 69 6e 74 66}
		$x2 = {5f 65 78 63 65 70 74 5f 68 61 6e 64 6c 65 72 33}
		$y1 = {6d 62 73 74 6f 77 63 73}
		$y2 = {77 63 73 74 6f 6d 62 73}
		$y3 = {4b 65 47 65 74 43 75 72 72 65 6e 74 49 72 71 6c}
		$z1 = {77 63 73 63 70 79}
		$z2 = {5a 77 43 72 65 61 74 65 46 69 6c 65}
		$z3 = {5a 77 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 46 69 6c 65}
		$z4 = {77 63 73 6c 65 6e}
		$z5 = {61 74 6f 69}

	condition:
		$m0 at 0 and all of ( $s* ) and ( all of ( $v* ) or all of ( $w* ) or all of ( $x* ) or all of ( $y* ) or all of ( $z* ) ) and filesize < 20KB
}

rule Regin_APT_KernelDriver_Generic_C : hardened
{
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		date = "23.11.14"
		hash1 = "e0895336617e0b45b312383814ec6783556d7635"
		hash2 = "732298fa025ed48179a3a2555b45be96f7079712"
		score = 75

	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 }
		$s0 = {4b 65 47 65 74 43 75 72 72 65 6e 74 49 72 71 6c}
		$s1 = {35 00 2e 00 32 00 2e 00 33 00 37 00 39 00 30 00 2e 00 30 00 20 00 28 00 73 00 72 00 76 00 30 00 33 00 5f 00 72 00 74 00 6d 00 2e 00 30 00 33 00 30 00 33 00 32 00 34 00 2d 00 32 00 30 00 34 00 38 00 29 00}
		$s2 = {75 00 73 00 62 00 63 00 6c 00 61 00 73 00 73 00}
		$x1 = {50 41 44 44 49 4e 47 58 58 50 41 44 44 49 4e 47 50 41 44 44 49 4e 47 58 58 50 41 44 44 49 4e 47 50 41 44 44 49 4e 47 58 58 50 41 44 44 49 4e 47 50 41 44 44 49 4e 47 58 58 50 41 44 44 49 4e 47 50 41 44 44 49 4e 47 58 58 50 41 44 44 49 4e 47}
		$x2 = {55 00 6e 00 69 00 76 00 65 00 72 00 73 00 61 00 6c 00 20 00 53 00 65 00 72 00 69 00 61 00 6c 00 20 00 42 00 75 00 73 00 20 00 43 00 6c 00 61 00 73 00 73 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00}
		$x3 = {35 00 2e 00 32 00 2e 00 33 00 37 00 39 00 30 00 2e 00 30 00}
		$y1 = {4c 00 53 00 41 00 20 00 53 00 68 00 65 00 6c 00 6c 00}
		$y2 = {30 52 69 63 68 77}

	condition:
		$m0 at 0 and all of ( $s* ) and ( all of ( $x* ) or all of ( $y* ) ) and filesize < 20KB
}

rule Regin_sig_svcsstat : hardened
{
	meta:
		description = "Detects svcstat from Regin report - file svcsstat.exe_sample"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "5164edc1d54f10b7cb00a266a1b52c623ab005e2"

	strings:
		$s0 = {53 65 72 76 69 63 65 20 43 6f 6e 74 72 6f 6c 20 4d 61 6e 61 67 65 72}
		$s1 = {5f 76 73 6e 77 70 72 69 6e 74 66}
		$s2 = {52 6f 6f 74 20 41 67 65 6e 63 79}
		$s3 = {52 6f 6f 74 20 41 67 65 6e 63 79 30}
		$s4 = {53 74 61 72 74 53 65 72 76 69 63 65 43 74 72 6c 44 69 73 70 61 74 63 68 65 72 41}
		$s5 = {5c 00 5c 00 3f 00 5c 00 55 00 4e 00 43 00}
		$s6 = {25 00 6c 00 73 00 25 00 6c 00 73 00}

	condition:
		all of them and filesize < 15KB and filesize > 10KB
}

rule Regin_Sample_1 : hardened
{
	meta:
		description = "Auto-generated rule - file-3665415_sys"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "773d7fab06807b5b1bc2d74fa80343e83593caf2"

	strings:
		$s0 = {47 65 74 74 69 6e 67 20 50 6f 72 74 4e 61 6d 65 2f 49 64 65 6e 74 69 66 69 65 72 20 66 61 69 6c 65 64 20 2d 20 25 78}
		$s1 = {53 65 72 69 61 6c 41 64 64 44 65 76 69 63 65 20 2d 20 65 72 72 6f 72 20 63 72 65 61 74 69 6e 67 20 6e 65 77 20 64 65 76 6f 62 6a 20 5b 25 23 30 38 6c 78 5d}
		$s2 = {45 78 74 65 72 6e 61 6c 20 4e 61 6d 69 6e 67 20 46 61 69 6c 65 64 20 2d 20 53 74 61 74 75 73 20 25 78}
		$s3 = {2d 2d 2d 2d 2d 2d 2d 20 53 61 6d 65 20 6d 75 6c 74 69 70 6f 72 74 20 2d 20 64 69 66 66 65 72 65 6e 74 20 69 6e 74 65 72 72 75 70 74 73}
		$s4 = {25 78 20 6f 63 63 75 72 72 65 64 20 70 72 69 6f 72 20 74 6f 20 74 68 65 20 77 61 69 74 20 2d 20 73 74 61 72 74 69 6e 67 20 74 68 65}
		$s5 = {27 75 73 65 72 20 72 65 67 69 73 74 72 79 20 69 6e 66 6f 20 2d 20 75 73 65 72 50 6f 72 74 49 6e 64 65 78 3a 20 25 64}
		$s6 = {43 6f 75 6c 64 20 6e 6f 74 20 72 65 70 6f 72 74 20 6c 65 67 61 63 79 20 64 65 76 69 63 65 20 2d 20 25 78}
		$s7 = {65 6e 74 65 72 69 6e 67 20 53 65 72 69 61 6c 47 65 74 50 6f 72 74 49 6e 66 6f}
		$s8 = {27 75 73 65 72 20 72 65 67 69 73 74 72 79 20 69 6e 66 6f 20 2d 20 75 73 65 72 50 6f 72 74 3a 20 25 78}
		$s9 = {49 6f 4f 70 65 6e 44 65 76 69 63 65 52 65 67 69 73 74 72 79 4b 65 79 20 66 61 69 6c 65 64 20 2d 20 25 78 20}
		$s10 = {4b 65 72 6e 65 6c 20 64 65 62 75 67 67 65 72 20 69 73 20 75 73 69 6e 67 20 70 6f 72 74 20 61 74 20 61 64 64 72 65 73 73 20 25 58}
		$s12 = {52 65 6c 65 61 73 65 20 2d 20 66 72 65 65 69 6e 67 20 6d 75 6c 74 69 20 63 6f 6e 74 65 78 74}
		$s13 = {53 65 72 69 61 6c 20 64 72 69 76 65 72 20 77 69 6c 6c 20 6e 6f 74 20 6c 6f 61 64 20 70 6f 72 74}
		$s14 = {27 75 73 65 72 20 72 65 67 69 73 74 72 79 20 69 6e 66 6f 20 2d 20 75 73 65 72 41 64 64 72 65 73 73 53 70 61 63 65 3a 20 25 64}
		$s15 = {53 65 72 69 61 6c 41 64 64 44 65 76 69 63 65 3a 20 45 6e 75 6d 65 72 61 74 69 6f 6e 20 72 65 71 75 65 73 74 2c 20 72 65 74 75 72 6e 69 6e 67 20 4e 4f 5f 4d 4f 52 45 5f 45 4e 54 52 49 45 53}
		$s20 = {27 75 73 65 72 20 72 65 67 69 73 74 72 79 20 69 6e 66 6f 20 2d 20 75 73 65 72 49 6e 64 65 78 65 64 3a 20 25 64}

	condition:
		all of them and filesize < 110KB and filesize > 80KB
}

rule Regin_Sample_2 : hardened
{
	meta:
		description = "Auto-generated rule - file hiddenmod_hookdisk_and_kdbg_8949d000.bin"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "a7b285d4b896b66fce0ebfcd15db53b3a74a0400"

	strings:
		$s0 = {5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 52 00 4f 00 4f 00 54 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6c 00 73 00 61 00 73 00 73 00 2e 00 65 00 78 00 65 00}
		$s1 = {61 00 74 00 61 00 70 00 69 00 2e 00 73 00 79 00 73 00}
		$s2 = {64 00 69 00 73 00 6b 00 2e 00 73 00 79 00 73 00}
		$s3 = {49 6f 47 65 74 52 65 6c 61 74 65 64 44 65 76 69 63 65 4f 62 6a 65 63 74}
		$s4 = {48 41 4c 2e 64 6c 6c}
		$s5 = {5c 52 65 67 69 73 74 72 79 5c 4d 61 63 68 69 6e 65 5c 53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73}
		$s6 = {50 73 47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 49 64}
		$s7 = {4b 65 47 65 74 43 75 72 72 65 6e 74 49 72 71 6c}
		$s8 = {5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00}
		$s9 = {4b 65 53 65 74 49 6d 70 6f 72 74 61 6e 63 65 44 70 63}
		$s10 = {4b 65 51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72}
		$s14 = {4b 65 49 6e 69 74 69 61 6c 69 7a 65 45 76 65 6e 74}
		$s15 = {4b 65 44 65 6c 61 79 45 78 65 63 75 74 69 6f 6e 54 68 72 65 61 64}
		$s16 = {4b 65 49 6e 69 74 69 61 6c 69 7a 65 54 69 6d 65 72 45 78}
		$s18 = {50 73 4c 6f 6f 6b 75 70 50 72 6f 63 65 73 73 42 79 50 72 6f 63 65 73 73 49 64}
		$s19 = {45 78 52 65 6c 65 61 73 65 46 61 73 74 4d 75 74 65 78 55 6e 73 61 66 65}
		$s20 = {45 78 41 63 71 75 69 72 65 46 61 73 74 4d 75 74 65 78 55 6e 73 61 66 65}

	condition:
		all of them and filesize < 40KB and filesize > 30KB
}

rule Regin_Sample_3 : hardened
{
	meta:
		description = "Detects Regin Backdoor sample fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"
		author = "@Malwrsignatures"
		date = "27.11.14"
		hash = "fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"

	strings:
		$hd = { fe ba dc fe }
		$s0 = {53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 50 00 61 00 63 00 6b 00 20 00 78 00}
		$s1 = {5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00}
		$s2 = {5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 48 00 6f 00 74 00 46 00 69 00 78 00}
		$s3 = {6d 00 6e 00 74 00 6f 00 73 00 6b 00 72 00 6e 00 6c 00 2e 00 65 00 78 00 65 00}
		$s4 = {5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 5c 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00}
		$s5 = {4d 00 65 00 6d 00 6f 00 72 00 79 00 20 00 6c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 20 00 30 00 78 00 25 00 70 00 2c 00 20 00 73 00 69 00 7a 00 65 00 20 00 30 00 78 00 25 00 30 00 38 00 78 00}
		$s6 = {53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 50 00 61 00 63 00 6b 00}
		$s7 = {2e 00 73 00 79 00 73 00}
		$s8 = {2e 00 64 00 6c 00 6c 00}
		$s10 = {5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 55 00 70 00 64 00 61 00 74 00 65 00 73 00}
		$s11 = {49 6f 47 65 74 52 65 6c 61 74 65 64 44 65 76 69 63 65 4f 62 6a 65 63 74}
		$s12 = {56 4d 45 4d 2e 73 79 73}
		$s13 = {52 00 74 00 6c 00 47 00 65 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00}
		$s14 = {6e 74 6b 72 6e 6c 70 61 2e 65 78 65}

	condition:
		($hd at 0 ) and all of ( $s* ) and filesize > 160KB and filesize < 200KB
}

rule Regin_Sample_Set_1 : hardened
{
	meta:
		description = "Auto-generated rule - file SHF-000052 and ndisips.sys"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash1 = "8487a961c8244004c9276979bb4b0c14392fc3b8"
		hash2 = "bcf3461d67b39a427c83f9e39b9833cfec977c61"

	strings:
		$s0 = {48 41 4c 2e 64 6c 6c}
		$s1 = {49 6f 47 65 74 44 65 76 69 63 65 4f 62 6a 65 63 74 50 6f 69 6e 74 65 72}
		$s2 = {4d 00 61 00 78 00 69 00 6d 00 75 00 6d 00 50 00 6f 00 72 00 74 00 73 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 64 00}
		$s3 = {4b 65 47 65 74 43 75 72 72 65 6e 74 49 72 71 6c}
		$s4 = {6e 74 6b 72 6e 6c 70 61 2e 65 78 65}
		$s5 = {5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00}
		$s6 = {43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 4d 00 75 00 6c 00 74 00 69 00 70 00 6c 00 65 00 50 00 6f 00 72 00 74 00 73 00}
		$s7 = {5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 52 00 4f 00 4f 00 54 00}
		$s8 = {49 6f 57 72 69 74 65 45 72 72 6f 72 4c 6f 67 45 6e 74 72 79}
		$s9 = {4b 65 51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72}
		$s10 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65}
		$s11 = {4b 65 52 65 6d 6f 76 65 45 6e 74 72 79 44 65 76 69 63 65 51 75 65 75 65}
		$s12 = {53 65 53 69 6e 67 6c 65 50 72 69 76 69 6c 65 67 65 43 68 65 63 6b}
		$s13 = {4b 65 49 6e 69 74 69 61 6c 69 7a 65 45 76 65 6e 74}
		$s14 = {49 6f 42 75 69 6c 64 44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c 52 65 71 75 65 73 74}
		$s15 = {4b 65 52 65 6d 6f 76 65 44 65 76 69 63 65 51 75 65 75 65}
		$s16 = {49 6f 66 43 6f 6d 70 6c 65 74 65 52 65 71 75 65 73 74}
		$s17 = {4b 65 49 6e 69 74 69 61 6c 69 7a 65 53 70 69 6e 4c 6f 63 6b}
		$s18 = {4d 6d 49 73 4e 6f 6e 50 61 67 65 64 53 79 73 74 65 6d 41 64 64 72 65 73 73 56 61 6c 69 64}
		$s19 = {49 6f 43 72 65 61 74 65 44 65 76 69 63 65}
		$s20 = {4b 65 66 52 65 6c 65 61 73 65 53 70 69 6e 4c 6f 63 6b 46 72 6f 6d 44 70 63 4c 65 76 65 6c}

	condition:
		all of them and filesize < 40KB and filesize > 30KB
}

rule Regin_Sample_Set_2 : hardened
{
	meta:
		description = "Detects Regin Backdoor sample 4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be and e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935"
		author = "@MalwrSignatures"
		date = "27.11.14"
		hash1 = "4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be"
		hash2 = "e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935"

	strings:
		$hd = { fe ba dc fe }
		$s0 = {64 00 25 00 6c 00 73 00 25 00 6c 00 73 00}
		$s1 = {5c 00 5c 00 3f 00 5c 00 55 00 4e 00 43 00}
		$s2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00}
		$s3 = {5c 00 5c 00 3f 00 5c 00 55 00 4e 00 43 00 5c 00}
		$s4 = {53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 43 00 6c 00 61 00 73 00 73 00 5c 00 7b 00 34 00 44 00 33 00 36 00 45 00 39 00 37 00 32 00 2d 00 45 00 33 00 32 00 35 00 2d 00 31 00 31 00 43 00 45 00 2d 00 42 00 46 00 43 00 31 00 2d 00 30 00 38 00 30 00 30 00 32 00 42 00 45 00 31 00 30 00 33 00 31 00 38 00 7d 00}
		$s5 = {53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 54 00 63 00 70 00 69 00 70 00 5c 00 4c 00 69 00 6e 00 6b 00 61 00 67 00 65 00}
		$s6 = {5c 00 5c 00 2e 00 5c 00 47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 25 00 73 00}
		$s7 = {74 00 65 00 6d 00 70 00}
		$s8 = {5c 00 5c 00 2e 00 5c 00 25 00 73 00}
		$s9 = {4d 00 65 00 6d 00 6f 00 72 00 79 00 20 00 6c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 20 00 30 00 78 00 25 00 70 00 2c 00 20 00 73 00 69 00 7a 00 65 00 20 00 30 00 78 00 25 00 30 00 38 00 78 00}
		$s10 = {73 73 63 61 6e 66}
		$s11 = {64 69 73 70 2e 64 6c 6c}
		$s12 = {25 78 3a 25 78 3a 25 78 3a 25 78 3a 25 78 3a 25 78 3a 25 78 3a 25 78 25 63}
		$s13 = {25 64 2e 25 64 2e 25 64 2e 25 64 25 63}
		$s14 = {69 6d 61 67 65 68 6c 70 2e 64 6c 6c}
		$s15 = {25 68 64 20 25 64}

	condition:
		($hd at 0 ) and all of ( $s* ) and filesize < 450KB and filesize > 360KB
}

rule apt_regin_legspin : hardened
{
	meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Regin's Legspin module"
		version = "1.0"
		last_modified = "2015-01-22"
		reference = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
		md5 = "29105f46e4d33f66fee346cfd099d1cc"

	strings:
		$mz = {4d 5a}
		$a1 = {73 68 61 72 65 70 77}
		$a2 = {72 65 67 6c 69 73 74}
		$a3 = {6c 6f 67 64 75 6d 70}
		$a4 = {4e 00 61 00 6d 00 65 00 3a 00}
		$a5 = {50 68 79 73 20 41 76 61 69 6c 3a}
		$a6 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}
		$a7 = {70 00 69 00 6e 00 67 00 2e 00 65 00 78 00 65 00}
		$a8 = {6d 69 6c 6c 69 73 65 63 73}

	condition:
		($mz at 0 ) and all of ( $a* )
}

rule apt_regin_hopscotch : hardened
{
	meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Regin's Hopscotch module"
		version = "1.0"
		last_modified = "2015-01-22"
		reference = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
		md5 = "6c34031d7a5fc2b091b623981a8ae61c"

	strings:
		$mz = {4d 5a}
		$a1 = {41 75 74 68 65 6e 74 69 63 61 74 65 4e 65 74 55 73 65 49 70 63}
		$a2 = {46 61 69 6c 65 64 20 74 6f 20 61 75 74 68 65 6e 74 69 63 61 74 65 20 74 6f}
		$a3 = {46 61 69 6c 65 64 20 74 6f 20 64 69 73 63 6f 6e 6e 65 63 74 20 66 72 6f 6d}
		$a4 = {25 00 53 00 5c 00 69 00 70 00 63 00 24 00}
		$a5 = {4e 6f 74 20 64 65 6c 65 74 69 6e 67 2e 2e 2e}
		$a6 = {43 6f 70 79 53 65 72 76 69 63 65 54 6f 52 65 6d 6f 74 65 4d 61 63 68 69 6e 65}
		$a7 = {44 48 20 45 78 63 68 61 6e 67 65 20 66 61 69 6c 65 64}
		$a8 = {43 6f 6e 6e 65 63 74 54 6f 4e 61 6d 65 64 50 69 70 65 73}

	condition:
		($mz at 0 ) and all of ( $a* )
}

rule apt_regin_2011_32bit_stage1 : hardened
{
	meta:
		copyright = "Kaspersky Lab"
		score = 50
		description = "Rule to detect Regin 32 bit stage 1 loaders"
		version = "1.0"
		last_modified = "2014-11-18"

	strings:
		$key1 = {331015EA261D38A7}
		$key2 = {9145A98BA37617DE}
		$key3 = {EF745F23AA67243D}
		$mz = {4d 5a}

	condition:
		($mz at 0 ) and any of ( $key* ) and filesize < 300000
}

rule apt_regin_rc5key : hardened
{
	meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Regin RC5 decryption keys"
		version = "1.0"
		last_modified = "2014-11-18"

	strings:
		$key1 = {73 23 1F 43 93 E1 9F 2F 99 0C 17 81 5C FF B4 01}
		$key2 = {10 19 53 2A 11 ED A3 74 3F C3 72 3F 9D 94 3D 78}

	condition:
		any of ( $key* )
}

rule apt_regin_vfs : hardened
{
	meta:
		copyright = "Kaspersky Lab"
		author = "Kaspersky Lab"
		description = "Rule to detect Regin VFSes"
		version = "1.0"
		last_modified = "2014-11-18"

	strings:
		$a1 = {00 02 00 08 00 08 03 F6 D7 F3 52}
		$a2 = {00 10 F0 FF F0 FF 11 C7 7F E8 52}
		$a3 = {00 04 00 10 00 10 03 C2 D3 1C 93}
		$a4 = {00 04 00 10 C8 00 04 C8 93 06 D8}

	condition:
		($a1 at 0 ) or ( $a2 at 0 ) or ( $a3 at 0 ) or ( $a4 at 0 )
}

rule apt_regin_dispatcher_disp_dll : hardened
{
	meta:
		copyright = "Kaspersky Lab"
		author = "Kaspersky Lab"
		description = "Rule to detect Regin disp.dll dispatcher"
		version = "1.0"
		last_modified = "2014-11-18"

	strings:
		$mz = {4d 5a}
		$string1 = {73 68 69 74}
		$string2 = {64 69 73 70 2e 64 6c 6c}
		$string3 = {32 35 35 2e 32 35 35 2e 32 35 35 2e 32 35 35}
		$string4 = {53 74 61 63 6b 57 61 6c 6b 36 34}
		$string5 = {69 6d 61 67 65 68 6c 70 2e 64 6c 6c}

	condition:
		($mz at 0 ) and ( all of ( $string* ) )
}

rule apt_regin_2013_64bit_stage1 : hardened
{
	meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Regin 64 bit stage 1 loaders"
		version = "1.0"
		last_modified = "2014-11-18"
		filename = "wshnetc.dll"
		md5 = "bddf5afbea2d0eed77f2ad4e9a4f044d"
		filename = "wsharp.dll"
		md5 = "c053a0a3f1edcbbfc9b51bc640e808ce"

	strings:
		$mz = {4d 5a}
		$a1 = {50 52 49 56 48 45 41 44}
		$a2 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64}
		$a3 = {5a 77 44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c 46 69 6c 65}

	condition:
		($mz at 0 ) and ( all of ( $a* ) ) and filesize < 100000
}

