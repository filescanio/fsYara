rule apt_nix_elf_derusbi : hardened
{
	meta:
		description = "Detects Derusbi Backdoor ELF"
		author = "Fidelis Cybersecurity"
		date = "2016/02/29"
		modified = "2023-05-04"
		reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
		id = "c825c5d6-1c2f-5ee7-871e-4be3f41d73f7"

	strings:
		$s1 = {4c 78 4d 61 69 6e}
		$s2 = {65 78 65 63 76 65}
		$s3 = {6b 69 6c 6c}
		$s4 = {63 70 20 2d 61 20 25 73 20 25 73}
		$s5 = {25 73 20 26}
		$s6 = {64 62 75 73 2d 64 61 65 6d 6f 6e}
		$s7 = {2d 2d 6e 6f 70 72 6f 66 69 6c 65}
		$s8 = {2d 2d 6e 6f 72 63}
		$s9 = {54 45 52 4d 3d 76 74 31 30 30}
		$s10 = {2f 70 72 6f 63 2f 25 75 2f 63 6d 64 6c 69 6e 65}
		$s11 = {6c 6f 61 64 73 6f}
		$s12 = {2f 70 72 6f 63 2f 73 65 6c 66 2f 65 78 65}
		$s13 = {50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65}
		$s14 = {43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65}
		$s15 = {43 4f 4e 4e 45 43 54 20 25 73}
		$s16 = {48 4f 53 54 3a 20 25 73 3a 25 64}
		$s17 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30}
		$s18 = {50 72 6f 78 79 2d 41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 3a 20 42 61 73 69 63 20 25 73}
		$s19 = {53 65 72 76 65 72 3a 20 41 70 61 63 68 65}
		$s20 = {50 72 6f 78 79 2d 41 75 74 68 65 6e 74 69 63 61 74 65}
		$s21 = {67 65 74 74 69 6d 65 6f 66 64 61 79}
		$s22 = {70 74 68 72 65 61 64 5f 63 72 65 61 74 65}
		$s23 = {70 74 68 72 65 61 64 5f 6a 6f 69 6e}
		$s24 = {70 74 68 72 65 61 64 5f 6d 75 74 65 78 5f 69 6e 69 74}
		$s25 = {70 74 68 72 65 61 64 5f 6d 75 74 65 78 5f 64 65 73 74 72 6f 79}
		$s26 = {70 74 68 72 65 61 64 5f 6d 75 74 65 78 5f 6c 6f 63 6b}
		$s27 = {67 65 74 73 6f 63 6b 6f 70 74}
		$s28 = {73 6f 63 6b 65 74}
		$s29 = {73 65 74 73 6f 63 6b 6f 70 74}
		$s30 = {73 65 6c 65 63 74}
		$s31 = {62 69 6e 64}
		$s32 = {73 68 75 74 64 6f 77 6e}
		$s33 = {6c 69 73 74 65 6e}
		$s34 = {6f 70 65 6e 64 69 72}
		$s35 = {72 65 61 64 64 69 72}
		$s36 = {63 6c 6f 73 65 64 69 72}
		$s37 = {72 65 6e 61 6d 65}

	condition:
		uint32( 0 ) == 0x464c457f and all of them
}

rule apt_nix_elf_derusbi_kernelModule : hardened
{
	meta:
		description = "Detects Derusbi Backdoor ELF Kernel Module"
		author = "Fidelis Cybersecurity"
		date = "2016/02/29"
		modified = "2023-05-04"
		reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
		id = "98196ffc-8a6f-5edc-a688-eeb449410b72"

	strings:
		$s1 = {5f 5f 74 68 69 73 5f 6d 6f 64 75 6c 65}
		$s2 = {69 6e 69 74 5f 6d 6f 64 75 6c 65}
		$s3 = {75 6e 68 69 64 65 5f 70 69 64}
		$s4 = {69 73 5f 68 69 64 64 65 6e 5f 70 69 64}
		$s5 = {63 6c 65 61 72 5f 68 69 64 64 65 6e 5f 70 69 64}
		$s6 = {68 69 64 65 5f 70 69 64}
		$s7 = {6c 69 63 65 6e 73 65}
		$s8 = {64 65 73 63 72 69 70 74 69 6f 6e}
		$s9 = {73 72 63 76 65 72 73 69 6f 6e 3d}
		$s10 = {64 65 70 65 6e 64 73 3d}
		$s12 = {76 65 72 6d 61 67 69 63 3d}
		$s13 = {63 75 72 72 65 6e 74 5f 74 61 73 6b}
		$s14 = {73 6f 63 6b 5f 72 65 6c 65 61 73 65}
		$s15 = {6d 6f 64 75 6c 65 5f 6c 61 79 6f 75 74}
		$s16 = {69 6e 69 74 5f 75 74 73 5f 6e 73}
		$s17 = {69 6e 69 74 5f 6e 65 74}
		$s18 = {69 6e 69 74 5f 74 61 73 6b}
		$s19 = {66 69 6c 70 5f 6f 70 65 6e}
		$s20 = {5f 5f 6e 65 74 6c 69 6e 6b 5f 6b 65 72 6e 65 6c 5f 63 72 65 61 74 65}
		$s21 = {6b 66 72 65 65 5f 73 6b 62}

	condition:
		uint32( 0 ) == 0x464c457f and all of them
}

rule apt_nix_elf_Derusbi_Linux_SharedMemCreation : hardened
{
	meta:
		description = "Detects Derusbi Backdoor ELF Shared Memory Creation"
		author = "Fidelis Cybersecurity"
		date = "2016/02/29"
		reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
		id = "068b7bea-853d-57e8-a9fe-8b451dbc7582"

	strings:
		$byte1 = { B6 03 00 00 ?? 40 00 00 00 ?? 0D 5F 01 82 }

	condition:
		uint32( 0 ) == 0x464C457F and any of them
}

rule apt_nix_elf_Derusbi_Linux_Strings : hardened loosened limited
{
	meta:
		description = "Detects Derusbi Backdoor ELF Strings"
		author = "Fidelis Cybersecurity"
		date = "2016/02/29"
		reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
		id = "06717cc9-678d-5912-a671-65605b9c9968"

	strings:
		$a1 = {((6c 6f 61 64 73 6f) | (6c 00 6f 00 61 00 64 00 73 00 6f 00))}
		$a2 = {((0a 75 6e 61 6d 65 20 2d 61 0a 0a) | (0a 00 75 00 6e 00 61 00 6d 00 65 00 20 00 2d 00 61 00 0a 00 0a 00))}
		$a3 = {((2f 64 65 76 2f 73 68 6d 2f 2e 78 31 31 2e 69 64) | (2f 00 64 00 65 00 76 00 2f 00 73 00 68 00 6d 00 2f 00 2e 00 78 00 31 00 31 00 2e 00 69 00 64 00))}
		$a4 = {((4c 78 4d 61 69 6e 36 34) | (4c 00 78 00 4d 00 61 00 69 00 6e 00 36 00 34 00))}
		$a5 = {((23 20 5c 75 40 5c 68 3a 5c 77 20 5c 24 20) | (23 00 20 00 5c 00 75 00 40 00 5c 00 68 00 3a 00 5c 00 77 00 20 00 5c 00 24 00 20 00))}
		$b1 = {30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00 61 00 62 00 63 00 64 00 65 00 66 00 67 00 68 00 69 00 6a 00 6b 00 6c 00 6d 00 6e 00 6f 00 70 00 71 00 72 00 73 00 74 00 75 00 76 00 77 00 78 00 79 00 7a 00}
		$b2 = {30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00 41 00 42 00 43 00 44 00 45 00 46 00 47 00 48 00 49 00 4a 00 4b 00 4c 00 4d 00 4e 00 4f 00 50 00 51 00 52 00 53 00 54 00 55 00 56 00 57 00 58 00 59 00 5a 00}
		$b3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 72 00 65 00 74 00 20 00 25 00 64 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$b4 = {((75 6e 61 6d 65 20 2d 61 0a 0a) | (75 00 6e 00 61 00 6d 00 65 00 20 00 2d 00 61 00 0a 00 0a 00))}
		$b5 = {((2f 70 72 6f 63 2f 25 75 2f 63 6d 64 6c 69 6e 65) | (2f 00 70 00 72 00 6f 00 63 00 2f 00 25 00 75 00 2f 00 63 00 6d 00 64 00 6c 00 69 00 6e 00 65 00))}
		$b6 = {((2f 70 72 6f 63 2f 73 65 6c 66 2f 65 78 65) | (2f 00 70 00 72 00 6f 00 63 00 2f 00 73 00 65 00 6c 00 66 00 2f 00 65 00 78 00 65 00))}
		$b7 = {((63 70 20 2d 61 20 25 73 20 25 73) | (63 00 70 00 20 00 2d 00 61 00 20 00 25 00 73 00 20 00 25 00 73 00))}
		$c1 = {((2f 64 65 76 2f 70 74 73 2f 34) | (2f 00 64 00 65 00 76 00 2f 00 70 00 74 00 73 00 2f 00 34 00))}
		$c2 = {((2f 74 6d 70 2f 31 34 30 38 2e 6c 6f 67) | (2f 00 74 00 6d 00 70 00 2f 00 31 00 34 00 30 00 38 00 2e 00 6c 00 6f 00 67 00))}

	condition:
		uint32( 0 ) == 0x464C457F and ( ( 1 of ( $a* ) and 4 of ( $b* ) ) or ( 1 of ( $a* ) and 1 of ( $c* ) ) or 2 of ( $a* ) or all of ( $b* ) )
}

rule apt_win_exe_trojan_derusbi : hardened
{
	meta:
		description = "Detects Derusbi Backdoor Win32"
		author = "Fidelis Cybersecurity"
		date = "2016/02/29"
		reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
		id = "6e7fecfa-f801-59b2-a394-df4c368011b7"

	strings:
		$sa_4 = {48 4f 53 54 3a 20 25 73 3a 25 64}
		$sa_6 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61}
		$sa_7 = {50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65}
		$sa_8 = {43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65}
		$sa_9 = {53 65 72 76 65 72 3a 20 41 70 61 63 68 65}
		$sa_12 = {5a 77 55 6e 6c 6f 61 64 44 72 69 76 65 72}
		$sa_13 = {5a 77 4c 6f 61 64 44 72 69 76 65 72}
		$sa_18 = {5f 74 69 6d 65 36 34}
		$sa_19 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}
		$sa_20 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}
		$sa_21 = { 8b [5] 8b ?? d3 ?? 83 ?? 08 30 [5] 40 3b [5] 72 }
		$sb_1 = {50 43 43 5f 43 4d 44 5f 50 41 43 4b 45 54}
		$sb_2 = {50 43 43 5f 43 4d 44}
		$sb_3 = {50 43 43 5f 42 41 53 45 4d 4f 44}
		$sb_4 = {50 43 43 5f 50 52 4f 58 59}
		$sb_5 = {50 43 43 5f 53 59 53}
		$sb_6 = {50 43 43 5f 50 52 4f 43 45 53 53}
		$sb_7 = {50 43 43 5f 46 49 4c 45}
		$sb_8 = {50 43 43 5f 53 4f 43 4b}
		$sc_1 = {((62 63 64 65 64 69 74 20 2d 73 65 74 20 74 65 73 74 73 69 67 6e 69 6e 67) | (62 00 63 00 64 00 65 00 64 00 69 00 74 00 20 00 2d 00 73 00 65 00 74 00 20 00 74 00 65 00 73 00 74 00 73 00 69 00 67 00 6e 00 69 00 6e 00 67 00))}
		$sc_2 = {((75 70 64 61 74 65 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d) | (75 00 70 00 64 00 61 00 74 00 65 00 2e 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00))}
		$sc_3 = {((5f 63 72 74 5f 64 65 62 75 67 67 65 72 5f 68 6f 6f 6b) | (5f 00 63 00 72 00 74 00 5f 00 64 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 5f 00 68 00 6f 00 6f 00 6b 00))}
		$sc_4 = {((75 65 38 47 35) | (75 00 65 00 38 00 47 00 35 00))}
		$sd_2 = {((5c 5c 2e 5c 70 69 70 65 5c 25 73) | (5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 25 00 73 00))}
		$sd_3 = {((2e 64 61 74) | (2e 00 64 00 61 00 74 00))}
		$sd_4 = {((43 4f 4e 4e 45 43 54 20 25 73 3a 25 64) | (43 00 4f 00 4e 00 4e 00 45 00 43 00 54 00 20 00 25 00 73 00 3a 00 25 00 64 00))}
		$sd_5 = {((5c 44 65 76 69 63 65 5c) | (5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00))}
		$se_1 = {((2d 25 73 2d 25 30 34 64) | (2d 00 25 00 73 00 2d 00 25 00 30 00 34 00 64 00))}
		$se_2 = {((2d 25 30 34 64) | (2d 00 25 00 30 00 34 00 64 00))}
		$se_5 = {((32 2e 30 33) | (32 00 2e 00 30 00 33 00))}

	condition:
		uint16( 0 ) == 0x5A4D and ( all of ( $sa_* ) or ( ( 8 of ( $sa_* ) ) and ( ( 5 of ( $sb_* ) ) or ( 3 of ( $sc_* ) ) or ( all of ( $sd_* ) ) or ( 1 of ( $sc_* ) and all of ( $se_* ) ) ) ) )
}

