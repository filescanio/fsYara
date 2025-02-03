rule APT_MAL_Win_BlueLight_B : InkySquid hardened
{
	meta:
		author = "threatintel@volexity.com"
		description = "North Korean origin malware which uses a custom Google App for c2 communications."
		date = "2021-06-21"
		hash1 = "837eaf7b736583497afb8bbdb527f70577901eff04cc69d807983b233524bfed"
		license = "See license at https://github.com/volexity/threat-intel/LICENSE.txt"
		reference = "https://www.volexity.com/blog/2021/08/17/north-korean-apt-inkysquid-infects-victims-using-browser-exploits/"
		id = "3ec2d44c-4c08-514d-a839-acef3f53f7dc"

	strings:
		$magic = {68 6f 73 74 5f 6e 61 6d 65 3a 20 25 6c 73 2c 20 63 6f 6f 6b 69 65 5f 6e 61 6d 65 3a 20 25 73 2c 20 63 6f 6f 6b 69 65 3a 20 25 73 2c 20 43 54 3a 20 25 6c 6c 75 2c 20 45 54 3a 20 25 6c 6c 75 2c 20 76 61 6c 75 65 3a 20 25 73 2c 20 70 61 74 68 3a 20 25 6c 73 2c 20 73 65 63 75 3a 20 25 64 2c 20 68 74 74 70 3a 20 25 64 2c 20 6c 61 73 74 3a 20 25 6c 6c 75 2c 20 68 61 73 3a 20 25 64}
		$f1 = {25 00 6c 00 73 00 2e 00 49 00 4e 00 54 00 45 00 47 00 2e 00 52 00 41 00 57 00}
		$f2 = {65 64 62 2e 63 68 6b}
		$f3 = {65 64 62 2e 6c 6f 67}
		$f4 = {65 64 62 72 65 73 30 30 30 30 31 2e 6a 72 73}
		$f5 = {65 64 62 72 65 73 30 30 30 30 32 2e 6a 72 73}
		$f6 = {65 64 62 74 6d 70 2e 6c 6f 67}
		$f7 = {63 68 65 56 30 31 2e 64 61 74}
		$chrome1 = {46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 63 68 72 6f 6d 65 20 63 6f 6f 6b 69 65}
		$chrome2 = {6d 61 69 6c 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2c 20 63 6f 6f 6b 69 65 5f 6e 61 6d 65 3a 20 4f 53 49 44}
		$chrome3 = {2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2c 20 63 6f 6f 6b 69 65 5f 6e 61 6d 65 3a 20 53 49 44 2c}
		$chrome4 = {2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2c 20 63 6f 6f 6b 69 65 5f 6e 61 6d 65 3a 20 5f 5f 53 65 63 75 72 65 2d 33 50 53 49 44 2c}
		$chrome5 = {46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 45 64 67 65 20 63 6f 6f 6b 69 65}
		$chrome6 = {67 6f 6f 67 6c 65 2e 63 6f 6d 2c 20 63 6f 6f 6b 69 65 5f 6e 61 6d 65 3a 20 53 49 44 2c}
		$chrome7 = {67 6f 6f 67 6c 65 2e 63 6f 6d 2c 20 63 6f 6f 6b 69 65 5f 6e 61 6d 65 3a 20 5f 5f 53 65 63 75 72 65 2d 33 50 53 49 44 2c}
		$chrome8 = {46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 4e 65 77 20 45 64 67 65 20 63 6f 6f 6b 69 65}
		$chrome9 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 31 30 2e 30 3b 20 57 69 6e 36 34 3b 20 78 36 34 3b 20 72 76 3a 38 30 2e 30 29 20 47 65 63 6b 6f 2f 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6f 78 2f 38 30 2e 30}
		$chrome10 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 3b 63 68 61 72 73 65 74 3d 75 74 66 2d 38}
		$chrome11 = {43 6f 6f 6b 69 65 3a 20 53 49 44 3d 25 73 3b 20 4f 53 49 44 3d 25 73 3b 20 5f 5f 53 65 63 75 72 65 2d 33 50 53 49 44 3d 25 73}
		$chrome12 = {68 74 74 70 73 3a 2f 2f 6d 61 69 6c 2e 67 6f 6f 67 6c 65 2e 63 6f 6d}
		$chrome13 = {72 65 73 75 6c 74 2e 68 74 6d 6c}
		$chrome14 = {47 4d 5f 41 43 54 49 4f 4e 5f 54 4f 4b 45 4e}
		$chrome15 = {47 4d 5f 49 44 5f 4b 45 59 3d}
		$chrome16 = {2f 6d 61 69 6c 2f 75 2f 30 2f 3f 69 6b 3d 25 73 26 61 74 3d 25 73 26 76 69 65 77 3d 75 70 26 61 63 74 3d 70 72 65 66 73}
		$chrome17 = {70 5f 62 78 5f 69 65 3d 31}
		$chrome18 = {6d 79 61 63 63 6f 75 6e 74 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2c 20 63 6f 6f 6b 69 65 5f 6e 61 6d 65 3a 20 4f 53 49 44}
		$chrome19 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 6b 6f 2d 4b 52 2c 6b 6f 3b 71 3d 30 2e 38 2c 65 6e 2d 55 53 3b 71 3d 30 2e 35 2c 65 6e 3b 71 3d 30 2e 33}
		$chrome20 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 3b 63 68 61 72 73 65 74 3d 75 74 66 2d 38}
		$chrome21 = {43 6f 6f 6b 69 65 3a 20 53 49 44 3d 25 73 3b 20 4f 53 49 44 3d 25 73 3b 20 5f 5f 53 65 63 75 72 65 2d 33 50 53 49 44 3d 25 73}
		$chrome22 = {68 74 74 70 73 3a 2f 2f 6d 79 61 63 63 6f 75 6e 74 2e 67 6f 6f 67 6c 65 2e 63 6f 6d}
		$chrome23 = {72 65 73 75 6c 74 2e 68 74 6d 6c}
		$chrome24 = {6d 79 61 63 63 6f 75 6e 74 2e 67 6f 6f 67 6c 65 2e 63 6f 6d}
		$chrome25 = {2f 5f 2f 41 63 63 6f 75 6e 74 53 65 74 74 69 6e 67 73 55 69 2f 64 61 74 61 2f 62 61 74 63 68 65 78 65 63 75 74 65}
		$chrome26 = {66 2e 72 65 71 3d 25 35 42 25 35 42 25 35 42 25 32 32 42 71 4c 64 73 64 25 32 32 25 32 43 25 32 32 25 35 42 74 72 75 65 25 35 44 25 32 32 25 32 43 6e 75 6c 6c 25 32 43 25 32 32 67 65 6e 65 72 69 63 25 32 32 25 35 44 25 35 44 25 35 44 26 61 74 3d}
		$chrome27 = {72 65 73 70 6f 6e 73 65 2e 68 74 6d 6c}
		$msg1 = {68 74 74 70 73 5f 73 74 61 74 75 73 20 69 73 20 25 73}
		$msg2 = {53 75 63 63 65 73 73 20 74 6f 20 66 69 6e 64 20 47 4d 5f 41 43 54 49 4f 4e 5f 54 4f 4b 45 4e 20 61 6e 64 20 47 4d 5f 49 44 5f 4b 45 59}
		$msg3 = {46 61 69 6c 65 64 20 74 6f 20 66 69 6e 64 20 47 4d 5f 41 43 54 49 4f 4e 5f 54 4f 4b 45 4e 20 61 6e 64 20 47 4d 5f 49 44 5f 4b 45 59}
		$msg4 = {46 61 69 6c 65 64 20 48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 20 74 6f 20 6d 61 69 6c 2e 67 6f 6f 67 6c 65 2e 63 6f 6d}
		$msg5 = {53 75 63 63 65 73 73 20 74 6f 20 65 6e 61 62 6c 65 20 69 6d 61 70}
		$msg6 = {46 61 69 6c 65 64 20 74 6f 20 65 6e 61 62 6c 65 20 69 6d 61 70}
		$msg7 = {53 75 63 63 65 73 73 20 74 6f 20 66 69 6e 64 20 53 4e 6c 4d 30 65}
		$msg8 = {46 61 69 6c 65 64 20 74 6f 20 66 69 6e 64 20 53 4e 6c 4d 30 65}
		$msg9 = {46 61 69 6c 65 64 20 48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 20 74 6f 20 6d 79 61 63 63 6f 75 6e 74 2e 67 6f 6f 67 6c 65 2e 63 6f 6d}
		$msg10 = {53 75 63 63 65 73 73 20 74 6f 20 65 6e 61 62 6c 65 20 74 68 75 6e 64 65 72 20 61 63 63 65 73 73}
		$msg11 = {46 61 69 6c 65 64 20 74 6f 20 65 6e 61 62 6c 65 20 74 68 75 6e 64 65 72 20 61 63 63 65 73 73}
		$keylogger_component1 = {5b 54 41 42 5d}
		$keylogger_component2 = {5b 52 45 54 55 52 4e 5d}
		$keylogger_component3 = {50 41 55 53 45}
		$keylogger_component4 = {5b 45 53 43 5d}
		$keylogger_component5 = {5b 50 41 47 45 20 55 50 5d}
		$keylogger_component6 = {5b 50 41 47 45 20 44 4f 57 4e 5d}
		$keylogger_component7 = {5b 45 4e 44 5d}
		$keylogger_component8 = {5b 48 4f 4d 45 5d}
		$keylogger_component9 = {5b 41 52 52 4f 57 20 4c 45 46 54 5d}
		$keylogger_component10 = {5b 41 52 52 4f 57 20 55 50 5d}
		$keylogger_component11 = {5b 41 52 52 4f 57 20 52 49 47 48 54 5d}
		$keylogger_component12 = {5b 41 52 52 4f 57 20 44 4f 57 4e 5d}
		$keylogger_component13 = {5b 49 4e 53 5d}
		$keylogger_component14 = {5b 44 45 4c 5d}
		$keylogger_component15 = {5b 57 49 4e 5d}
		$keylogger_component16 = {5b 4e 55 4d 20 2a 5d}
		$keylogger_component17 = {5b 4e 55 4d 20 2b 5d}
		$keylogger_component18 = {5b 4e 55 4d 20 2c 5d}
		$keylogger_component19 = {5b 4e 55 4d 20 2d 5d}
		$keylogger_component20 = {5b 4e 55 4d 20 2e 5d}
		$keylogger_component21 = {4e 55 4d 20 2f 5d}
		$keylogger_component22 = {5b 4e 55 4d 4c 4f 43 4b 5d}
		$keylogger_component23 = {5b 53 43 52 4f 4c 4c 4c 4f 43 4b 5d}
		$keylogger_component24 = {54 69 6d 65 3a 20}
		$keylogger_component25 = {57 69 6e 64 6f 77 3a 20}
		$keylogger_component26 = {43 41 50 53 4c 4f 43 4b 2b}
		$keylogger_component27 = {53 48 49 46 54 2b}
		$keylogger_component28 = {43 54 52 4c 2b}
		$keylogger_component29 = {41 4c 54 2b}

	condition:
		$magic or ( all of ( $f* ) and 5 of ( $keylogger_component* ) ) or 24 of ( $chrome* ) or 4 of ( $msg* ) or 27 of ( $keylogger_component* )
}

rule APT_MAL_Win_BlueLight : InkySquid hardened
{
	meta:
		author = "threatintel@volexity.com"
		date = "2021-04-23"
		description = "The BLUELIGHT malware family. Leverages Microsoft OneDrive for network communications."
		hash1 = "7c40019c1d4cef2ffdd1dd8f388aaba537440b1bffee41789c900122d075a86d"
		hash2 = "94b71ee0861cc7cfbbae53ad2e411a76f296fd5684edf6b25ebe79bf6a2a600a"
		license = "See license at https://github.com/volexity/threat-intel/LICENSE.txt"
		reference = "https://www.volexity.com/blog/2021/08/17/north-korean-apt-inkysquid-infects-victims-using-browser-exploits/"
		id = "3ec2d44c-4c08-514d-a839-acef3f53f7dc"

	strings:
		$pdb1 = {5c 44 65 76 65 6c 6f 70 6d 65 6e 74 5c 42 41 43 4b 44 4f 4f 52 5c 6e 63 6f 76 5c}
		$pdb2 = {52 65 6c 65 61 73 65 5c 62 6c 75 65 6c 69 67 68 74 2e 70 64 62}
		$msg0 = {68 74 74 70 73 3a 2f 2f 69 70 69 6e 66 6f 2e 69 6f}
		$msg1 = {63 6f 75 6e 74 72 79}
		$msg5 = {22 55 73 65 72 4e 61 6d 65 22 3a 22}
		$msg7 = {22 43 6f 6d 4e 61 6d 65 22 3a 22}
		$msg8 = {22 4f 53 22 3a 22}
		$msg9 = {22 4f 6e 6c 69 6e 65 49 50 22 3a 22}
		$msg10 = {22 4c 6f 63 61 6c 49 50 22 3a 22}
		$msg11 = {22 54 69 6d 65 22 3a 22}
		$msg12 = {22 43 6f 6d 70 69 6c 65 64 22 3a 22}
		$msg13 = {22 50 72 6f 63 65 73 73 20 4c 65 76 65 6c 22 3a 22}
		$msg14 = {22 41 6e 74 69 56 69 72 75 73 22 3a 22}
		$msg15 = {22 56 4d 22 3a 22}

	condition:
		any of ( $pdb* ) or all of ( $msg* )
}

