rule SUSP_XORed_Mozilla : hardened limited
{
	meta:
		description = "Detects suspicious single byte XORed keyword 'Mozilla/5.0' - it uses yara's XOR modifier and therefore cannot print the XOR key. You can use the CyberChef recipe linked in the reference field to brute force the used key."
		author = "Florian Roth"
		reference = "https://gchq.github.io/CyberChef/#recipe=XOR_Brute_Force()"
		date = "2019-10-28"
		modified = "2023-11-25"
		score = 65
		id = "af7fc551-0d4e-589e-9152-95d9c4ab03bf"

	strings:
		$xo1 = {(( 4c 6e 7b 68 6d 6d 60 2e 34 2f 31) |( 4f 6d 78 6b 6e 6e 63 2d 37 2c 32) |( 4e 6c 79 6a 6f 6f 62 2c 36 2d 33) |( 49 6b 7e 6d 68 68 65 2b 31 2a 34) |( 48 6a 7f 6c 69 69 64 2a 30 2b 35) |( 4b 69 7c 6f 6a 6a 67 29 33 28 36) |( 4a 68 7d 6e 6b 6b 66 28 32 29 37) |( 45 67 72 61 64 64 69 27 3d 26 38) |( 44 66 73 60 65 65 68 26 3c 27 39) |( 47 65 70 63 66 66 6b 25 3f 24 3a) |( 46 64 71 62 67 67 6a 24 3e 25 3b) |( 41 63 76 65 60 60 6d 23 39 22 3c) |( 40 62 77 64 61 61 6c 22 38 23 3d) |( 43 61 74 67 62 62 6f 21 3b 20 3e) |( 42 60 75 66 63 63 6e 20 3a 21 3f) |( 5d 7f 6a 79 7c 7c 71 3f 25 3e 20) |( 5c 7e 6b 78 7d 7d 70 3e 24 3f 21) |( 5f 7d 68 7b 7e 7e 73 3d 27 3c 22) |( 5e 7c 69 7a 7f 7f 72 3c 26 3d 23) |( 59 7b 6e 7d 78 78 75 3b 21 3a 24) |( 58 7a 6f 7c 79 79 74 3a 20 3b 25) |( 5b 79 6c 7f 7a 7a 77 39 23 38 26) |( 5a 78 6d 7e 7b 7b 76 38 22 39 27) |( 55 77 62 71 74 74 79 37 2d 36 28) |( 54 76 63 70 75 75 78 36 2c 37 29) |( 57 75 60 73 76 76 7b 35 2f 34 2a) |( 56 74 61 72 77 77 7a 34 2e 35 2b) |( 51 73 66 75 70 70 7d 33 29 32 2c) |( 50 72 67 74 71 71 7c 32 28 33 2d) |( 53 71 64 77 72 72 7f 31 2b 30 2e) |( 52 70 65 76 73 73 7e 30 2a 31 2f)  | ( 4c 01 6e 01 7b 01 68 01 6d 01 6d 01 60 01 2e 01 34 01 2f 01 31 01) |( 4f 02 6d 02 78 02 6b 02 6e 02 6e 02 63 02 2d 02 37 02 2c 02 32 02) |( 4e 03 6c 03 79 03 6a 03 6f 03 6f 03 62 03 2c 03 36 03 2d 03 33 03) |( 49 04 6b 04 7e 04 6d 04 68 04 68 04 65 04 2b 04 31 04 2a 04 34 04) |( 48 05 6a 05 7f 05 6c 05 69 05 69 05 64 05 2a 05 30 05 2b 05 35 05) |( 4b 06 69 06 7c 06 6f 06 6a 06 6a 06 67 06 29 06 33 06 28 06 36 06) |( 4a 07 68 07 7d 07 6e 07 6b 07 6b 07 66 07 28 07 32 07 29 07 37 07) |( 45 08 67 08 72 08 61 08 64 08 64 08 69 08 27 08 3d 08 26 08 38 08) |( 44 09 66 09 73 09 60 09 65 09 65 09 68 09 26 09 3c 09 27 09 39 09) |( 47 0a 65 0a 70 0a 63 0a 66 0a 66 0a 6b 0a 25 0a 3f 0a 24 0a 3a 0a) |( 46 0b 64 0b 71 0b 62 0b 67 0b 67 0b 6a 0b 24 0b 3e 0b 25 0b 3b 0b) |( 41 0c 63 0c 76 0c 65 0c 60 0c 60 0c 6d 0c 23 0c 39 0c 22 0c 3c 0c) |( 40 0d 62 0d 77 0d 64 0d 61 0d 61 0d 6c 0d 22 0d 38 0d 23 0d 3d 0d) |( 43 0e 61 0e 74 0e 67 0e 62 0e 62 0e 6f 0e 21 0e 3b 0e 20 0e 3e 0e) |( 42 0f 60 0f 75 0f 66 0f 63 0f 63 0f 6e 0f 20 0f 3a 0f 21 0f 3f 0f) |( 5d 10 7f 10 6a 10 79 10 7c 10 7c 10 71 10 3f 10 25 10 3e 10 20 10) |( 5c 11 7e 11 6b 11 78 11 7d 11 7d 11 70 11 3e 11 24 11 3f 11 21 11) |( 5f 12 7d 12 68 12 7b 12 7e 12 7e 12 73 12 3d 12 27 12 3c 12 22 12) |( 5e 13 7c 13 69 13 7a 13 7f 13 7f 13 72 13 3c 13 26 13 3d 13 23 13) |( 59 14 7b 14 6e 14 7d 14 78 14 78 14 75 14 3b 14 21 14 3a 14 24 14) |( 58 15 7a 15 6f 15 7c 15 79 15 79 15 74 15 3a 15 20 15 3b 15 25 15) |( 5b 16 79 16 6c 16 7f 16 7a 16 7a 16 77 16 39 16 23 16 38 16 26 16) |( 5a 17 78 17 6d 17 7e 17 7b 17 7b 17 76 17 38 17 22 17 39 17 27 17) |( 55 18 77 18 62 18 71 18 74 18 74 18 79 18 37 18 2d 18 36 18 28 18) |( 54 19 76 19 63 19 70 19 75 19 75 19 78 19 36 19 2c 19 37 19 29 19) |( 57 1a 75 1a 60 1a 73 1a 76 1a 76 1a 7b 1a 35 1a 2f 1a 34 1a 2a 1a) |( 56 1b 74 1b 61 1b 72 1b 77 1b 77 1b 7a 1b 34 1b 2e 1b 35 1b 2b 1b) |( 51 1c 73 1c 66 1c 75 1c 70 1c 70 1c 7d 1c 33 1c 29 1c 32 1c 2c 1c) |( 50 1d 72 1d 67 1d 74 1d 71 1d 71 1d 7c 1d 32 1d 28 1d 33 1d 2d 1d) |( 53 1e 71 1e 64 1e 77 1e 72 1e 72 1e 7f 1e 31 1e 2b 1e 30 1e 2e 1e) |( 52 1f 70 1f 65 1f 76 1f 73 1f 73 1f 7e 1f 30 1f 2a 1f 31 1f 2f 1f) )}
		$fp1 = {53 00 65 00 6e 00 74 00 69 00 6e 00 65 00 6c 00 20 00 4c 00 61 00 62 00 73 00}
		$fp2 = {3c 66 69 6c 74 65 72 20 6f 62 6a 65 63 74 20 61 74}

	condition:
		$xo1 and not 1 of ( $fp* ) and not uint32( 0 ) == 0x434d5953
}

rule SUSP_XORed_MSDOS_Stub_Message : hardened limited
{
	meta:
		description = "Detects suspicious XORed MSDOS stub message"
		author = "Florian Roth"
		reference = "https://yara.readthedocs.io/en/latest/writingrules.html#xor-strings"
		date = "2019-10-28"
		modified = "2023-10-11"
		score = 55
		id = "9ab52434-9162-5fd5-bf34-8b163f6aeec4"

	strings:
		$xo1 = {(( 55 69 68 72 21 71 73 6e 66 73 60 6c 21 62 60 6f 6f 6e 75 21 63 64 21 73 74 6f 21 68 6f 21 45 4e 52 21 6c 6e 65 64) |( 56 6a 6b 71 22 72 70 6d 65 70 63 6f 22 61 63 6c 6c 6d 76 22 60 67 22 70 77 6c 22 6b 6c 22 46 4d 51 22 6f 6d 66 67) |( 57 6b 6a 70 23 73 71 6c 64 71 62 6e 23 60 62 6d 6d 6c 77 23 61 66 23 71 76 6d 23 6a 6d 23 47 4c 50 23 6e 6c 67 66) |( 50 6c 6d 77 24 74 76 6b 63 76 65 69 24 67 65 6a 6a 6b 70 24 66 61 24 76 71 6a 24 6d 6a 24 40 4b 57 24 69 6b 60 61) |( 51 6d 6c 76 25 75 77 6a 62 77 64 68 25 66 64 6b 6b 6a 71 25 67 60 25 77 70 6b 25 6c 6b 25 41 4a 56 25 68 6a 61 60) |( 52 6e 6f 75 26 76 74 69 61 74 67 6b 26 65 67 68 68 69 72 26 64 63 26 74 73 68 26 6f 68 26 42 49 55 26 6b 69 62 63) |( 53 6f 6e 74 27 77 75 68 60 75 66 6a 27 64 66 69 69 68 73 27 65 62 27 75 72 69 27 6e 69 27 43 48 54 27 6a 68 63 62) |( 5c 60 61 7b 28 78 7a 67 6f 7a 69 65 28 6b 69 66 66 67 7c 28 6a 6d 28 7a 7d 66 28 61 66 28 4c 47 5b 28 65 67 6c 6d) |( 5d 61 60 7a 29 79 7b 66 6e 7b 68 64 29 6a 68 67 67 66 7d 29 6b 6c 29 7b 7c 67 29 60 67 29 4d 46 5a 29 64 66 6d 6c) |( 5e 62 63 79 2a 7a 78 65 6d 78 6b 67 2a 69 6b 64 64 65 7e 2a 68 6f 2a 78 7f 64 2a 63 64 2a 4e 45 59 2a 67 65 6e 6f) |( 5f 63 62 78 2b 7b 79 64 6c 79 6a 66 2b 68 6a 65 65 64 7f 2b 69 6e 2b 79 7e 65 2b 62 65 2b 4f 44 58 2b 66 64 6f 6e) |( 58 64 65 7f 2c 7c 7e 63 6b 7e 6d 61 2c 6f 6d 62 62 63 78 2c 6e 69 2c 7e 79 62 2c 65 62 2c 48 43 5f 2c 61 63 68 69) |( 59 65 64 7e 2d 7d 7f 62 6a 7f 6c 60 2d 6e 6c 63 63 62 79 2d 6f 68 2d 7f 78 63 2d 64 63 2d 49 42 5e 2d 60 62 69 68) |( 5a 66 67 7d 2e 7e 7c 61 69 7c 6f 63 2e 6d 6f 60 60 61 7a 2e 6c 6b 2e 7c 7b 60 2e 67 60 2e 4a 41 5d 2e 63 61 6a 6b) |( 5b 67 66 7c 2f 7f 7d 60 68 7d 6e 62 2f 6c 6e 61 61 60 7b 2f 6d 6a 2f 7d 7a 61 2f 66 61 2f 4b 40 5c 2f 62 60 6b 6a) |( 44 78 79 63 30 60 62 7f 77 62 71 7d 30 73 71 7e 7e 7f 64 30 72 75 30 62 65 7e 30 79 7e 30 54 5f 43 30 7d 7f 74 75) |( 45 79 78 62 31 61 63 7e 76 63 70 7c 31 72 70 7f 7f 7e 65 31 73 74 31 63 64 7f 31 78 7f 31 55 5e 42 31 7c 7e 75 74) |( 46 7a 7b 61 32 62 60 7d 75 60 73 7f 32 71 73 7c 7c 7d 66 32 70 77 32 60 67 7c 32 7b 7c 32 56 5d 41 32 7f 7d 76 77) |( 47 7b 7a 60 33 63 61 7c 74 61 72 7e 33 70 72 7d 7d 7c 67 33 71 76 33 61 66 7d 33 7a 7d 33 57 5c 40 33 7e 7c 77 76) |( 40 7c 7d 67 34 64 66 7b 73 66 75 79 34 77 75 7a 7a 7b 60 34 76 71 34 66 61 7a 34 7d 7a 34 50 5b 47 34 79 7b 70 71) |( 41 7d 7c 66 35 65 67 7a 72 67 74 78 35 76 74 7b 7b 7a 61 35 77 70 35 67 60 7b 35 7c 7b 35 51 5a 46 35 78 7a 71 70) |( 42 7e 7f 65 36 66 64 79 71 64 77 7b 36 75 77 78 78 79 62 36 74 73 36 64 63 78 36 7f 78 36 52 59 45 36 7b 79 72 73) |( 43 7f 7e 64 37 67 65 78 70 65 76 7a 37 74 76 79 79 78 63 37 75 72 37 65 62 79 37 7e 79 37 53 58 44 37 7a 78 73 72) |( 4c 70 71 6b 38 68 6a 77 7f 6a 79 75 38 7b 79 76 76 77 6c 38 7a 7d 38 6a 6d 76 38 71 76 38 5c 57 4b 38 75 77 7c 7d) |( 4d 71 70 6a 39 69 6b 76 7e 6b 78 74 39 7a 78 77 77 76 6d 39 7b 7c 39 6b 6c 77 39 70 77 39 5d 56 4a 39 74 76 7d 7c) |( 4e 72 73 69 3a 6a 68 75 7d 68 7b 77 3a 79 7b 74 74 75 6e 3a 78 7f 3a 68 6f 74 3a 73 74 3a 5e 55 49 3a 77 75 7e 7f) |( 4f 73 72 68 3b 6b 69 74 7c 69 7a 76 3b 78 7a 75 75 74 6f 3b 79 7e 3b 69 6e 75 3b 72 75 3b 5f 54 48 3b 76 74 7f 7e) |( 48 74 75 6f 3c 6c 6e 73 7b 6e 7d 71 3c 7f 7d 72 72 73 68 3c 7e 79 3c 6e 69 72 3c 75 72 3c 58 53 4f 3c 71 73 78 79) |( 49 75 74 6e 3d 6d 6f 72 7a 6f 7c 70 3d 7e 7c 73 73 72 69 3d 7f 78 3d 6f 68 73 3d 74 73 3d 59 52 4e 3d 70 72 79 78) |( 4a 76 77 6d 3e 6e 6c 71 79 6c 7f 73 3e 7d 7f 70 70 71 6a 3e 7c 7b 3e 6c 6b 70 3e 77 70 3e 5a 51 4d 3e 73 71 7a 7b) |( 4b 77 76 6c 3f 6f 6d 70 78 6d 7e 72 3f 7c 7e 71 71 70 6b 3f 7d 7a 3f 6d 6a 71 3f 76 71 3f 5b 50 4c 3f 72 70 7b 7a)  | ( 55 01 69 01 68 01 72 01 21 01 71 01 73 01 6e 01 66 01 73 01 60 01 6c 01 21 01 62 01 60 01 6f 01 6f 01 6e 01 75 01 21 01 63 01 64 01 21 01 73 01 74 01 6f 01 21 01 68 01 6f 01 21 01 45 01 4e 01 52 01 21 01 6c 01 6e 01 65 01 64 01) |( 56 02 6a 02 6b 02 71 02 22 02 72 02 70 02 6d 02 65 02 70 02 63 02 6f 02 22 02 61 02 63 02 6c 02 6c 02 6d 02 76 02 22 02 60 02 67 02 22 02 70 02 77 02 6c 02 22 02 6b 02 6c 02 22 02 46 02 4d 02 51 02 22 02 6f 02 6d 02 66 02 67 02) |( 57 03 6b 03 6a 03 70 03 23 03 73 03 71 03 6c 03 64 03 71 03 62 03 6e 03 23 03 60 03 62 03 6d 03 6d 03 6c 03 77 03 23 03 61 03 66 03 23 03 71 03 76 03 6d 03 23 03 6a 03 6d 03 23 03 47 03 4c 03 50 03 23 03 6e 03 6c 03 67 03 66 03) |( 50 04 6c 04 6d 04 77 04 24 04 74 04 76 04 6b 04 63 04 76 04 65 04 69 04 24 04 67 04 65 04 6a 04 6a 04 6b 04 70 04 24 04 66 04 61 04 24 04 76 04 71 04 6a 04 24 04 6d 04 6a 04 24 04 40 04 4b 04 57 04 24 04 69 04 6b 04 60 04 61 04) |( 51 05 6d 05 6c 05 76 05 25 05 75 05 77 05 6a 05 62 05 77 05 64 05 68 05 25 05 66 05 64 05 6b 05 6b 05 6a 05 71 05 25 05 67 05 60 05 25 05 77 05 70 05 6b 05 25 05 6c 05 6b 05 25 05 41 05 4a 05 56 05 25 05 68 05 6a 05 61 05 60 05) |( 52 06 6e 06 6f 06 75 06 26 06 76 06 74 06 69 06 61 06 74 06 67 06 6b 06 26 06 65 06 67 06 68 06 68 06 69 06 72 06 26 06 64 06 63 06 26 06 74 06 73 06 68 06 26 06 6f 06 68 06 26 06 42 06 49 06 55 06 26 06 6b 06 69 06 62 06 63 06) |( 53 07 6f 07 6e 07 74 07 27 07 77 07 75 07 68 07 60 07 75 07 66 07 6a 07 27 07 64 07 66 07 69 07 69 07 68 07 73 07 27 07 65 07 62 07 27 07 75 07 72 07 69 07 27 07 6e 07 69 07 27 07 43 07 48 07 54 07 27 07 6a 07 68 07 63 07 62 07) |( 5c 08 60 08 61 08 7b 08 28 08 78 08 7a 08 67 08 6f 08 7a 08 69 08 65 08 28 08 6b 08 69 08 66 08 66 08 67 08 7c 08 28 08 6a 08 6d 08 28 08 7a 08 7d 08 66 08 28 08 61 08 66 08 28 08 4c 08 47 08 5b 08 28 08 65 08 67 08 6c 08 6d 08) |( 5d 09 61 09 60 09 7a 09 29 09 79 09 7b 09 66 09 6e 09 7b 09 68 09 64 09 29 09 6a 09 68 09 67 09 67 09 66 09 7d 09 29 09 6b 09 6c 09 29 09 7b 09 7c 09 67 09 29 09 60 09 67 09 29 09 4d 09 46 09 5a 09 29 09 64 09 66 09 6d 09 6c 09) |( 5e 0a 62 0a 63 0a 79 0a 2a 0a 7a 0a 78 0a 65 0a 6d 0a 78 0a 6b 0a 67 0a 2a 0a 69 0a 6b 0a 64 0a 64 0a 65 0a 7e 0a 2a 0a 68 0a 6f 0a 2a 0a 78 0a 7f 0a 64 0a 2a 0a 63 0a 64 0a 2a 0a 4e 0a 45 0a 59 0a 2a 0a 67 0a 65 0a 6e 0a 6f 0a) |( 5f 0b 63 0b 62 0b 78 0b 2b 0b 7b 0b 79 0b 64 0b 6c 0b 79 0b 6a 0b 66 0b 2b 0b 68 0b 6a 0b 65 0b 65 0b 64 0b 7f 0b 2b 0b 69 0b 6e 0b 2b 0b 79 0b 7e 0b 65 0b 2b 0b 62 0b 65 0b 2b 0b 4f 0b 44 0b 58 0b 2b 0b 66 0b 64 0b 6f 0b 6e 0b) |( 58 0c 64 0c 65 0c 7f 0c 2c 0c 7c 0c 7e 0c 63 0c 6b 0c 7e 0c 6d 0c 61 0c 2c 0c 6f 0c 6d 0c 62 0c 62 0c 63 0c 78 0c 2c 0c 6e 0c 69 0c 2c 0c 7e 0c 79 0c 62 0c 2c 0c 65 0c 62 0c 2c 0c 48 0c 43 0c 5f 0c 2c 0c 61 0c 63 0c 68 0c 69 0c) |( 59 0d 65 0d 64 0d 7e 0d 2d 0d 7d 0d 7f 0d 62 0d 6a 0d 7f 0d 6c 0d 60 0d 2d 0d 6e 0d 6c 0d 63 0d 63 0d 62 0d 79 0d 2d 0d 6f 0d 68 0d 2d 0d 7f 0d 78 0d 63 0d 2d 0d 64 0d 63 0d 2d 0d 49 0d 42 0d 5e 0d 2d 0d 60 0d 62 0d 69 0d 68 0d) |( 5a 0e 66 0e 67 0e 7d 0e 2e 0e 7e 0e 7c 0e 61 0e 69 0e 7c 0e 6f 0e 63 0e 2e 0e 6d 0e 6f 0e 60 0e 60 0e 61 0e 7a 0e 2e 0e 6c 0e 6b 0e 2e 0e 7c 0e 7b 0e 60 0e 2e 0e 67 0e 60 0e 2e 0e 4a 0e 41 0e 5d 0e 2e 0e 63 0e 61 0e 6a 0e 6b 0e) |( 5b 0f 67 0f 66 0f 7c 0f 2f 0f 7f 0f 7d 0f 60 0f 68 0f 7d 0f 6e 0f 62 0f 2f 0f 6c 0f 6e 0f 61 0f 61 0f 60 0f 7b 0f 2f 0f 6d 0f 6a 0f 2f 0f 7d 0f 7a 0f 61 0f 2f 0f 66 0f 61 0f 2f 0f 4b 0f 40 0f 5c 0f 2f 0f 62 0f 60 0f 6b 0f 6a 0f) |( 44 10 78 10 79 10 63 10 30 10 60 10 62 10 7f 10 77 10 62 10 71 10 7d 10 30 10 73 10 71 10 7e 10 7e 10 7f 10 64 10 30 10 72 10 75 10 30 10 62 10 65 10 7e 10 30 10 79 10 7e 10 30 10 54 10 5f 10 43 10 30 10 7d 10 7f 10 74 10 75 10) |( 45 11 79 11 78 11 62 11 31 11 61 11 63 11 7e 11 76 11 63 11 70 11 7c 11 31 11 72 11 70 11 7f 11 7f 11 7e 11 65 11 31 11 73 11 74 11 31 11 63 11 64 11 7f 11 31 11 78 11 7f 11 31 11 55 11 5e 11 42 11 31 11 7c 11 7e 11 75 11 74 11) |( 46 12 7a 12 7b 12 61 12 32 12 62 12 60 12 7d 12 75 12 60 12 73 12 7f 12 32 12 71 12 73 12 7c 12 7c 12 7d 12 66 12 32 12 70 12 77 12 32 12 60 12 67 12 7c 12 32 12 7b 12 7c 12 32 12 56 12 5d 12 41 12 32 12 7f 12 7d 12 76 12 77 12) |( 47 13 7b 13 7a 13 60 13 33 13 63 13 61 13 7c 13 74 13 61 13 72 13 7e 13 33 13 70 13 72 13 7d 13 7d 13 7c 13 67 13 33 13 71 13 76 13 33 13 61 13 66 13 7d 13 33 13 7a 13 7d 13 33 13 57 13 5c 13 40 13 33 13 7e 13 7c 13 77 13 76 13) |( 40 14 7c 14 7d 14 67 14 34 14 64 14 66 14 7b 14 73 14 66 14 75 14 79 14 34 14 77 14 75 14 7a 14 7a 14 7b 14 60 14 34 14 76 14 71 14 34 14 66 14 61 14 7a 14 34 14 7d 14 7a 14 34 14 50 14 5b 14 47 14 34 14 79 14 7b 14 70 14 71 14) |( 41 15 7d 15 7c 15 66 15 35 15 65 15 67 15 7a 15 72 15 67 15 74 15 78 15 35 15 76 15 74 15 7b 15 7b 15 7a 15 61 15 35 15 77 15 70 15 35 15 67 15 60 15 7b 15 35 15 7c 15 7b 15 35 15 51 15 5a 15 46 15 35 15 78 15 7a 15 71 15 70 15) |( 42 16 7e 16 7f 16 65 16 36 16 66 16 64 16 79 16 71 16 64 16 77 16 7b 16 36 16 75 16 77 16 78 16 78 16 79 16 62 16 36 16 74 16 73 16 36 16 64 16 63 16 78 16 36 16 7f 16 78 16 36 16 52 16 59 16 45 16 36 16 7b 16 79 16 72 16 73 16) |( 43 17 7f 17 7e 17 64 17 37 17 67 17 65 17 78 17 70 17 65 17 76 17 7a 17 37 17 74 17 76 17 79 17 79 17 78 17 63 17 37 17 75 17 72 17 37 17 65 17 62 17 79 17 37 17 7e 17 79 17 37 17 53 17 58 17 44 17 37 17 7a 17 78 17 73 17 72 17) |( 4c 18 70 18 71 18 6b 18 38 18 68 18 6a 18 77 18 7f 18 6a 18 79 18 75 18 38 18 7b 18 79 18 76 18 76 18 77 18 6c 18 38 18 7a 18 7d 18 38 18 6a 18 6d 18 76 18 38 18 71 18 76 18 38 18 5c 18 57 18 4b 18 38 18 75 18 77 18 7c 18 7d 18) |( 4d 19 71 19 70 19 6a 19 39 19 69 19 6b 19 76 19 7e 19 6b 19 78 19 74 19 39 19 7a 19 78 19 77 19 77 19 76 19 6d 19 39 19 7b 19 7c 19 39 19 6b 19 6c 19 77 19 39 19 70 19 77 19 39 19 5d 19 56 19 4a 19 39 19 74 19 76 19 7d 19 7c 19) |( 4e 1a 72 1a 73 1a 69 1a 3a 1a 6a 1a 68 1a 75 1a 7d 1a 68 1a 7b 1a 77 1a 3a 1a 79 1a 7b 1a 74 1a 74 1a 75 1a 6e 1a 3a 1a 78 1a 7f 1a 3a 1a 68 1a 6f 1a 74 1a 3a 1a 73 1a 74 1a 3a 1a 5e 1a 55 1a 49 1a 3a 1a 77 1a 75 1a 7e 1a 7f 1a) |( 4f 1b 73 1b 72 1b 68 1b 3b 1b 6b 1b 69 1b 74 1b 7c 1b 69 1b 7a 1b 76 1b 3b 1b 78 1b 7a 1b 75 1b 75 1b 74 1b 6f 1b 3b 1b 79 1b 7e 1b 3b 1b 69 1b 6e 1b 75 1b 3b 1b 72 1b 75 1b 3b 1b 5f 1b 54 1b 48 1b 3b 1b 76 1b 74 1b 7f 1b 7e 1b) |( 48 1c 74 1c 75 1c 6f 1c 3c 1c 6c 1c 6e 1c 73 1c 7b 1c 6e 1c 7d 1c 71 1c 3c 1c 7f 1c 7d 1c 72 1c 72 1c 73 1c 68 1c 3c 1c 7e 1c 79 1c 3c 1c 6e 1c 69 1c 72 1c 3c 1c 75 1c 72 1c 3c 1c 58 1c 53 1c 4f 1c 3c 1c 71 1c 73 1c 78 1c 79 1c) |( 49 1d 75 1d 74 1d 6e 1d 3d 1d 6d 1d 6f 1d 72 1d 7a 1d 6f 1d 7c 1d 70 1d 3d 1d 7e 1d 7c 1d 73 1d 73 1d 72 1d 69 1d 3d 1d 7f 1d 78 1d 3d 1d 6f 1d 68 1d 73 1d 3d 1d 74 1d 73 1d 3d 1d 59 1d 52 1d 4e 1d 3d 1d 70 1d 72 1d 79 1d 78 1d) |( 4a 1e 76 1e 77 1e 6d 1e 3e 1e 6e 1e 6c 1e 71 1e 79 1e 6c 1e 7f 1e 73 1e 3e 1e 7d 1e 7f 1e 70 1e 70 1e 71 1e 6a 1e 3e 1e 7c 1e 7b 1e 3e 1e 6c 1e 6b 1e 70 1e 3e 1e 77 1e 70 1e 3e 1e 5a 1e 51 1e 4d 1e 3e 1e 73 1e 71 1e 7a 1e 7b 1e) |( 4b 1f 77 1f 76 1f 6c 1f 3f 1f 6f 1f 6d 1f 70 1f 78 1f 6d 1f 7e 1f 72 1f 3f 1f 7c 1f 7e 1f 71 1f 71 1f 70 1f 6b 1f 3f 1f 7d 1f 7a 1f 3f 1f 6d 1f 6a 1f 71 1f 3f 1f 76 1f 71 1f 3f 1f 5b 1f 50 1f 4c 1f 3f 1f 72 1f 70 1f 7b 1f 7a 1f) )}
		$xo2 = {(( 55 69 68 72 21 71 73 6e 66 73 60 6c 21 6c 74 72 75 21 63 64 21 73 74 6f 21 74 6f 65 64 73 21 56 68 6f 32 33) |( 56 6a 6b 71 22 72 70 6d 65 70 63 6f 22 6f 77 71 76 22 60 67 22 70 77 6c 22 77 6c 66 67 70 22 55 6b 6c 31 30) |( 57 6b 6a 70 23 73 71 6c 64 71 62 6e 23 6e 76 70 77 23 61 66 23 71 76 6d 23 76 6d 67 66 71 23 54 6a 6d 30 31) |( 50 6c 6d 77 24 74 76 6b 63 76 65 69 24 69 71 77 70 24 66 61 24 76 71 6a 24 71 6a 60 61 76 24 53 6d 6a 37 36) |( 51 6d 6c 76 25 75 77 6a 62 77 64 68 25 68 70 76 71 25 67 60 25 77 70 6b 25 70 6b 61 60 77 25 52 6c 6b 36 37) |( 52 6e 6f 75 26 76 74 69 61 74 67 6b 26 6b 73 75 72 26 64 63 26 74 73 68 26 73 68 62 63 74 26 51 6f 68 35 34) |( 53 6f 6e 74 27 77 75 68 60 75 66 6a 27 6a 72 74 73 27 65 62 27 75 72 69 27 72 69 63 62 75 27 50 6e 69 34 35) |( 5c 60 61 7b 28 78 7a 67 6f 7a 69 65 28 65 7d 7b 7c 28 6a 6d 28 7a 7d 66 28 7d 66 6c 6d 7a 28 5f 61 66 3b 3a) |( 5d 61 60 7a 29 79 7b 66 6e 7b 68 64 29 64 7c 7a 7d 29 6b 6c 29 7b 7c 67 29 7c 67 6d 6c 7b 29 5e 60 67 3a 3b) |( 5e 62 63 79 2a 7a 78 65 6d 78 6b 67 2a 67 7f 79 7e 2a 68 6f 2a 78 7f 64 2a 7f 64 6e 6f 78 2a 5d 63 64 39 38) |( 5f 63 62 78 2b 7b 79 64 6c 79 6a 66 2b 66 7e 78 7f 2b 69 6e 2b 79 7e 65 2b 7e 65 6f 6e 79 2b 5c 62 65 38 39) |( 58 64 65 7f 2c 7c 7e 63 6b 7e 6d 61 2c 61 79 7f 78 2c 6e 69 2c 7e 79 62 2c 79 62 68 69 7e 2c 5b 65 62 3f 3e) |( 59 65 64 7e 2d 7d 7f 62 6a 7f 6c 60 2d 60 78 7e 79 2d 6f 68 2d 7f 78 63 2d 78 63 69 68 7f 2d 5a 64 63 3e 3f) |( 5a 66 67 7d 2e 7e 7c 61 69 7c 6f 63 2e 63 7b 7d 7a 2e 6c 6b 2e 7c 7b 60 2e 7b 60 6a 6b 7c 2e 59 67 60 3d 3c) |( 5b 67 66 7c 2f 7f 7d 60 68 7d 6e 62 2f 62 7a 7c 7b 2f 6d 6a 2f 7d 7a 61 2f 7a 61 6b 6a 7d 2f 58 66 61 3c 3d) |( 44 78 79 63 30 60 62 7f 77 62 71 7d 30 7d 65 63 64 30 72 75 30 62 65 7e 30 65 7e 74 75 62 30 47 79 7e 23 22) |( 45 79 78 62 31 61 63 7e 76 63 70 7c 31 7c 64 62 65 31 73 74 31 63 64 7f 31 64 7f 75 74 63 31 46 78 7f 22 23) |( 46 7a 7b 61 32 62 60 7d 75 60 73 7f 32 7f 67 61 66 32 70 77 32 60 67 7c 32 67 7c 76 77 60 32 45 7b 7c 21 20) |( 47 7b 7a 60 33 63 61 7c 74 61 72 7e 33 7e 66 60 67 33 71 76 33 61 66 7d 33 66 7d 77 76 61 33 44 7a 7d 20 21) |( 40 7c 7d 67 34 64 66 7b 73 66 75 79 34 79 61 67 60 34 76 71 34 66 61 7a 34 61 7a 70 71 66 34 43 7d 7a 27 26) |( 41 7d 7c 66 35 65 67 7a 72 67 74 78 35 78 60 66 61 35 77 70 35 67 60 7b 35 60 7b 71 70 67 35 42 7c 7b 26 27) |( 42 7e 7f 65 36 66 64 79 71 64 77 7b 36 7b 63 65 62 36 74 73 36 64 63 78 36 63 78 72 73 64 36 41 7f 78 25 24) |( 43 7f 7e 64 37 67 65 78 70 65 76 7a 37 7a 62 64 63 37 75 72 37 65 62 79 37 62 79 73 72 65 37 40 7e 79 24 25) |( 4c 70 71 6b 38 68 6a 77 7f 6a 79 75 38 75 6d 6b 6c 38 7a 7d 38 6a 6d 76 38 6d 76 7c 7d 6a 38 4f 71 76 2b 2a) |( 4d 71 70 6a 39 69 6b 76 7e 6b 78 74 39 74 6c 6a 6d 39 7b 7c 39 6b 6c 77 39 6c 77 7d 7c 6b 39 4e 70 77 2a 2b) |( 4e 72 73 69 3a 6a 68 75 7d 68 7b 77 3a 77 6f 69 6e 3a 78 7f 3a 68 6f 74 3a 6f 74 7e 7f 68 3a 4d 73 74 29 28) |( 4f 73 72 68 3b 6b 69 74 7c 69 7a 76 3b 76 6e 68 6f 3b 79 7e 3b 69 6e 75 3b 6e 75 7f 7e 69 3b 4c 72 75 28 29) |( 48 74 75 6f 3c 6c 6e 73 7b 6e 7d 71 3c 71 69 6f 68 3c 7e 79 3c 6e 69 72 3c 69 72 78 79 6e 3c 4b 75 72 2f 2e) |( 49 75 74 6e 3d 6d 6f 72 7a 6f 7c 70 3d 70 68 6e 69 3d 7f 78 3d 6f 68 73 3d 68 73 79 78 6f 3d 4a 74 73 2e 2f) |( 4a 76 77 6d 3e 6e 6c 71 79 6c 7f 73 3e 73 6b 6d 6a 3e 7c 7b 3e 6c 6b 70 3e 6b 70 7a 7b 6c 3e 49 77 70 2d 2c) |( 4b 77 76 6c 3f 6f 6d 70 78 6d 7e 72 3f 72 6a 6c 6b 3f 7d 7a 3f 6d 6a 71 3f 6a 71 7b 7a 6d 3f 48 76 71 2c 2d)  | ( 55 01 69 01 68 01 72 01 21 01 71 01 73 01 6e 01 66 01 73 01 60 01 6c 01 21 01 6c 01 74 01 72 01 75 01 21 01 63 01 64 01 21 01 73 01 74 01 6f 01 21 01 74 01 6f 01 65 01 64 01 73 01 21 01 56 01 68 01 6f 01 32 01 33 01) |( 56 02 6a 02 6b 02 71 02 22 02 72 02 70 02 6d 02 65 02 70 02 63 02 6f 02 22 02 6f 02 77 02 71 02 76 02 22 02 60 02 67 02 22 02 70 02 77 02 6c 02 22 02 77 02 6c 02 66 02 67 02 70 02 22 02 55 02 6b 02 6c 02 31 02 30 02) |( 57 03 6b 03 6a 03 70 03 23 03 73 03 71 03 6c 03 64 03 71 03 62 03 6e 03 23 03 6e 03 76 03 70 03 77 03 23 03 61 03 66 03 23 03 71 03 76 03 6d 03 23 03 76 03 6d 03 67 03 66 03 71 03 23 03 54 03 6a 03 6d 03 30 03 31 03) |( 50 04 6c 04 6d 04 77 04 24 04 74 04 76 04 6b 04 63 04 76 04 65 04 69 04 24 04 69 04 71 04 77 04 70 04 24 04 66 04 61 04 24 04 76 04 71 04 6a 04 24 04 71 04 6a 04 60 04 61 04 76 04 24 04 53 04 6d 04 6a 04 37 04 36 04) |( 51 05 6d 05 6c 05 76 05 25 05 75 05 77 05 6a 05 62 05 77 05 64 05 68 05 25 05 68 05 70 05 76 05 71 05 25 05 67 05 60 05 25 05 77 05 70 05 6b 05 25 05 70 05 6b 05 61 05 60 05 77 05 25 05 52 05 6c 05 6b 05 36 05 37 05) |( 52 06 6e 06 6f 06 75 06 26 06 76 06 74 06 69 06 61 06 74 06 67 06 6b 06 26 06 6b 06 73 06 75 06 72 06 26 06 64 06 63 06 26 06 74 06 73 06 68 06 26 06 73 06 68 06 62 06 63 06 74 06 26 06 51 06 6f 06 68 06 35 06 34 06) |( 53 07 6f 07 6e 07 74 07 27 07 77 07 75 07 68 07 60 07 75 07 66 07 6a 07 27 07 6a 07 72 07 74 07 73 07 27 07 65 07 62 07 27 07 75 07 72 07 69 07 27 07 72 07 69 07 63 07 62 07 75 07 27 07 50 07 6e 07 69 07 34 07 35 07) |( 5c 08 60 08 61 08 7b 08 28 08 78 08 7a 08 67 08 6f 08 7a 08 69 08 65 08 28 08 65 08 7d 08 7b 08 7c 08 28 08 6a 08 6d 08 28 08 7a 08 7d 08 66 08 28 08 7d 08 66 08 6c 08 6d 08 7a 08 28 08 5f 08 61 08 66 08 3b 08 3a 08) |( 5d 09 61 09 60 09 7a 09 29 09 79 09 7b 09 66 09 6e 09 7b 09 68 09 64 09 29 09 64 09 7c 09 7a 09 7d 09 29 09 6b 09 6c 09 29 09 7b 09 7c 09 67 09 29 09 7c 09 67 09 6d 09 6c 09 7b 09 29 09 5e 09 60 09 67 09 3a 09 3b 09) |( 5e 0a 62 0a 63 0a 79 0a 2a 0a 7a 0a 78 0a 65 0a 6d 0a 78 0a 6b 0a 67 0a 2a 0a 67 0a 7f 0a 79 0a 7e 0a 2a 0a 68 0a 6f 0a 2a 0a 78 0a 7f 0a 64 0a 2a 0a 7f 0a 64 0a 6e 0a 6f 0a 78 0a 2a 0a 5d 0a 63 0a 64 0a 39 0a 38 0a) |( 5f 0b 63 0b 62 0b 78 0b 2b 0b 7b 0b 79 0b 64 0b 6c 0b 79 0b 6a 0b 66 0b 2b 0b 66 0b 7e 0b 78 0b 7f 0b 2b 0b 69 0b 6e 0b 2b 0b 79 0b 7e 0b 65 0b 2b 0b 7e 0b 65 0b 6f 0b 6e 0b 79 0b 2b 0b 5c 0b 62 0b 65 0b 38 0b 39 0b) |( 58 0c 64 0c 65 0c 7f 0c 2c 0c 7c 0c 7e 0c 63 0c 6b 0c 7e 0c 6d 0c 61 0c 2c 0c 61 0c 79 0c 7f 0c 78 0c 2c 0c 6e 0c 69 0c 2c 0c 7e 0c 79 0c 62 0c 2c 0c 79 0c 62 0c 68 0c 69 0c 7e 0c 2c 0c 5b 0c 65 0c 62 0c 3f 0c 3e 0c) |( 59 0d 65 0d 64 0d 7e 0d 2d 0d 7d 0d 7f 0d 62 0d 6a 0d 7f 0d 6c 0d 60 0d 2d 0d 60 0d 78 0d 7e 0d 79 0d 2d 0d 6f 0d 68 0d 2d 0d 7f 0d 78 0d 63 0d 2d 0d 78 0d 63 0d 69 0d 68 0d 7f 0d 2d 0d 5a 0d 64 0d 63 0d 3e 0d 3f 0d) |( 5a 0e 66 0e 67 0e 7d 0e 2e 0e 7e 0e 7c 0e 61 0e 69 0e 7c 0e 6f 0e 63 0e 2e 0e 63 0e 7b 0e 7d 0e 7a 0e 2e 0e 6c 0e 6b 0e 2e 0e 7c 0e 7b 0e 60 0e 2e 0e 7b 0e 60 0e 6a 0e 6b 0e 7c 0e 2e 0e 59 0e 67 0e 60 0e 3d 0e 3c 0e) |( 5b 0f 67 0f 66 0f 7c 0f 2f 0f 7f 0f 7d 0f 60 0f 68 0f 7d 0f 6e 0f 62 0f 2f 0f 62 0f 7a 0f 7c 0f 7b 0f 2f 0f 6d 0f 6a 0f 2f 0f 7d 0f 7a 0f 61 0f 2f 0f 7a 0f 61 0f 6b 0f 6a 0f 7d 0f 2f 0f 58 0f 66 0f 61 0f 3c 0f 3d 0f) |( 44 10 78 10 79 10 63 10 30 10 60 10 62 10 7f 10 77 10 62 10 71 10 7d 10 30 10 7d 10 65 10 63 10 64 10 30 10 72 10 75 10 30 10 62 10 65 10 7e 10 30 10 65 10 7e 10 74 10 75 10 62 10 30 10 47 10 79 10 7e 10 23 10 22 10) |( 45 11 79 11 78 11 62 11 31 11 61 11 63 11 7e 11 76 11 63 11 70 11 7c 11 31 11 7c 11 64 11 62 11 65 11 31 11 73 11 74 11 31 11 63 11 64 11 7f 11 31 11 64 11 7f 11 75 11 74 11 63 11 31 11 46 11 78 11 7f 11 22 11 23 11) |( 46 12 7a 12 7b 12 61 12 32 12 62 12 60 12 7d 12 75 12 60 12 73 12 7f 12 32 12 7f 12 67 12 61 12 66 12 32 12 70 12 77 12 32 12 60 12 67 12 7c 12 32 12 67 12 7c 12 76 12 77 12 60 12 32 12 45 12 7b 12 7c 12 21 12 20 12) |( 47 13 7b 13 7a 13 60 13 33 13 63 13 61 13 7c 13 74 13 61 13 72 13 7e 13 33 13 7e 13 66 13 60 13 67 13 33 13 71 13 76 13 33 13 61 13 66 13 7d 13 33 13 66 13 7d 13 77 13 76 13 61 13 33 13 44 13 7a 13 7d 13 20 13 21 13) |( 40 14 7c 14 7d 14 67 14 34 14 64 14 66 14 7b 14 73 14 66 14 75 14 79 14 34 14 79 14 61 14 67 14 60 14 34 14 76 14 71 14 34 14 66 14 61 14 7a 14 34 14 61 14 7a 14 70 14 71 14 66 14 34 14 43 14 7d 14 7a 14 27 14 26 14) |( 41 15 7d 15 7c 15 66 15 35 15 65 15 67 15 7a 15 72 15 67 15 74 15 78 15 35 15 78 15 60 15 66 15 61 15 35 15 77 15 70 15 35 15 67 15 60 15 7b 15 35 15 60 15 7b 15 71 15 70 15 67 15 35 15 42 15 7c 15 7b 15 26 15 27 15) |( 42 16 7e 16 7f 16 65 16 36 16 66 16 64 16 79 16 71 16 64 16 77 16 7b 16 36 16 7b 16 63 16 65 16 62 16 36 16 74 16 73 16 36 16 64 16 63 16 78 16 36 16 63 16 78 16 72 16 73 16 64 16 36 16 41 16 7f 16 78 16 25 16 24 16) |( 43 17 7f 17 7e 17 64 17 37 17 67 17 65 17 78 17 70 17 65 17 76 17 7a 17 37 17 7a 17 62 17 64 17 63 17 37 17 75 17 72 17 37 17 65 17 62 17 79 17 37 17 62 17 79 17 73 17 72 17 65 17 37 17 40 17 7e 17 79 17 24 17 25 17) |( 4c 18 70 18 71 18 6b 18 38 18 68 18 6a 18 77 18 7f 18 6a 18 79 18 75 18 38 18 75 18 6d 18 6b 18 6c 18 38 18 7a 18 7d 18 38 18 6a 18 6d 18 76 18 38 18 6d 18 76 18 7c 18 7d 18 6a 18 38 18 4f 18 71 18 76 18 2b 18 2a 18) |( 4d 19 71 19 70 19 6a 19 39 19 69 19 6b 19 76 19 7e 19 6b 19 78 19 74 19 39 19 74 19 6c 19 6a 19 6d 19 39 19 7b 19 7c 19 39 19 6b 19 6c 19 77 19 39 19 6c 19 77 19 7d 19 7c 19 6b 19 39 19 4e 19 70 19 77 19 2a 19 2b 19) |( 4e 1a 72 1a 73 1a 69 1a 3a 1a 6a 1a 68 1a 75 1a 7d 1a 68 1a 7b 1a 77 1a 3a 1a 77 1a 6f 1a 69 1a 6e 1a 3a 1a 78 1a 7f 1a 3a 1a 68 1a 6f 1a 74 1a 3a 1a 6f 1a 74 1a 7e 1a 7f 1a 68 1a 3a 1a 4d 1a 73 1a 74 1a 29 1a 28 1a) |( 4f 1b 73 1b 72 1b 68 1b 3b 1b 6b 1b 69 1b 74 1b 7c 1b 69 1b 7a 1b 76 1b 3b 1b 76 1b 6e 1b 68 1b 6f 1b 3b 1b 79 1b 7e 1b 3b 1b 69 1b 6e 1b 75 1b 3b 1b 6e 1b 75 1b 7f 1b 7e 1b 69 1b 3b 1b 4c 1b 72 1b 75 1b 28 1b 29 1b) |( 48 1c 74 1c 75 1c 6f 1c 3c 1c 6c 1c 6e 1c 73 1c 7b 1c 6e 1c 7d 1c 71 1c 3c 1c 71 1c 69 1c 6f 1c 68 1c 3c 1c 7e 1c 79 1c 3c 1c 6e 1c 69 1c 72 1c 3c 1c 69 1c 72 1c 78 1c 79 1c 6e 1c 3c 1c 4b 1c 75 1c 72 1c 2f 1c 2e 1c) |( 49 1d 75 1d 74 1d 6e 1d 3d 1d 6d 1d 6f 1d 72 1d 7a 1d 6f 1d 7c 1d 70 1d 3d 1d 70 1d 68 1d 6e 1d 69 1d 3d 1d 7f 1d 78 1d 3d 1d 6f 1d 68 1d 73 1d 3d 1d 68 1d 73 1d 79 1d 78 1d 6f 1d 3d 1d 4a 1d 74 1d 73 1d 2e 1d 2f 1d) |( 4a 1e 76 1e 77 1e 6d 1e 3e 1e 6e 1e 6c 1e 71 1e 79 1e 6c 1e 7f 1e 73 1e 3e 1e 73 1e 6b 1e 6d 1e 6a 1e 3e 1e 7c 1e 7b 1e 3e 1e 6c 1e 6b 1e 70 1e 3e 1e 6b 1e 70 1e 7a 1e 7b 1e 6c 1e 3e 1e 49 1e 77 1e 70 1e 2d 1e 2c 1e) |( 4b 1f 77 1f 76 1f 6c 1f 3f 1f 6f 1f 6d 1f 70 1f 78 1f 6d 1f 7e 1f 72 1f 3f 1f 72 1f 6a 1f 6c 1f 6b 1f 3f 1f 7d 1f 7a 1f 3f 1f 6d 1f 6a 1f 71 1f 3f 1f 6a 1f 71 1f 7b 1f 7a 1f 6d 1f 3f 1f 48 1f 76 1f 71 1f 2c 1f 2d 1f) )}
		$fp1 = {((41 56 41 53 54 20 53 6f 66 74 77 61 72 65) | (41 00 56 00 41 00 53 00 54 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00))}
		$fp2 = {((41 56 47 20 4e 65 74 68 65 72 6c 61 6e 64 73) | (41 00 56 00 47 00 20 00 4e 00 65 00 74 00 68 00 65 00 72 00 6c 00 61 00 6e 00 64 00 73 00))}
		$fp3 = {((41 56 47 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73) | (41 00 56 00 47 00 20 00 54 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 69 00 65 00 73 00))}
		$fp4 = {4d 00 61 00 6c 00 69 00 63 00 69 00 6f 00 75 00 73 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 52 00 65 00 6d 00 6f 00 76 00 61 00 6c 00 20 00 54 00 6f 00 6f 00 6c 00}
		$fp5 = {((4d 63 41 66 65 65 20 4c 61 62 73) | (4d 00 63 00 41 00 66 00 65 00 65 00 20 00 4c 00 61 00 62 00 73 00))}
		$fp6 = {((4b 61 73 70 65 72 73 6b 79 20 4c 61 62) | (4b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 20 00 4c 00 61 00 62 00))}
		$fp7 = {((3c 70 72 6f 70 65 72 74 69 65 73 6d 61 70 3e) | (3c 00 70 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 6d 00 61 00 70 00 3e 00))}
		$fp10 = {41 00 76 00 69 00 72 00 61 00 20 00 45 00 6e 00 67 00 69 00 6e 00 65 00 20 00 4d 00 6f 00 64 00 75 00 6c 00 65 00}
		$fp11 = {73 00 79 00 6e 00 74 00 65 00 76 00 6f 00 20 00 47 00 6d 00 62 00 48 00}
		$fp13 = {53 6f 70 68 6f 73 43 6c 65 61 6e}
		$fp14 = {53 00 6f 00 70 00 68 00 6f 00 73 00 48 00 6f 00 6d 00 65 00 43 00 6c 00 65 00 61 00 6e 00}

	condition:
		1 of ( $x* ) and not 1 of ( $fp* ) and not uint16( 0 ) == 0xb0b0 and not uint16( 0 ) == 0x5953
}

