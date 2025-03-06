rule Cobalt_functions : hardened
{
	meta:
		author = "@j0sm1"
		url = "https://www.securityartwork.es/2017/06/16/analisis-del-powershell-usado-fin7/"
		description = "Detect functions coded with ROR edi,D; Detect CobaltStrike used by differents groups APT"
		ruleset = "APT_Cobalt.yar"
		repository = "Yara-Rules/rules"
		source_url = "https://github.com/Yara-Rules/rules/blob/0f93570194a80d2f2032869055808b0ddcdfb360/malware/APT_Cobalt.yar"
		license = "GNU General Public License v2.0"
		score = 75

	strings:
		$h1 = {58 A4 53 E5}
		$h2 = {4C 77 26 07}
		$h3 = {6A C9 9C C9}
		$h4 = {44 F0 35 E0}
		$h5 = {F4 00 8E CC}

	condition:
		2 of ( $h* )
}

rule cobalt_strike_indicator : high hardened limited
{
	meta:
		description = "CobaltStrike indicator"
		author = "Florian Roth"
		hash_2024_2018_04_Common_Malware_Carrier_payload = "8cdd29e28daf040965d4cad8bf3c73d00dde3f2968bab44c7d8fe482ba2057f9"
		ruleset = "cobalt_strike.yara"
		repository = "chainguard-dev/bincapz"
		source_url = "https://github.com/chainguard-dev/bincapz/blob/641688a57cdfb271ec78be8a931e69b336513074/rules/tools/backdoor/cobalt_strike.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$ref = {(( 25 73 20 61 73 20 25 73 5c 25 73 3a 20 25 64) |( 24 72 21 60 72 21 24 72 5d 24 72 3b 21 24 65) |( 27 71 22 63 71 22 27 71 5e 27 71 38 22 27 66) |( 26 70 23 62 70 23 26 70 5f 26 70 39 23 26 67) |( 21 77 24 65 77 24 21 77 58 21 77 3e 24 21 60) |( 20 76 25 64 76 25 20 76 59 20 76 3f 25 20 61) |( 23 75 26 67 75 26 23 75 5a 23 75 3c 26 23 62) |( 22 74 27 66 74 27 22 74 5b 22 74 3d 27 22 63) |( 2d 7b 28 69 7b 28 2d 7b 54 2d 7b 32 28 2d 6c) |( 2c 7a 29 68 7a 29 2c 7a 55 2c 7a 33 29 2c 6d) |( 2f 79 2a 6b 79 2a 2f 79 56 2f 79 30 2a 2f 6e) |( 2e 78 2b 6a 78 2b 2e 78 57 2e 78 31 2b 2e 6f) |( 29 7f 2c 6d 7f 2c 29 7f 50 29 7f 36 2c 29 68) |( 28 7e 2d 6c 7e 2d 28 7e 51 28 7e 37 2d 28 69) |( 2b 7d 2e 6f 7d 2e 2b 7d 52 2b 7d 34 2e 2b 6a) |( 2a 7c 2f 6e 7c 2f 2a 7c 53 2a 7c 35 2f 2a 6b) |( 35 63 30 71 63 30 35 63 4c 35 63 2a 30 35 74) |( 34 62 31 70 62 31 34 62 4d 34 62 2b 31 34 75) |( 37 61 32 73 61 32 37 61 4e 37 61 28 32 37 76) |( 36 60 33 72 60 33 36 60 4f 36 60 29 33 36 77) |( 31 67 34 75 67 34 31 67 48 31 67 2e 34 31 70) |( 30 66 35 74 66 35 30 66 49 30 66 2f 35 30 71) |( 33 65 36 77 65 36 33 65 4a 33 65 2c 36 33 72) |( 32 64 37 76 64 37 32 64 4b 32 64 2d 37 32 73) |( 3d 6b 38 79 6b 38 3d 6b 44 3d 6b 22 38 3d 7c) |( 3c 6a 39 78 6a 39 3c 6a 45 3c 6a 23 39 3c 7d) |( 3f 69 3a 7b 69 3a 3f 69 46 3f 69 20 3a 3f 7e) |( 3e 68 3b 7a 68 3b 3e 68 47 3e 68 21 3b 3e 7f) |( 39 6f 3c 7d 6f 3c 39 6f 40 39 6f 26 3c 39 78) |( 38 6e 3d 7c 6e 3d 38 6e 41 38 6e 27 3d 38 79) |( 3b 6d 3e 7f 6d 3e 3b 6d 42 3b 6d 24 3e 3b 7a) |( 3a 6c 3f 7e 6c 3f 3a 6c 43 3a 6c 25 3f 3a 7b) |( 05 53 00 41 53 00 05 53 7c 05 53 1a 00 05 44) |( 04 52 01 40 52 01 04 52 7d 04 52 1b 01 04 45) |( 07 51 02 43 51 02 07 51 7e 07 51 18 02 07 46) |( 06 50 03 42 50 03 06 50 7f 06 50 19 03 06 47) |( 01 57 04 45 57 04 01 57 78 01 57 1e 04 01 40) |( 00 56 05 44 56 05 00 56 79 00 56 1f 05 00 41) |( 03 55 06 47 55 06 03 55 7a 03 55 1c 06 03 42) |( 02 54 07 46 54 07 02 54 7b 02 54 1d 07 02 43) |( 0d 5b 08 49 5b 08 0d 5b 74 0d 5b 12 08 0d 4c) |( 0c 5a 09 48 5a 09 0c 5a 75 0c 5a 13 09 0c 4d) |( 0f 59 0a 4b 59 0a 0f 59 76 0f 59 10 0a 0f 4e) |( 0e 58 0b 4a 58 0b 0e 58 77 0e 58 11 0b 0e 4f) |( 09 5f 0c 4d 5f 0c 09 5f 70 09 5f 16 0c 09 48) |( 08 5e 0d 4c 5e 0d 08 5e 71 08 5e 17 0d 08 49) |( 0b 5d 0e 4f 5d 0e 0b 5d 72 0b 5d 14 0e 0b 4a) |( 0a 5c 0f 4e 5c 0f 0a 5c 73 0a 5c 15 0f 0a 4b) |( 15 43 10 51 43 10 15 43 6c 15 43 0a 10 15 54) |( 14 42 11 50 42 11 14 42 6d 14 42 0b 11 14 55) |( 17 41 12 53 41 12 17 41 6e 17 41 08 12 17 56) |( 16 40 13 52 40 13 16 40 6f 16 40 09 13 16 57) |( 11 47 14 55 47 14 11 47 68 11 47 0e 14 11 50) |( 10 46 15 54 46 15 10 46 69 10 46 0f 15 10 51) |( 13 45 16 57 45 16 13 45 6a 13 45 0c 16 13 52) |( 12 44 17 56 44 17 12 44 6b 12 44 0d 17 12 53) |( 1d 4b 18 59 4b 18 1d 4b 64 1d 4b 02 18 1d 5c) |( 1c 4a 19 58 4a 19 1c 4a 65 1c 4a 03 19 1c 5d) |( 1f 49 1a 5b 49 1a 1f 49 66 1f 49 00 1a 1f 5e) |( 1e 48 1b 5a 48 1b 1e 48 67 1e 48 01 1b 1e 5f) |( 19 4f 1c 5d 4f 1c 19 4f 60 19 4f 06 1c 19 58) )}

	condition:
		any of them
}

rule CobaltStrikeBeacon : hardened limited
{
	meta:
		author = "ditekshen, enzo & Elastic"
		description = "Cobalt Strike Beacon Payload"
		cape_type = "CobaltStrikeBeacon Payload"
		ruleset = "CobaltStrikeBeacon.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/CobaltStrikeBeacon.yar"
		license = "Other"
		score = 75

	strings:
		$s1 = {25 25 49 4d 50 4f 52 54 25 25}
		$s2 = {77 77 77 36 2e 25 78 25 78 2e 25 73}
		$s3 = {63 64 6e 2e 25 78 25 78 2e 25 73}
		$s4 = {61 70 69 2e 25 78 25 78 2e 25 73}
		$s5 = {25 73 20 28 61 64 6d 69 6e 29}
		$s6 = {63 6f 75 6c 64 20 6e 6f 74 20 73 70 61 77 6e 20 25 73 3a 20 25 64}
		$s7 = {43 6f 75 6c 64 20 6e 6f 74 20 6b 69 6c 6c 20 25 64 3a 20 25 64}
		$s8 = {43 6f 75 6c 64 20 6e 6f 74 20 63 6f 6e 6e 65 63 74 20 74 6f 20 70 69 70 65 20 28 25 73 29 3a 20 25 64}
		$s9 = /%s\.\d[(%08x).]+\.%x%x\.%s/ ascii
		$pwsh1 = {49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 63 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70}
		$pwsh2 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 70 20 2d 65 78 65 63 20 62 79 70 61 73 73 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 20 22 25 73 22}
		$ver3a = {69 68 69 68 69 6b ?? ?? 69}
		$ver3b = {69 69 69 69}
		$ver4a = {2e 2f 2e 2f 2e 2c ?? ?? 2e}
		$ver4b = {2e 2e 2e 2e}
		$a1 = {(( 25 30 32 64 2f 25 30 32 64 2f 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64) |( 24 31 33 65 2e 24 31 33 65 2e 24 31 33 65 21 24 31 33 65 3b 24 31 33 65 3b 24 31 33 65) |( 27 32 30 66 2d 27 32 30 66 2d 27 32 30 66 22 27 32 30 66 38 27 32 30 66 38 27 32 30 66) |( 26 33 31 67 2c 26 33 31 67 2c 26 33 31 67 23 26 33 31 67 39 26 33 31 67 39 26 33 31 67) |( 21 34 36 60 2b 21 34 36 60 2b 21 34 36 60 24 21 34 36 60 3e 21 34 36 60 3e 21 34 36 60) |( 20 35 37 61 2a 20 35 37 61 2a 20 35 37 61 25 20 35 37 61 3f 20 35 37 61 3f 20 35 37 61) |( 23 36 34 62 29 23 36 34 62 29 23 36 34 62 26 23 36 34 62 3c 23 36 34 62 3c 23 36 34 62) |( 22 37 35 63 28 22 37 35 63 28 22 37 35 63 27 22 37 35 63 3d 22 37 35 63 3d 22 37 35 63) |( 2d 38 3a 6c 27 2d 38 3a 6c 27 2d 38 3a 6c 28 2d 38 3a 6c 32 2d 38 3a 6c 32 2d 38 3a 6c) |( 2c 39 3b 6d 26 2c 39 3b 6d 26 2c 39 3b 6d 29 2c 39 3b 6d 33 2c 39 3b 6d 33 2c 39 3b 6d) |( 2f 3a 38 6e 25 2f 3a 38 6e 25 2f 3a 38 6e 2a 2f 3a 38 6e 30 2f 3a 38 6e 30 2f 3a 38 6e) |( 2e 3b 39 6f 24 2e 3b 39 6f 24 2e 3b 39 6f 2b 2e 3b 39 6f 31 2e 3b 39 6f 31 2e 3b 39 6f) |( 29 3c 3e 68 23 29 3c 3e 68 23 29 3c 3e 68 2c 29 3c 3e 68 36 29 3c 3e 68 36 29 3c 3e 68) |( 28 3d 3f 69 22 28 3d 3f 69 22 28 3d 3f 69 2d 28 3d 3f 69 37 28 3d 3f 69 37 28 3d 3f 69) |( 2b 3e 3c 6a 21 2b 3e 3c 6a 21 2b 3e 3c 6a 2e 2b 3e 3c 6a 34 2b 3e 3c 6a 34 2b 3e 3c 6a) |( 2a 3f 3d 6b 20 2a 3f 3d 6b 20 2a 3f 3d 6b 2f 2a 3f 3d 6b 35 2a 3f 3d 6b 35 2a 3f 3d 6b) |( 35 20 22 74 3f 35 20 22 74 3f 35 20 22 74 30 35 20 22 74 2a 35 20 22 74 2a 35 20 22 74) |( 34 21 23 75 3e 34 21 23 75 3e 34 21 23 75 31 34 21 23 75 2b 34 21 23 75 2b 34 21 23 75) |( 37 22 20 76 3d 37 22 20 76 3d 37 22 20 76 32 37 22 20 76 28 37 22 20 76 28 37 22 20 76) |( 36 23 21 77 3c 36 23 21 77 3c 36 23 21 77 33 36 23 21 77 29 36 23 21 77 29 36 23 21 77) |( 31 24 26 70 3b 31 24 26 70 3b 31 24 26 70 34 31 24 26 70 2e 31 24 26 70 2e 31 24 26 70) |( 30 25 27 71 3a 30 25 27 71 3a 30 25 27 71 35 30 25 27 71 2f 30 25 27 71 2f 30 25 27 71) |( 33 26 24 72 39 33 26 24 72 39 33 26 24 72 36 33 26 24 72 2c 33 26 24 72 2c 33 26 24 72) |( 32 27 25 73 38 32 27 25 73 38 32 27 25 73 37 32 27 25 73 2d 32 27 25 73 2d 32 27 25 73) |( 3d 28 2a 7c 37 3d 28 2a 7c 37 3d 28 2a 7c 38 3d 28 2a 7c 22 3d 28 2a 7c 22 3d 28 2a 7c) |( 3c 29 2b 7d 36 3c 29 2b 7d 36 3c 29 2b 7d 39 3c 29 2b 7d 23 3c 29 2b 7d 23 3c 29 2b 7d) |( 3f 2a 28 7e 35 3f 2a 28 7e 35 3f 2a 28 7e 3a 3f 2a 28 7e 20 3f 2a 28 7e 20 3f 2a 28 7e) |( 3e 2b 29 7f 34 3e 2b 29 7f 34 3e 2b 29 7f 3b 3e 2b 29 7f 21 3e 2b 29 7f 21 3e 2b 29 7f) |( 39 2c 2e 78 33 39 2c 2e 78 33 39 2c 2e 78 3c 39 2c 2e 78 26 39 2c 2e 78 26 39 2c 2e 78) |( 38 2d 2f 79 32 38 2d 2f 79 32 38 2d 2f 79 3d 38 2d 2f 79 27 38 2d 2f 79 27 38 2d 2f 79) |( 3b 2e 2c 7a 31 3b 2e 2c 7a 31 3b 2e 2c 7a 3e 3b 2e 2c 7a 24 3b 2e 2c 7a 24 3b 2e 2c 7a) |( 3a 2f 2d 7b 30 3a 2f 2d 7b 30 3a 2f 2d 7b 3f 3a 2f 2d 7b 25 3a 2f 2d 7b 25 3a 2f 2d 7b) |( 05 10 12 44 0f 05 10 12 44 0f 05 10 12 44 00 05 10 12 44 1a 05 10 12 44 1a 05 10 12 44) |( 04 11 13 45 0e 04 11 13 45 0e 04 11 13 45 01 04 11 13 45 1b 04 11 13 45 1b 04 11 13 45) |( 07 12 10 46 0d 07 12 10 46 0d 07 12 10 46 02 07 12 10 46 18 07 12 10 46 18 07 12 10 46) |( 06 13 11 47 0c 06 13 11 47 0c 06 13 11 47 03 06 13 11 47 19 06 13 11 47 19 06 13 11 47) |( 01 14 16 40 0b 01 14 16 40 0b 01 14 16 40 04 01 14 16 40 1e 01 14 16 40 1e 01 14 16 40) |( 00 15 17 41 0a 00 15 17 41 0a 00 15 17 41 05 00 15 17 41 1f 00 15 17 41 1f 00 15 17 41) |( 03 16 14 42 09 03 16 14 42 09 03 16 14 42 06 03 16 14 42 1c 03 16 14 42 1c 03 16 14 42) |( 02 17 15 43 08 02 17 15 43 08 02 17 15 43 07 02 17 15 43 1d 02 17 15 43 1d 02 17 15 43) |( 0d 18 1a 4c 07 0d 18 1a 4c 07 0d 18 1a 4c 08 0d 18 1a 4c 12 0d 18 1a 4c 12 0d 18 1a 4c) |( 0c 19 1b 4d 06 0c 19 1b 4d 06 0c 19 1b 4d 09 0c 19 1b 4d 13 0c 19 1b 4d 13 0c 19 1b 4d) |( 0f 1a 18 4e 05 0f 1a 18 4e 05 0f 1a 18 4e 0a 0f 1a 18 4e 10 0f 1a 18 4e 10 0f 1a 18 4e) |( 0e 1b 19 4f 04 0e 1b 19 4f 04 0e 1b 19 4f 0b 0e 1b 19 4f 11 0e 1b 19 4f 11 0e 1b 19 4f) |( 09 1c 1e 48 03 09 1c 1e 48 03 09 1c 1e 48 0c 09 1c 1e 48 16 09 1c 1e 48 16 09 1c 1e 48) |( 08 1d 1f 49 02 08 1d 1f 49 02 08 1d 1f 49 0d 08 1d 1f 49 17 08 1d 1f 49 17 08 1d 1f 49) |( 0b 1e 1c 4a 01 0b 1e 1c 4a 01 0b 1e 1c 4a 0e 0b 1e 1c 4a 14 0b 1e 1c 4a 14 0b 1e 1c 4a) |( 0a 1f 1d 4b 00 0a 1f 1d 4b 00 0a 1f 1d 4b 0f 0a 1f 1d 4b 15 0a 1f 1d 4b 15 0a 1f 1d 4b) |( 15 00 02 54 1f 15 00 02 54 1f 15 00 02 54 10 15 00 02 54 0a 15 00 02 54 0a 15 00 02 54) |( 14 01 03 55 1e 14 01 03 55 1e 14 01 03 55 11 14 01 03 55 0b 14 01 03 55 0b 14 01 03 55) |( 17 02 00 56 1d 17 02 00 56 1d 17 02 00 56 12 17 02 00 56 08 17 02 00 56 08 17 02 00 56) |( 16 03 01 57 1c 16 03 01 57 1c 16 03 01 57 13 16 03 01 57 09 16 03 01 57 09 16 03 01 57) |( 11 04 06 50 1b 11 04 06 50 1b 11 04 06 50 14 11 04 06 50 0e 11 04 06 50 0e 11 04 06 50) |( 10 05 07 51 1a 10 05 07 51 1a 10 05 07 51 15 10 05 07 51 0f 10 05 07 51 0f 10 05 07 51) |( 13 06 04 52 19 13 06 04 52 19 13 06 04 52 16 13 06 04 52 0c 13 06 04 52 0c 13 06 04 52) |( 12 07 05 53 18 12 07 05 53 18 12 07 05 53 17 12 07 05 53 0d 12 07 05 53 0d 12 07 05 53) |( 1d 08 0a 5c 17 1d 08 0a 5c 17 1d 08 0a 5c 18 1d 08 0a 5c 02 1d 08 0a 5c 02 1d 08 0a 5c) |( 1c 09 0b 5d 16 1c 09 0b 5d 16 1c 09 0b 5d 19 1c 09 0b 5d 03 1c 09 0b 5d 03 1c 09 0b 5d) |( 1f 0a 08 5e 15 1f 0a 08 5e 15 1f 0a 08 5e 1a 1f 0a 08 5e 00 1f 0a 08 5e 00 1f 0a 08 5e) |( 1e 0b 09 5f 14 1e 0b 09 5f 14 1e 0b 09 5f 1b 1e 0b 09 5f 01 1e 0b 09 5f 01 1e 0b 09 5f) |( 19 0c 0e 58 13 19 0c 0e 58 13 19 0c 0e 58 1c 19 0c 0e 58 06 19 0c 0e 58 06 19 0c 0e 58) )}
		$a2 = {(( 53 74 61 72 74 65 64 20 73 65 72 76 69 63 65 20 25 73 20 6f 6e 20 25 73) |( 52 75 60 73 75 64 65 21 72 64 73 77 68 62 64 21 24 72 21 6e 6f 21 24 72) |( 51 76 63 70 76 67 66 22 71 67 70 74 6b 61 67 22 27 71 22 6d 6c 22 27 71) |( 50 77 62 71 77 66 67 23 70 66 71 75 6a 60 66 23 26 70 23 6c 6d 23 26 70) |( 57 70 65 76 70 61 60 24 77 61 76 72 6d 67 61 24 21 77 24 6b 6a 24 21 77) |( 56 71 64 77 71 60 61 25 76 60 77 73 6c 66 60 25 20 76 25 6a 6b 25 20 76) |( 55 72 67 74 72 63 62 26 75 63 74 70 6f 65 63 26 23 75 26 69 68 26 23 75) |( 54 73 66 75 73 62 63 27 74 62 75 71 6e 64 62 27 22 74 27 68 69 27 22 74) |( 5b 7c 69 7a 7c 6d 6c 28 7b 6d 7a 7e 61 6b 6d 28 2d 7b 28 67 66 28 2d 7b) |( 5a 7d 68 7b 7d 6c 6d 29 7a 6c 7b 7f 60 6a 6c 29 2c 7a 29 66 67 29 2c 7a) |( 59 7e 6b 78 7e 6f 6e 2a 79 6f 78 7c 63 69 6f 2a 2f 79 2a 65 64 2a 2f 79) |( 58 7f 6a 79 7f 6e 6f 2b 78 6e 79 7d 62 68 6e 2b 2e 78 2b 64 65 2b 2e 78) |( 5f 78 6d 7e 78 69 68 2c 7f 69 7e 7a 65 6f 69 2c 29 7f 2c 63 62 2c 29 7f) |( 5e 79 6c 7f 79 68 69 2d 7e 68 7f 7b 64 6e 68 2d 28 7e 2d 62 63 2d 28 7e) |( 5d 7a 6f 7c 7a 6b 6a 2e 7d 6b 7c 78 67 6d 6b 2e 2b 7d 2e 61 60 2e 2b 7d) |( 5c 7b 6e 7d 7b 6a 6b 2f 7c 6a 7d 79 66 6c 6a 2f 2a 7c 2f 60 61 2f 2a 7c) |( 43 64 71 62 64 75 74 30 63 75 62 66 79 73 75 30 35 63 30 7f 7e 30 35 63) |( 42 65 70 63 65 74 75 31 62 74 63 67 78 72 74 31 34 62 31 7e 7f 31 34 62) |( 41 66 73 60 66 77 76 32 61 77 60 64 7b 71 77 32 37 61 32 7d 7c 32 37 61) |( 40 67 72 61 67 76 77 33 60 76 61 65 7a 70 76 33 36 60 33 7c 7d 33 36 60) |( 47 60 75 66 60 71 70 34 67 71 66 62 7d 77 71 34 31 67 34 7b 7a 34 31 67) |( 46 61 74 67 61 70 71 35 66 70 67 63 7c 76 70 35 30 66 35 7a 7b 35 30 66) |( 45 62 77 64 62 73 72 36 65 73 64 60 7f 75 73 36 33 65 36 79 78 36 33 65) |( 44 63 76 65 63 72 73 37 64 72 65 61 7e 74 72 37 32 64 37 78 79 37 32 64) |( 4b 6c 79 6a 6c 7d 7c 38 6b 7d 6a 6e 71 7b 7d 38 3d 6b 38 77 76 38 3d 6b) |( 4a 6d 78 6b 6d 7c 7d 39 6a 7c 6b 6f 70 7a 7c 39 3c 6a 39 76 77 39 3c 6a) |( 49 6e 7b 68 6e 7f 7e 3a 69 7f 68 6c 73 79 7f 3a 3f 69 3a 75 74 3a 3f 69) |( 48 6f 7a 69 6f 7e 7f 3b 68 7e 69 6d 72 78 7e 3b 3e 68 3b 74 75 3b 3e 68) |( 4f 68 7d 6e 68 79 78 3c 6f 79 6e 6a 75 7f 79 3c 39 6f 3c 73 72 3c 39 6f) |( 4e 69 7c 6f 69 78 79 3d 6e 78 6f 6b 74 7e 78 3d 38 6e 3d 72 73 3d 38 6e) |( 4d 6a 7f 6c 6a 7b 7a 3e 6d 7b 6c 68 77 7d 7b 3e 3b 6d 3e 71 70 3e 3b 6d) |( 4c 6b 7e 6d 6b 7a 7b 3f 6c 7a 6d 69 76 7c 7a 3f 3a 6c 3f 70 71 3f 3a 6c) |( 73 54 41 52 54 45 44 00 53 45 52 56 49 43 45 00 05 53 00 4f 4e 00 05 53) |( 72 55 40 53 55 44 45 01 52 44 53 57 48 42 44 01 04 52 01 4e 4f 01 04 52) |( 71 56 43 50 56 47 46 02 51 47 50 54 4b 41 47 02 07 51 02 4d 4c 02 07 51) |( 70 57 42 51 57 46 47 03 50 46 51 55 4a 40 46 03 06 50 03 4c 4d 03 06 50) |( 77 50 45 56 50 41 40 04 57 41 56 52 4d 47 41 04 01 57 04 4b 4a 04 01 57) |( 76 51 44 57 51 40 41 05 56 40 57 53 4c 46 40 05 00 56 05 4a 4b 05 00 56) |( 75 52 47 54 52 43 42 06 55 43 54 50 4f 45 43 06 03 55 06 49 48 06 03 55) |( 74 53 46 55 53 42 43 07 54 42 55 51 4e 44 42 07 02 54 07 48 49 07 02 54) |( 7b 5c 49 5a 5c 4d 4c 08 5b 4d 5a 5e 41 4b 4d 08 0d 5b 08 47 46 08 0d 5b) |( 7a 5d 48 5b 5d 4c 4d 09 5a 4c 5b 5f 40 4a 4c 09 0c 5a 09 46 47 09 0c 5a) |( 79 5e 4b 58 5e 4f 4e 0a 59 4f 58 5c 43 49 4f 0a 0f 59 0a 45 44 0a 0f 59) |( 78 5f 4a 59 5f 4e 4f 0b 58 4e 59 5d 42 48 4e 0b 0e 58 0b 44 45 0b 0e 58) |( 7f 58 4d 5e 58 49 48 0c 5f 49 5e 5a 45 4f 49 0c 09 5f 0c 43 42 0c 09 5f) |( 7e 59 4c 5f 59 48 49 0d 5e 48 5f 5b 44 4e 48 0d 08 5e 0d 42 43 0d 08 5e) |( 7d 5a 4f 5c 5a 4b 4a 0e 5d 4b 5c 58 47 4d 4b 0e 0b 5d 0e 41 40 0e 0b 5d) |( 7c 5b 4e 5d 5b 4a 4b 0f 5c 4a 5d 59 46 4c 4a 0f 0a 5c 0f 40 41 0f 0a 5c) |( 63 44 51 42 44 55 54 10 43 55 42 46 59 53 55 10 15 43 10 5f 5e 10 15 43) |( 62 45 50 43 45 54 55 11 42 54 43 47 58 52 54 11 14 42 11 5e 5f 11 14 42) |( 61 46 53 40 46 57 56 12 41 57 40 44 5b 51 57 12 17 41 12 5d 5c 12 17 41) |( 60 47 52 41 47 56 57 13 40 56 41 45 5a 50 56 13 16 40 13 5c 5d 13 16 40) |( 67 40 55 46 40 51 50 14 47 51 46 42 5d 57 51 14 11 47 14 5b 5a 14 11 47) |( 66 41 54 47 41 50 51 15 46 50 47 43 5c 56 50 15 10 46 15 5a 5b 15 10 46) |( 65 42 57 44 42 53 52 16 45 53 44 40 5f 55 53 16 13 45 16 59 58 16 13 45) |( 64 43 56 45 43 52 53 17 44 52 45 41 5e 54 52 17 12 44 17 58 59 17 12 44) |( 6b 4c 59 4a 4c 5d 5c 18 4b 5d 4a 4e 51 5b 5d 18 1d 4b 18 57 56 18 1d 4b) |( 6a 4d 58 4b 4d 5c 5d 19 4a 5c 4b 4f 50 5a 5c 19 1c 4a 19 56 57 19 1c 4a) |( 69 4e 5b 48 4e 5f 5e 1a 49 5f 48 4c 53 59 5f 1a 1f 49 1a 55 54 1a 1f 49) |( 68 4f 5a 49 4f 5e 5f 1b 48 5e 49 4d 52 58 5e 1b 1e 48 1b 54 55 1b 1e 48) |( 6f 48 5d 4e 48 59 58 1c 4f 59 4e 4a 55 5f 59 1c 19 4f 1c 53 52 1c 19 4f) )}
		$a3 = {(( 25 73 20 61 73 20 25 73 5c 25 73 3a 20 25 64) |( 24 72 21 60 72 21 24 72 5d 24 72 3b 21 24 65) |( 27 71 22 63 71 22 27 71 5e 27 71 38 22 27 66) |( 26 70 23 62 70 23 26 70 5f 26 70 39 23 26 67) |( 21 77 24 65 77 24 21 77 58 21 77 3e 24 21 60) |( 20 76 25 64 76 25 20 76 59 20 76 3f 25 20 61) |( 23 75 26 67 75 26 23 75 5a 23 75 3c 26 23 62) |( 22 74 27 66 74 27 22 74 5b 22 74 3d 27 22 63) |( 2d 7b 28 69 7b 28 2d 7b 54 2d 7b 32 28 2d 6c) |( 2c 7a 29 68 7a 29 2c 7a 55 2c 7a 33 29 2c 6d) |( 2f 79 2a 6b 79 2a 2f 79 56 2f 79 30 2a 2f 6e) |( 2e 78 2b 6a 78 2b 2e 78 57 2e 78 31 2b 2e 6f) |( 29 7f 2c 6d 7f 2c 29 7f 50 29 7f 36 2c 29 68) |( 28 7e 2d 6c 7e 2d 28 7e 51 28 7e 37 2d 28 69) |( 2b 7d 2e 6f 7d 2e 2b 7d 52 2b 7d 34 2e 2b 6a) |( 2a 7c 2f 6e 7c 2f 2a 7c 53 2a 7c 35 2f 2a 6b) |( 35 63 30 71 63 30 35 63 4c 35 63 2a 30 35 74) |( 34 62 31 70 62 31 34 62 4d 34 62 2b 31 34 75) |( 37 61 32 73 61 32 37 61 4e 37 61 28 32 37 76) |( 36 60 33 72 60 33 36 60 4f 36 60 29 33 36 77) |( 31 67 34 75 67 34 31 67 48 31 67 2e 34 31 70) |( 30 66 35 74 66 35 30 66 49 30 66 2f 35 30 71) |( 33 65 36 77 65 36 33 65 4a 33 65 2c 36 33 72) |( 32 64 37 76 64 37 32 64 4b 32 64 2d 37 32 73) |( 3d 6b 38 79 6b 38 3d 6b 44 3d 6b 22 38 3d 7c) |( 3c 6a 39 78 6a 39 3c 6a 45 3c 6a 23 39 3c 7d) |( 3f 69 3a 7b 69 3a 3f 69 46 3f 69 20 3a 3f 7e) |( 3e 68 3b 7a 68 3b 3e 68 47 3e 68 21 3b 3e 7f) |( 39 6f 3c 7d 6f 3c 39 6f 40 39 6f 26 3c 39 78) |( 38 6e 3d 7c 6e 3d 38 6e 41 38 6e 27 3d 38 79) |( 3b 6d 3e 7f 6d 3e 3b 6d 42 3b 6d 24 3e 3b 7a) |( 3a 6c 3f 7e 6c 3f 3a 6c 43 3a 6c 25 3f 3a 7b) |( 05 53 00 41 53 00 05 53 7c 05 53 1a 00 05 44) |( 04 52 01 40 52 01 04 52 7d 04 52 1b 01 04 45) |( 07 51 02 43 51 02 07 51 7e 07 51 18 02 07 46) |( 06 50 03 42 50 03 06 50 7f 06 50 19 03 06 47) |( 01 57 04 45 57 04 01 57 78 01 57 1e 04 01 40) |( 00 56 05 44 56 05 00 56 79 00 56 1f 05 00 41) |( 03 55 06 47 55 06 03 55 7a 03 55 1c 06 03 42) |( 02 54 07 46 54 07 02 54 7b 02 54 1d 07 02 43) |( 0d 5b 08 49 5b 08 0d 5b 74 0d 5b 12 08 0d 4c) |( 0c 5a 09 48 5a 09 0c 5a 75 0c 5a 13 09 0c 4d) |( 0f 59 0a 4b 59 0a 0f 59 76 0f 59 10 0a 0f 4e) |( 0e 58 0b 4a 58 0b 0e 58 77 0e 58 11 0b 0e 4f) |( 09 5f 0c 4d 5f 0c 09 5f 70 09 5f 16 0c 09 48) |( 08 5e 0d 4c 5e 0d 08 5e 71 08 5e 17 0d 08 49) |( 0b 5d 0e 4f 5d 0e 0b 5d 72 0b 5d 14 0e 0b 4a) |( 0a 5c 0f 4e 5c 0f 0a 5c 73 0a 5c 15 0f 0a 4b) |( 15 43 10 51 43 10 15 43 6c 15 43 0a 10 15 54) |( 14 42 11 50 42 11 14 42 6d 14 42 0b 11 14 55) |( 17 41 12 53 41 12 17 41 6e 17 41 08 12 17 56) |( 16 40 13 52 40 13 16 40 6f 16 40 09 13 16 57) |( 11 47 14 55 47 14 11 47 68 11 47 0e 14 11 50) |( 10 46 15 54 46 15 10 46 69 10 46 0f 15 10 51) |( 13 45 16 57 45 16 13 45 6a 13 45 0c 16 13 52) |( 12 44 17 56 44 17 12 44 6b 12 44 0d 17 12 53) |( 1d 4b 18 59 4b 18 1d 4b 64 1d 4b 02 18 1d 5c) |( 1c 4a 19 58 4a 19 1c 4a 65 1c 4a 03 19 1c 5d) |( 1f 49 1a 5b 49 1a 1f 49 66 1f 49 00 1a 1f 5e) |( 1e 48 1b 5a 48 1b 1e 48 67 1e 48 01 1b 1e 5f) |( 19 4f 1c 5d 4f 1c 19 4f 60 19 4f 06 1c 19 58) )}
		$b_x64 = {4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03}
		$b_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}

	condition:
		all of ( $ver3* ) or all of ( $ver4* ) or 2 of ( $a* ) or any of ( $b* ) or 5 of ( $s* ) or ( all of ( $pwsh* ) and 2 of ( $s* ) ) or ( #s9 > 6 and 4 of them )
}

rule MALW_cobaltrike : hardened
{
	meta:
		description = "Rule to detect CobaltStrike beacon"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2020-07-19"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/CobaltStrike"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		hash1 = "f47a627880bfa4a117fec8be74ab206690e5eb0e9050331292e032cd22883f5b"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"
		ruleset = "MALW_cobaltstrike.yar"
		repository = "advanced-threat-research/Yara-Rules"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules/blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_cobaltstrike.yar"
		license = "Apache License 2.0"
		score = 75
		vetted_family = "cobalt"

	strings:
		$pattern_0 = { e9???????? eb0a b801000000 e9???????? }
		$pattern_1 = { 3bc7 750d ff15???????? 3d33270000 }
		$pattern_2 = { 8bd0 e8???????? 85c0 7e0e }
		$pattern_3 = { 50 8d8d24efffff 51 e8???????? }
		$pattern_4 = { 03b5d4eeffff 89b5c8eeffff 3bf7 72bd 3bf7 }
		$pattern_5 = { 8b450c 8945f4 8d45f4 50 }
		$pattern_6 = { 33c5 8945fc 8b4508 53 56 ff750c 33db }
		$pattern_7 = { e8???????? e9???????? 833d????????01 7505 e8???????? }
		$pattern_8 = { 53 53 8d85f4faffff 50 }
		$pattern_9 = { 68???????? 53 50 e8???????? 83c424 }
		$pattern_10 = { 488b4c2420 8b0401 8b4c2408 33c8 8bc1 89442408 }
		$pattern_11 = { 488d4d97 e8???????? 4c8d9c24d0000000 418bc7 498b5b20 498b7328 498b7b30 }
		$pattern_12 = { bd08000000 85d2 7459 ffcf 4d85ed }
		$pattern_13 = { 4183c9ff 33d2 ff15???????? 4c63c0 4983f8ff }
		$pattern_14 = { 49c1e002 e8???????? 03f3 4d8d349e 3bf5 7d13 }
		$pattern_15 = { 752c 4c8d45af 488d55af 488d4d27 }

	condition:
		7 of them and filesize < 696320
}

rule cobaltstrike_beacon_raw : hardened
{
	meta:
		score = 75

	strings:
		$s1 = {25 64 20 69 73 20 61 6e 20 78 36 34 20 70 72 6f 63 65 73 73 20 28 63 61 6e 27 74 20 69 6e 6a 65 63 74 20 78 38 36 20 63 6f 6e 74 65 6e 74 29}
		$s2 = {46 61 69 6c 65 64 20 74 6f 20 69 6d 70 65 72 73 6f 6e 61 74 65 20 6c 6f 67 67 65 64 20 6f 6e 20 75 73 65 72 20 25 64 20 28 25 75 29}
		$s3 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 70 20 2d 65 78 65 63 20 62 79 70 61 73 73 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 20 22 25 73 22}
		$s4 = {49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 63 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 3a 25 75 2f 27 29 3b 20 25 73}
		$s5 = {63 6f 75 6c 64 20 6e 6f 74 20 72 75 6e 20 63 6f 6d 6d 61 6e 64 20 28 77 2f 20 74 6f 6b 65 6e 29 20 62 65 63 61 75 73 65 20 6f 66 20 69 74 73 20 6c 65 6e 67 74 68 20 6f 66 20 25 64 20 62 79 74 65 73 21}
		$s6 = {63 6f 75 6c 64 20 6e 6f 74 20 77 72 69 74 65 20 74 6f 20 70 72 6f 63 65 73 73 20 6d 65 6d 6f 72 79 3a 20 25 64}
		$s7 = {25 73 2e 34 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 78 25 78 2e 25 73}
		$s8 = {43 6f 75 6c 64 20 6e 6f 74 20 63 6f 6e 6e 65 63 74 20 74 6f 20 70 69 70 65 20 28 25 73 29 3a 20 25 64}
		$b1 = {62 65 61 63 6f 6e 2e 64 6c 6c}
		$b2 = {62 65 61 63 6f 6e 2e 78 38 36 2e 64 6c 6c}
		$b3 = {62 65 61 63 6f 6e 2e 78 36 34 2e 64 6c 6c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( any of ( $b* ) or 5 of ( $s* ) )
}

rule cobaltstrike_beacon_b64 : hardened
{
	meta:
		score = 75

	strings:
		$s1a = {4a 57 51 67 61 58 4d 67 59 57 34 67 65 44 59 30 49 48 42 79 62 32 4e 6c 63 33 4d 67 4b 47 4e 68 62 69 64 30 49 47 6c 75 61 6d}
		$s1b = {5a 43 42 70 63 79 42 68 62 69 42 34 4e 6a 51 67 63 48 4a 76 59 32 56 7a 63 79 41 6f 59 32 46 75 4a 33 51 67 61 57 35 71 5a 57}
		$s1c = {49 47 6c 7a 49 47 46 75 49 48 67 32 4e 43 42 77 63 6d 39 6a 5a 58 4e 7a 49 43 68 6a 59 57 34 6e 64 43 42 70 62 6d 70 6c 59 33}
		$s2a = {52 6d 46 70 62 47 56 6b 49 48 52 76 49 47 6c 74 63 47 56 79 63 32 39 75 59 58 52 6c 49 47 78 76 5a 32 64 6c 5a 43 42 76 62 69}
		$s2b = {59 57 6c 73 5a 57 51 67 64 47 38 67 61 57 31 77 5a 58 4a 7a 62 32 35 68 64 47 55 67 62 47 39 6e 5a 32 56 6b 49 47 39 75 49 48}
		$s2c = {61 57 78 6c 5a 43 42 30 62 79 42 70 62 58 42 6c 63 6e 4e 76 62 6d 46 30 5a 53 42 73 62 32 64 6e 5a 57 51 67 62 32 34 67 64 58}
		$s3a = {63 47 39 33 5a 58 4a 7a 61 47 56 73 62 43 41 74 62 6d 39 77 49 43 31 6c 65 47 56 6a 49 47 4a 35 63 47 46 7a 63 79 41 74 52 57}
		$s3b = {62 33 64 6c 63 6e 4e 6f 5a 57 78 73 49 43 31 75 62 33 41 67 4c 57 56 34 5a 57 4d 67 59 6e 6c 77 59 58 4e 7a 49 43 31 46 62 6d}
		$s3c = {64 32 56 79 63 32 68 6c 62 47 77 67 4c 57 35 76 63 43 41 74 5a 58 68 6c 59 79 42 69 65 58 42 68 63 33 4d 67 4c 55 56 75 59 32}
		$s4a = {53 55 56 59 49 43 68 4f 5a 58 63 74 54 32 4a 71 5a 57 4e 30 49 45 35 6c 64 43 35 58 5a 57 4a 6a 62 47 6c 6c 62 6e 51 70 4c 6b}
		$s4b = {52 56 67 67 4b 45 35 6c 64 79 31 50 59 6d 70 6c 59 33 51 67 54 6d 56 30 4c 6c 64 6c 59 6d 4e 73 61 57 56 75 64 43 6b 75 52 47}
		$s4c = {57 43 41 6f 54 6d 56 33 4c 55 39 69 61 6d 56 6a 64 43 42 4f 5a 58 51 75 56 32 56 69 59 32 78 70 5a 57 35 30 4b 53 35 45 62 33}

	condition:
		filesize < 1000KB and 5 of ( $s* )
}

rule CobaltStrike_Sleeve_BeaconLoader_HA_x86_o_v4_3_v4_4_v4_5_and_v4_6 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.HA.x86.o (HeapAlloc) Versions 4.3 through at least 4.6"
		hash = "8e4a1862aa3693f0e9011ade23ad3ba036c76ae8ccfb6585dc19ceb101507dcd"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		ruleset = "CobaltStrike__Sleeve_BeaconLoader_all.yara"
		repository = "chronicle/GCTI"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$core_sig = {
      C6 45 F0 48
      C6 45 F1 65
      C6 45 F2 61
      C6 45 F3 70
      C6 45 F4 41
      C6 45 F5 6C
      C6 45 F6 6C
      C6 45 F7 6F
      C6 45 F8 63
      C6 45 F9 00
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_MVF_x86_o_v4_3_v4_4_v4_5_and_v4_6 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x86.o (MapViewOfFile) Versions 4.3 through at least 4.6"
		hash = "cded3791caffbb921e2afa2de4c04546067c3148c187780066e8757e67841b44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		ruleset = "CobaltStrike__Sleeve_BeaconLoader_all.yara"
		repository = "chronicle/GCTI"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$core_sig = {
      C6 45 EC 4D
      C6 45 ED 61
      C6 45 EE 70
      C6 45 EF 56
      C6 45 F0 69
      C6 45 F1 65
      C6 45 F2 77
      C6 45 F3 4F
      C6 45 F4 66
      C6 45 F5 46
      C6 45 F6 69
      C6 45 F7 6C
      C6 45 F8 65
      C6 45 F9 00
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_VA_x86_o_v4_3_v4_4_v4_5_and_v4_6 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.VA.x86.o (VirtualAlloc) Versions 4.3 through at least 4.6"
		hash = "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		ruleset = "CobaltStrike__Sleeve_BeaconLoader_all.yara"
		repository = "chronicle/GCTI"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$core_sig = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }
		$deobfuscator = {
      8B 4D FC
      83 C1 01
      89 4D FC
      8B 55 FC
      3B 55 0C
      73 19
      0F B6 45 10
      8B 4D 08
      03 4D FC
      0F BE 11
      33 D0
      8B 45 08
      03 45 FC
      88 10
      EB D6
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_x86_o_v4_3_v4_4_v4_5_and_v4_6 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.x86.o Versions 4.3 through at least 4.6"
		hash = "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		ruleset = "CobaltStrike__Sleeve_BeaconLoader_all.yara"
		repository = "chronicle/GCTI"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$core_sig = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }
		$deobfuscator = {
      8B 4D FC
      83 C1 01
      89 4D FC
      8B 55 FC
      3B 55 0C
      73 19
      0F B6 45 10
      8B 4D 08
      03 4D FC
      0F BE 11
      33 D0
      8B 45 08
      03 45 FC
      88 10
      EB D6
    }

	condition:
		$core_sig and not $deobfuscator
}

rule CobaltStrike_Sleeve_BeaconLoader_HA_x64_o_v4_3_v4_4_v4_5_and_v4_6 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.HA.x64.o (HeapAlloc) Versions 4.3 through at least 4.6"
		hash = "d64f10d5a486f0f2215774e8ab56087f32bef19ac666e96c5627c70d345a354d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		ruleset = "CobaltStrike__Sleeve_BeaconLoader_all.yara"
		repository = "chronicle/GCTI"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$core_sig = {
      C6 44 24 38 48
      C6 44 24 39 65
      C6 44 24 3A 61
      C6 44 24 3B 70
      C6 44 24 3C 41
      C6 44 24 3D 6C
      C6 44 24 3E 6C
      C6 44 24 3F 6F
      C6 44 24 40 63
      C6 44 24 41 00
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_MVF_x64_o_v4_3_v4_4_v4_5_and_v4_6 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x64.o (MapViewOfFile) Versions 4.3 through at least 4.6"
		hash = "9d5b6ccd0d468da389657309b2dc325851720390f9a5f3d3187aff7d2cd36594"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		ruleset = "CobaltStrike__Sleeve_BeaconLoader_all.yara"
		repository = "chronicle/GCTI"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$core_sig = {
      C6 44 24 58 4D
      C6 44 24 59 61
      C6 44 24 5A 70
      C6 44 24 5B 56
      C6 44 24 5C 69
      C6 44 24 5D 65
      C6 44 24 5E 77
      C6 44 24 5F 4F
      C6 44 24 60 66
      C6 44 24 61 46
      C6 44 24 62 69
      C6 44 24 63 6C
      C6 44 24 64 65
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_VA_x64_o_v4_3_v4_4_v4_5_and_v4_6 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.VA.x64.o (VirtualAlloc) Versions 4.3 through at least 4.6"
		hash = "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		ruleset = "CobaltStrike__Sleeve_BeaconLoader_all.yara"
		repository = "chronicle/GCTI"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$core_sig = {
      C6 44 24 48 56
      C6 44 24 49 69
      C6 44 24 4A 72
      C6 44 24 4B 74
      C6 44 24 4C 75
      C6 44 24 4D 61
      C6 44 24 4E 6C
      C6 44 24 4F 41
      C6 44 24 50 6C
      C6 44 24 51 6C
      C6 44 24 52 6F
      C6 44 24 53 63
      C6 44 24 54 00
    }
		$deobfuscator = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }

	condition:
		all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_x64_o_v4_3_v4_4_v4_5_and_v4_6 : hardened
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.x64.o (Base) Versions 4.3 through at least 4.6"
		hash = "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		ruleset = "CobaltStrike__Sleeve_BeaconLoader_all.yara"
		repository = "chronicle/GCTI"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Sleeve_BeaconLoader_all.yara"
		license = "Apache License 2.0"
		score = 75

	strings:
		$core_sig = {
      33 C0
      83 F8 01
      74 63
      48 8B 44 24 20
      0F B7 00
      3D 4D 5A 00 00
      75 45
      48 8B 44 24 20
      48 63 40 3C
      48 89 44 24 28
      48 83 7C 24 28 40
      72 2F
      48 81 7C 24 28 00 04 00 00
      73 24
      48 8B 44 24 20
      48 8B 4C 24 28
      48 03 C8
      48 8B C1
      48 89 44 24 28
      48 8B 44 24 28
      81 38 50 45 00 00
      75 02
    }
		$deobfuscator = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }

	condition:
		$core_sig and not $deobfuscator
}

rule MAL_CobaltStrike_Oct_2021_1 : hardened
{
	meta:
		description = "Detect Cobalt Strike implant"
		author = "Arkbird_SOLG"
		reference = "https://twitter.com/malwrhunterteam/status/1454154412902002692"
		date = "2021-10-30"
		hash1 = "f520f97e3aa065efc4b7633735530a7ea341f3b332122921cb9257bf55147fb7"
		hash2 = "7370c09d07b4695aa11e299a9c17007e9267e1578ce2753259c02a8cf27b18b6"
		hash3 = "bfbc1c27a73c33e375eeea164dc876c23bca1fbc0051bb48d3ed3e50df6fa0e8"
		tlp = "white"
		adversary = "-"
		ruleset = "MAL_CobaltStrike_Oct_2021_1.yara"
		repository = "StrangerealIntel/DailyIOC"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-10-29/Hive/MAL_CobaltStrike_Oct_2021_1.yara"
		score = 75

	strings:
		$s1 = { 48 83 ec 10 4c 89 14 24 4c 89 5c 24 08 4d 33 db 4c 8d 54 24 18 4c 2b d0 4d 0f 42 d3 65 4c 8b 1c 25 10 00 00 00 4d 3b d3 f2 73 17 66 41 81 e2 00 f0 4d 8d 9b 00 f0 ff ff 41 c6 03 00 4d 3b d3 f2 75 ef 4c 8b 14 24 4c 8b 5c 24 08 48 83 c4 10 f2 c3 }
		$s2 = { 89 ?? 24 ?? 8b ?? 24 0c 89 ?? 24 ?? 8b ?? 24 ?? c1 ?? 0d 89 ?? 24 0c 48 8b ?? 24 10 89 ?? 24 [2] 8b ?? 24 10 }
		$s3 = { b8 10 00 00 00 48 89 45 ?? e8 [3] 00 48 29 c4 48 89 e0 48 8b 4d ?? 48 89 45 ?? 48 89 c8 e8 [3] 00 48 29 c4 48 89 e0 48 8b 4d ?? 48 89 45 ?? 48 89 c8 e8 [3] 00 48 29 c4 48 89 e0 48 8b 4d ?? 48 89 45 ?? 48 89 c8 e8 [3] 00 48 29 c4 48 89 e0 48 8b 4d ?? 48 89 45 ?? 48 89 c8 e8 [3] 00 48 29 c4 48 89 e0 48 8b 4d ?? 8b 55 f8 89 11 4c 8b 45 ?? 4c 8b 4d f0 4d 89 08 4c 8b 55 ?? 4c 8b 5d e8 4d 89 1a 48 8b 75 ?? 48 8b 7d e0 48 89 3e c7 00 ?? 00 00 00 48 8b 05 [3] 00 48 05 [2] 00 00 8b 19 4d 8b 00 4d 8b 32 48 8b 0e 48 83 ec 20 4c 89 f2 41 89 d9 ff d0 48 83 c4 20 ?? 45 }
		$s4 = { 48 83 ec 48 44 89 4c 24 44 4c 89 44 24 38 48 89 54 24 30 48 89 4c 24 28 c7 44 24 24 ?? 00 00 00 48 8b 05 [3] 00 48 05 [2] 00 00 44 8b 4c 24 44 4c 8b 44 24 38 48 8b 54 24 30 48 8b 4c 24 28 ff d0 90 48 83 c4 }

	condition:
		uint16( 0 ) == 0x5A4D and filesize > 20KB and 3 of ( $s* )
}

rule Windows_Trojan_CobaltStrike_c851687a : hardened
{
	meta:
		author = "Elastic Security"
		id = "c851687a-aac6-43e7-a0b6-6aed36dcf12e"
		fingerprint = "70224e28a223d09f2211048936beb9e2d31c0312c97a80e22c85e445f1937c10"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies UAC Bypass module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {62 79 70 61 73 73 75 61 63 2e 64 6c 6c}
		$a2 = {62 79 70 61 73 73 75 61 63 2e 78 36 34 2e 64 6c 6c}
		$a3 = {5c 5c 2e 5c 70 69 70 65 5c 62 79 70 61 73 73 75 61 63}
		$b1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 79 00 73 00 70 00 72 00 65 00 70 00 5c 00 73 00 79 00 73 00 70 00 72 00 65 00 70 00 2e 00 65 00 78 00 65 00}
		$b2 = {5b 2d 5d 20 43 6f 75 6c 64 20 6e 6f 74 20 77 72 69 74 65 20 74 65 6d 70 20 44 4c 4c 20 74 6f 20 27 25 53 27}
		$b3 = {5b 2a 5d 20 43 6c 65 61 6e 75 70 20 73 75 63 63 65 73 73 66 75 6c}
		$b4 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6c 00 69 00 63 00 6f 00 6e 00 66 00 67 00 2e 00 65 00 78 00 65 00}
		$b5 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 65 00 76 00 65 00 6e 00 74 00 76 00 77 00 72 00 2e 00 65 00 78 00 65 00}
		$b6 = {5b 2d 5d 20 25 53 20 72 61 6e 20 74 6f 6f 20 6c 6f 6e 67 2e 20 43 6f 75 6c 64 20 6e 6f 74 20 74 65 72 6d 69 6e 61 74 65 20 74 68 65 20 70 72 6f 63 65 73 73 2e}
		$b7 = {5b 2a 5d 20 57 72 6f 74 65 20 68 69 6a 61 63 6b 20 44 4c 4c 20 74 6f 20 27 25 53 27}
		$b8 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 79 00 73 00 70 00 72 00 65 00 70 00 5c 00}
		$b9 = {5b 2d 5d 20 43 4f 4d 20 69 6e 69 74 69 61 6c 69 7a 61 74 69 6f 6e 20 66 61 69 6c 65 64 2e}
		$b10 = {5b 2d 5d 20 50 72 69 76 69 6c 65 67 65 64 20 66 69 6c 65 20 63 6f 70 79 20 66 61 69 6c 65 64 3a 20 25 53}
		$b11 = {5b 2d 5d 20 46 61 69 6c 65 64 20 74 6f 20 73 74 61 72 74 20 25 53 3a 20 25 64}
		$b12 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72}
		$b13 = {5b 2d 5d 20 27 25 53 27 20 65 78 69 73 74 73 20 69 6e 20 44 4c 4c 20 68 69 6a 61 63 6b 20 6c 6f 63 61 74 69 6f 6e 2e}
		$b14 = {5b 2d 5d 20 43 6c 65 61 6e 75 70 20 66 61 69 6c 65 64 2e 20 52 65 6d 6f 76 65 3a 20 25 53}
		$b15 = {5b 2b 5d 20 25 53 20 72 61 6e 20 61 6e 64 20 65 78 69 74 65 64 2e}
		$b16 = {5b 2b 5d 20 50 72 69 76 69 6c 65 67 65 64 20 66 69 6c 65 20 63 6f 70 79 20 73 75 63 63 65 73 73 21 20 25 53}

	condition:
		2 of ( $a* ) or 10 of ( $b* )
}

rule Windows_Trojan_CobaltStrike_0b58325e : hardened
{
	meta:
		author = "Elastic Security"
		id = "0b58325e-2538-434d-9a2c-26e2c32db039"
		fingerprint = "8ecd5bdce925ae5d4f90cecb9bc8c3901b54ba1c899a33354bcf529eeb2485d4"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Keylogger module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {6b 65 79 6c 6f 67 67 65 72 2e 64 6c 6c}
		$a2 = {6b 65 79 6c 6f 67 67 65 72 2e 78 36 34 2e 64 6c 6c}
		$a3 = {5c 5c 2e 5c 70 69 70 65 5c 6b 65 79 6c 6f 67 67 65 72}
		$a4 = {25 63 45 3d 3d 3d 3d 3d 3d 3d 25 63}
		$a5 = {5b 75 6e 6b 6e 6f 77 6e 3a 20 25 30 32 58 5d}
		$b1 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72}
		$b2 = {25 63 32 25 73 25 63}
		$b3 = {5b 6e 75 6d 6c 6f 63 6b 5d}
		$b4 = {25 63 43 25 73}
		$b5 = {5b 62 61 63 6b 73 70 61 63 65 5d}
		$b6 = {5b 73 63 72 6f 6c 6c 20 6c 6f 63 6b 5d}
		$b7 = {5b 63 6f 6e 74 72 6f 6c 5d}
		$b8 = {5b 6c 65 66 74 5d}
		$b9 = {5b 70 61 67 65 20 75 70 5d}
		$b10 = {5b 70 61 67 65 20 64 6f 77 6e 5d}
		$b11 = {5b 70 72 74 73 63 72 5d}
		$b12 = {5a 52 69 63 68 39}
		$b13 = {5b 63 74 72 6c 5d}
		$b14 = {5b 68 6f 6d 65 5d}
		$b15 = {5b 70 61 75 73 65 5d}
		$b16 = {5b 63 6c 65 61 72 5d}

	condition:
		1 of ( $a* ) and 14 of ( $b* )
}

rule Windows_Trojan_CobaltStrike_2b8cddf8 : hardened
{
	meta:
		author = "Elastic Security"
		id = "2b8cddf8-ca7a-4f85-be9d-6d8534d0482e"
		fingerprint = "0d7d28d79004ca61b0cfdcda29bd95e3333e6fc6e6646a3f6ba058aa01bee188"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies dll load module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 64 6c 6c 6c 6f 61 64 2e 78 36 34 2e 6f}
		$a2 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 64 6c 6c 6c 6f 61 64 2e 78 38 36 2e 6f}
		$b1 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 45 72 72 6f 72 44 44}
		$b2 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 45 72 72 6f 72 4e 41}
		$b3 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 45 72 72 6f 72 44}
		$b4 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 44 61 74 61 49 6e 74}
		$b5 = {5f 5f 69 6d 70 5f 4b 45 52 4e 45 4c 33 32 24 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79}
		$b6 = {5f 5f 69 6d 70 5f 4b 45 52 4e 45 4c 33 32 24 4f 70 65 6e 50 72 6f 63 65 73 73}
		$b7 = {5f 5f 69 6d 70 5f 4b 45 52 4e 45 4c 33 32 24 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64}
		$b8 = {5f 5f 69 6d 70 5f 4b 45 52 4e 45 4c 33 32 24 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78}
		$c1 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 45 72 72 6f 72 44 44}
		$c2 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 45 72 72 6f 72 4e 41}
		$c3 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 45 72 72 6f 72 44}
		$c4 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 44 61 74 61 49 6e 74}
		$c5 = {5f 5f 69 6d 70 5f 5f 4b 45 52 4e 45 4c 33 32 24 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79}
		$c6 = {5f 5f 69 6d 70 5f 5f 4b 45 52 4e 45 4c 33 32 24 4f 70 65 6e 50 72 6f 63 65 73 73}
		$c7 = {5f 5f 69 6d 70 5f 5f 4b 45 52 4e 45 4c 33 32 24 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64}
		$c8 = {5f 5f 69 6d 70 5f 5f 4b 45 52 4e 45 4c 33 32 24 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78}

	condition:
		1 of ( $a* ) or 5 of ( $b* ) or 5 of ( $c* )
}

rule Windows_Trojan_CobaltStrike_59b44767 : hardened
{
	meta:
		author = "Elastic Security"
		id = "59b44767-c9a5-42c0-b177-7fe49afd7dfb"
		fingerprint = "882886a282ec78623a0d3096be3d324a8a1b8a23bcb88ea0548df2fae5e27aa5"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies getsystem module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 67 65 74 73 79 73 74 65 6d 2e 78 38 36 2e 6f}
		$a2 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 67 65 74 73 79 73 74 65 6d 2e 78 36 34 2e 6f}
		$b1 = {67 65 74 73 79 73 74 65 6d 20 66 61 69 6c 65 64 2e}
		$b2 = {5f 69 73 53 79 73 74 65 6d 53 49 44}
		$b3 = {5f 5f 69 6d 70 5f 5f 4e 54 44 4c 4c 24 4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e 40 31 36}
		$c1 = {67 65 74 73 79 73 74 65 6d 20 66 61 69 6c 65 64 2e}
		$c2 = {24 70 64 61 74 61 24 69 73 53 79 73 74 65 6d 53 49 44}
		$c3 = {24 75 6e 77 69 6e 64 24 69 73 53 79 73 74 65 6d 53 49 44}
		$c4 = {5f 5f 69 6d 70 5f 4e 54 44 4c 4c 24 4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e}

	condition:
		1 of ( $a* ) or 3 of ( $b* ) or 3 of ( $c* )
}

rule Windows_Trojan_CobaltStrike_7efd3c3f : hardened
{
	meta:
		author = "Elastic Security"
		id = "7efd3c3f-1104-4b46-9d1e-dc2c62381b8c"
		fingerprint = "9e7c7c9a7436f5ee4c27fd46d6f06e7c88f4e4d1166759573cedc3ed666e1838"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Hashdump module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 70
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {68 61 73 68 64 75 6d 70 2e 64 6c 6c}
		$a2 = {68 61 73 68 64 75 6d 70 2e 78 36 34 2e 64 6c 6c}
		$a3 = {5c 5c 2e 5c 70 69 70 65 5c 68 61 73 68 64 75 6d 70}
		$a4 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72}
		$a5 = {47 6c 6f 62 61 6c 5c 53 41 4d}
		$a6 = {47 6c 6f 62 61 6c 5c 46 52 45 45}
		$a7 = {5b 2d 5d 20 6e 6f 20 72 65 73 75 6c 74 73 2e}

	condition:
		4 of ( $a* )
}

rule Windows_Trojan_CobaltStrike_6e971281 : hardened
{
	meta:
		author = "Elastic Security"
		id = "6e971281-3ee3-402f-8a72-745ec8fb91fb"
		fingerprint = "62d97cf73618a1b4d773d5494b2761714be53d5cda774f9a96eaa512c8d5da12"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Interfaces module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 69 6e 74 65 72 66 61 63 65 73 2e 78 36 34 2e 6f}
		$a2 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 69 6e 74 65 72 66 61 63 65 73 2e 78 38 36 2e 6f}
		$b1 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 46 6f 72 6d 61 74 41 6c 6c 6f 63}
		$b2 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 46 6f 72 6d 61 74 50 72 69 6e 74 66}
		$b3 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 4f 75 74 70 75 74}
		$b4 = {5f 5f 69 6d 70 5f 4b 45 52 4e 45 4c 33 32 24 4c 6f 63 61 6c 41 6c 6c 6f 63}
		$b5 = {5f 5f 69 6d 70 5f 4b 45 52 4e 45 4c 33 32 24 4c 6f 63 61 6c 46 72 65 65}
		$b6 = {5f 5f 69 6d 70 5f 4c 6f 61 64 4c 69 62 72 61 72 79 41}
		$c1 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 46 6f 72 6d 61 74 41 6c 6c 6f 63}
		$c2 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 46 6f 72 6d 61 74 50 72 69 6e 74 66}
		$c3 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 4f 75 74 70 75 74}
		$c4 = {5f 5f 69 6d 70 5f 5f 4b 45 52 4e 45 4c 33 32 24 4c 6f 63 61 6c 41 6c 6c 6f 63}
		$c5 = {5f 5f 69 6d 70 5f 5f 4b 45 52 4e 45 4c 33 32 24 4c 6f 63 61 6c 46 72 65 65}
		$c6 = {5f 5f 69 6d 70 5f 5f 4c 6f 61 64 4c 69 62 72 61 72 79 41}

	condition:
		1 of ( $a* ) or 4 of ( $b* ) or 4 of ( $c* )
}

rule Windows_Trojan_CobaltStrike_09b79efa : hardened
{
	meta:
		author = "Elastic Security"
		id = "09b79efa-55d7-481d-9ee0-74ac5f787cef"
		fingerprint = "04ef6555e8668c56c528dc62184331a6562f47652c73de732e5f7c82779f2fd8"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Invoke Assembly module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {69 6e 76 6f 6b 65 61 73 73 65 6d 62 6c 79 2e 78 36 34 2e 64 6c 6c}
		$a2 = {69 6e 76 6f 6b 65 61 73 73 65 6d 62 6c 79 2e 64 6c 6c}
		$b1 = {5b 2d 5d 20 46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 64 65 66 61 75 6c 74 20 41 70 70 44 6f 6d 61 69 6e 20 77 2f 68 72 20 30 78 25 30 38 6c 78}
		$b2 = {5b 2d 5d 20 46 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 20 74 68 65 20 61 73 73 65 6d 62 6c 79 20 77 2f 68 72 20 30 78 25 30 38 6c 78}
		$b3 = {5b 2d 5d 20 46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 74 68 65 20 72 75 6e 74 69 6d 65 20 68 6f 73 74}
		$b4 = {5b 2d 5d 20 49 6e 76 6f 6b 65 5f 33 20 6f 6e 20 45 6e 74 72 79 50 6f 69 6e 74 20 66 61 69 6c 65 64 2e}
		$b5 = {5b 2d 5d 20 43 4c 52 20 66 61 69 6c 65 64 20 74 6f 20 73 74 61 72 74 20 77 2f 68 72 20 30 78 25 30 38 6c 78}
		$b6 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72}
		$b7 = {2e 4e 45 54 20 72 75 6e 74 69 6d 65 20 5b 76 65 72 20 25 53 5d 20 63 61 6e 6e 6f 74 20 62 65 20 6c 6f 61 64 65 64}
		$b8 = {5b 2d 5d 20 4e 6f 20 2e 4e 45 54 20 72 75 6e 74 69 6d 65 20 66 6f 75 6e 64 2e 20 3a 28}
		$b9 = {5b 2d 5d 20 49 43 6f 72 52 75 6e 74 69 6d 65 48 6f 73 74 3a 3a 47 65 74 44 65 66 61 75 6c 74 44 6f 6d 61 69 6e 20 66 61 69 6c 65 64 20 77 2f 68 72 20 30 78 25 30 38 6c 78}
		$c1 = { FF 57 0C 85 C0 78 40 8B 45 F8 8D 55 F4 8B 08 52 50 }

	condition:
		1 of ( $a* ) or 3 of ( $b* ) or 1 of ( $c* )
}

rule Windows_Trojan_CobaltStrike_6e77233e : hardened
{
	meta:
		author = "Elastic Security"
		id = "6e77233e-7fb4-4295-823d-f97786c5d9c4"
		fingerprint = "cef2949eae78b1c321c2ec4010749a5ac0551d680bd5eb85493fc88c5227d285"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Kerberos module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 6b 65 72 62 65 72 6f 73 2e 78 36 34 2e 6f}
		$a2 = {24 75 6e 77 69 6e 64 24 63 6f 6d 6d 61 6e 64 5f 6b 65 72 62 65 72 6f 73 5f 74 69 63 6b 65 74 5f 75 73 65}
		$a3 = {24 70 64 61 74 61 24 63 6f 6d 6d 61 6e 64 5f 6b 65 72 62 65 72 6f 73 5f 74 69 63 6b 65 74 5f 75 73 65}
		$a4 = {63 6f 6d 6d 61 6e 64 5f 6b 65 72 62 65 72 6f 73 5f 74 69 63 6b 65 74 5f 75 73 65}
		$a5 = {24 70 64 61 74 61 24 63 6f 6d 6d 61 6e 64 5f 6b 65 72 62 65 72 6f 73 5f 74 69 63 6b 65 74 5f 70 75 72 67 65}
		$a6 = {63 6f 6d 6d 61 6e 64 5f 6b 65 72 62 65 72 6f 73 5f 74 69 63 6b 65 74 5f 70 75 72 67 65}
		$a7 = {24 75 6e 77 69 6e 64 24 63 6f 6d 6d 61 6e 64 5f 6b 65 72 62 65 72 6f 73 5f 74 69 63 6b 65 74 5f 70 75 72 67 65}
		$a8 = {24 75 6e 77 69 6e 64 24 6b 65 72 62 65 72 6f 73 5f 69 6e 69 74}
		$a9 = {24 75 6e 77 69 6e 64 24 4b 65 72 62 65 72 6f 73 54 69 63 6b 65 74 55 73 65}
		$a10 = {4b 65 72 62 65 72 6f 73 54 69 63 6b 65 74 55 73 65}
		$a11 = {24 75 6e 77 69 6e 64 24 4b 65 72 62 65 72 6f 73 54 69 63 6b 65 74 50 75 72 67 65}
		$b1 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 6b 65 72 62 65 72 6f 73 2e 78 38 36 2e 6f}
		$b2 = {5f 63 6f 6d 6d 61 6e 64 5f 6b 65 72 62 65 72 6f 73 5f 74 69 63 6b 65 74 5f 75 73 65}
		$b3 = {5f 63 6f 6d 6d 61 6e 64 5f 6b 65 72 62 65 72 6f 73 5f 74 69 63 6b 65 74 5f 70 75 72 67 65}
		$b4 = {5f 6b 65 72 62 65 72 6f 73 5f 69 6e 69 74}
		$b5 = {5f 4b 65 72 62 65 72 6f 73 54 69 63 6b 65 74 55 73 65}
		$b6 = {5f 4b 65 72 62 65 72 6f 73 54 69 63 6b 65 74 50 75 72 67 65}
		$b7 = {5f 4c 73 61 43 61 6c 6c 4b 65 72 62 65 72 6f 73 50 61 63 6b 61 67 65}

	condition:
		5 of ( $a* ) or 3 of ( $b* )
}

rule Windows_Trojan_CobaltStrike_de42495a : hardened
{
	meta:
		author = "Elastic Security"
		id = "de42495a-0002-466e-98b9-19c9ebb9240e"
		fingerprint = "dab3c25809ec3af70df5a8a04a2efd4e8ecb13a4c87001ea699e7a1512973b82"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Mimikatz module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {5c 5c 2e 5c 70 69 70 65 5c 6d 69 6d 69 6b 61 74 7a}
		$b1 = {45 00 52 00 52 00 4f 00 52 00 20 00 6b 00 75 00 68 00 6c 00 5f 00 6d 00 5f 00 64 00 70 00 61 00 70 00 69 00 5f 00 63 00 68 00 72 00 6f 00 6d 00 65 00 20 00 3b 00 20 00 49 00 6e 00 70 00 75 00 74 00 20 00 27 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 27 00 20 00 66 00 69 00 6c 00 65 00 20 00 6e 00 65 00 65 00 64 00 65 00 64 00 20 00 28 00 2f 00 69 00 6e 00 3a 00 22 00 25 00 25 00 6c 00 6f 00 63 00 61 00 6c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 25 00 5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00}
		$b2 = {45 00 52 00 52 00 4f 00 52 00 20 00 6b 00 75 00 68 00 6c 00 5f 00 6d 00 5f 00 6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 5f 00 67 00 65 00 74 00 55 00 73 00 65 00 72 00 73 00 41 00 6e 00 64 00 53 00 61 00 6d 00 4b 00 65 00 79 00 20 00 3b 00 20 00 6b 00 75 00 6c 00 6c 00 5f 00 6d 00 5f 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5f 00 52 00 65 00 67 00 4f 00 70 00 65 00 6e 00 4b 00 65 00 79 00 45 00 78 00 20 00 53 00 41 00 4d 00 20 00 41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 20 00 28 00 30 00 78 00 25 00 30 00 38 00 78 00 29 00}
		$b3 = {45 00 52 00 52 00 4f 00 52 00 20 00 6b 00 75 00 68 00 6c 00 5f 00 6d 00 5f 00 6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 5f 00 67 00 65 00 74 00 55 00 73 00 65 00 72 00 73 00 41 00 6e 00 64 00 53 00 61 00 6d 00 4b 00 65 00 79 00 20 00 3b 00 20 00 6b 00 75 00 68 00 6c 00 5f 00 6d 00 5f 00 6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 5f 00 67 00 65 00 74 00 53 00 61 00 6d 00 4b 00 65 00 79 00 20 00 4b 00 4f 00}
		$b4 = {45 00 52 00 52 00 4f 00 52 00 20 00 6b 00 75 00 68 00 6c 00 5f 00 6d 00 5f 00 6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 5f 00 67 00 65 00 74 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 41 00 6e 00 64 00 53 00 79 00 73 00 6b 00 65 00 79 00 20 00 3b 00 20 00 6b 00 75 00 6c 00 6c 00 5f 00 6d 00 5f 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5f 00 52 00 65 00 67 00 4f 00 70 00 65 00 6e 00 4b 00 65 00 79 00 45 00 78 00 20 00 4c 00 53 00 41 00 20 00 4b 00 4f 00}
		$b5 = {45 00 52 00 52 00 4f 00 52 00 20 00 6b 00 75 00 68 00 6c 00 5f 00 6d 00 5f 00 6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 5f 00 6c 00 73 00 61 00 5f 00 67 00 65 00 74 00 48 00 61 00 6e 00 64 00 6c 00 65 00 20 00 3b 00 20 00 4f 00 70 00 65 00 6e 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 28 00 30 00 78 00 25 00 30 00 38 00 78 00 29 00}
		$b6 = {45 00 52 00 52 00 4f 00 52 00 20 00 6b 00 75 00 68 00 6c 00 5f 00 6d 00 5f 00 6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 5f 00 65 00 6e 00 75 00 6d 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 73 00 5f 00 75 00 73 00 65 00 72 00 73 00 20 00 3b 00 20 00 53 00 61 00 6d 00 4c 00 6f 00 6f 00 6b 00 75 00 70 00 4e 00 61 00 6d 00 65 00 73 00 49 00 6e 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 3a 00 20 00 25 00 30 00 38 00 78 00}
		$b7 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 28 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 29 00 20 00 23 00 20 00 25 00 73 00}
		$b8 = {70 6f 77 65 72 73 68 65 6c 6c 5f 72 65 66 6c 65 63 74 69 76 65 5f 6d 69 6d 69 6b 61 74 7a}
		$b9 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 5f 00 64 00 70 00 61 00 70 00 69 00 5f 00 63 00 61 00 63 00 68 00 65 00 2e 00 6e 00 64 00 72 00}
		$b10 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 2e 00 6c 00 6f 00 67 00}
		$b11 = {45 00 52 00 52 00 4f 00 52 00 20 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 5f 00 64 00 6f 00 4c 00 6f 00 63 00 61 00 6c 00}
		$b12 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 5f 00 78 00 36 00 34 00 2e 00 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 65 00 64 00}

	condition:
		1 of ( $a* ) and 7 of ( $b* )
}

rule Windows_Trojan_CobaltStrike_72f68375 : hardened
{
	meta:
		author = "Elastic Security"
		id = "72f68375-35ab-49cc-905d-15302389a236"
		fingerprint = "ecc28f414b2c347722b681589da8529c6f3af0491845453874f8fd87c2ae86d7"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Netdomain module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 6e 65 74 5f 64 6f 6d 61 69 6e 2e 78 36 34 2e 6f}
		$a2 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 6e 65 74 5f 64 6f 6d 61 69 6e 2e 78 38 36 2e 6f}
		$b1 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 50 72 69 6e 74 66}
		$b2 = {5f 5f 69 6d 70 5f 4e 45 54 41 50 49 33 32 24 4e 65 74 41 70 69 42 75 66 66 65 72 46 72 65 65}
		$b3 = {5f 5f 69 6d 70 5f 4e 45 54 41 50 49 33 32 24 44 73 47 65 74 44 63 4e 61 6d 65 41}
		$c1 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 50 72 69 6e 74 66}
		$c2 = {5f 5f 69 6d 70 5f 5f 4e 45 54 41 50 49 33 32 24 4e 65 74 41 70 69 42 75 66 66 65 72 46 72 65 65}
		$c3 = {5f 5f 69 6d 70 5f 5f 4e 45 54 41 50 49 33 32 24 44 73 47 65 74 44 63 4e 61 6d 65 41}

	condition:
		1 of ( $a* ) or 2 of ( $b* ) or 2 of ( $c* )
}

rule Windows_Trojan_CobaltStrike_15f680fb : hardened
{
	meta:
		author = "Elastic Security"
		id = "15f680fb-a04f-472d-a182-0b9bee111351"
		fingerprint = "0ecb8e41c01bf97d6dea4cf6456b769c6dd2a037b37d754f38580bcf561e1d2c"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Netview module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {6e 65 74 76 69 65 77 2e 78 36 34 2e 64 6c 6c}
		$a2 = {6e 65 74 76 69 65 77 2e 64 6c 6c}
		$a3 = {5c 5c 2e 5c 70 69 70 65 5c 6e 65 74 76 69 65 77}
		$b1 = {53 65 73 73 69 6f 6e 73 20 66 6f 72 20 5c 5c 25 73 3a}
		$b2 = {41 63 63 6f 75 6e 74 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 66 6f 72 20 25 73 20 6f 6e 20 5c 5c 25 73 3a}
		$b3 = {55 73 65 72 73 20 66 6f 72 20 5c 5c 25 73 3a}
		$b4 = {53 68 61 72 65 73 20 61 74 20 5c 5c 25 73 3a}
		$b5 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72}
		$b6 = {50 61 73 73 77 6f 72 64 20 63 68 61 6e 67 65 61 62 6c 65}
		$b7 = {55 00 73 00 65 00 72 00 27 00 73 00 20 00 43 00 6f 00 6d 00 6d 00 65 00 6e 00 74 00}
		$b8 = {4c 69 73 74 20 6f 66 20 68 6f 73 74 73 20 66 6f 72 20 64 6f 6d 61 69 6e 20 27 25 73 27 3a}
		$b9 = {50 61 73 73 77 6f 72 64 20 63 68 61 6e 67 65 61 62 6c 65}
		$b10 = {4c 6f 67 67 65 64 20 6f 6e 20 75 73 65 72 73 20 61 74 20 5c 5c 25 73 3a}

	condition:
		2 of ( $a* ) or 6 of ( $b* )
}

rule Windows_Trojan_CobaltStrike_5b4383ec : hardened
{
	meta:
		author = "Elastic Security"
		id = "5b4383ec-3c93-4e91-850e-d43cc3a86710"
		fingerprint = "283d3d2924e92b31f26ec4fc6b79c51bd652fb1377b6985b003f09f8c3dba66c"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Portscan module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {70 6f 72 74 73 63 61 6e 2e 78 36 34 2e 64 6c 6c}
		$a2 = {70 6f 72 74 73 63 61 6e 2e 64 6c 6c}
		$a3 = {5c 5c 2e 5c 70 69 70 65 5c 70 6f 72 74 73 63 61 6e}
		$b1 = {28 49 43 4d 50 29 20 54 61 72 67 65 74 20 27 25 73 27 20 69 73 20 61 6c 69 76 65 2e 20 5b 72 65 61 64 20 25 64 20 62 79 74 65 73 5d}
		$b2 = {28 41 52 50 29 20 54 61 72 67 65 74 20 27 25 73 27 20 69 73 20 61 6c 69 76 65 2e 20}
		$b3 = {54 41 52 47 45 54 53 21 31 32 33 34 35}
		$b4 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72}
		$b5 = {25 73 3a 25 64 20 28 70 6c 61 74 66 6f 72 6d 3a 20 25 64 20 76 65 72 73 69 6f 6e 3a 20 25 64 2e 25 64 20 6e 61 6d 65 3a 20 25 53 20 64 6f 6d 61 69 6e 3a 20 25 53 29}
		$b6 = {53 63 61 6e 6e 65 72 20 6d 6f 64 75 6c 65 20 69 73 20 63 6f 6d 70 6c 65 74 65}
		$b7 = {70 69 6e 67 70 6f 6e 67}
		$b8 = {50 4f 52 54 53 21 31 32 33 34 35}
		$b9 = {25 73 3a 25 64 20 28 25 73 29}
		$b10 = {50 52 45 46 45 52 45 4e 43 45 53 21 31 32 33 34 35}

	condition:
		2 of ( $a* ) or 6 of ( $b* )
}

rule Windows_Trojan_CobaltStrike_91e08059 : hardened
{
	meta:
		author = "Elastic Security"
		id = "91e08059-46a8-47d0-91c9-e86874951a4a"
		fingerprint = "d8baacb58a3db00489827275ad6a2d007c018eaecbce469356b068d8a758634b"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Post Ex module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {70 6f 73 74 65 78 2e 78 36 34 2e 64 6c 6c}
		$a2 = {70 6f 73 74 65 78 2e 64 6c 6c}
		$a3 = {52 75 6e 41 73 41 64 6d 69 6e 43 4d 53 54 50}
		$a4 = {4b 65 72 62 65 72 6f 73 54 69 63 6b 65 74 50 75 72 67 65}
		$b1 = {47 65 74 53 79 73 74 65 6d}
		$b2 = {48 65 6c 6c 6f 57 6f 72 6c 64}
		$b3 = {4b 65 72 62 65 72 6f 73 54 69 63 6b 65 74 55 73 65}
		$b4 = {53 70 61 77 6e 41 73 41 64 6d 69 6e}
		$b5 = {52 75 6e 41 73 41 64 6d 69 6e}
		$b6 = {4e 65 74 44 6f 6d 61 69 6e}

	condition:
		2 of ( $a* ) or 4 of ( $b* )
}

rule Windows_Trojan_CobaltStrike_ee756db7 : hardened
{
	meta:
		author = "Elastic Security"
		id = "ee756db7-e177-41f0-af99-c44646d334f7"
		fingerprint = "e589cc259644bc75d6c4db02a624c978e855201cf851c0d87f0d54685ce68f71"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Attempts to detect Cobalt Strike based on strings found in BEACON"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {25 73 2e 34 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 78 25 78 2e 25 73}
		$a2 = {25 73 2e 33 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 78 25 78 2e 25 73}
		$a3 = {70 70 69 64 20 25 64 20 69 73 20 69 6e 20 61 20 64 69 66 66 65 72 65 6e 74 20 64 65 73 6b 74 6f 70 20 73 65 73 73 69 6f 6e 20 28 73 70 61 77 6e 65 64 20 6a 6f 62 73 20 6d 61 79 20 66 61 69 6c 29 2e 20 55 73 65 20 27 70 70 69 64 27 20 74 6f 20 72 65 73 65 74 2e}
		$a4 = {49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 63 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 3a 25 75 2f 27 29 3b 20 25 73}
		$a5 = {49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 63 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 3a 25 75 2f 27 29}
		$a6 = {25 73 2e 32 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 78 25 78 2e 25 73}
		$a7 = {63 6f 75 6c 64 20 6e 6f 74 20 72 75 6e 20 63 6f 6d 6d 61 6e 64 20 28 77 2f 20 74 6f 6b 65 6e 29 20 62 65 63 61 75 73 65 20 6f 66 20 69 74 73 20 6c 65 6e 67 74 68 20 6f 66 20 25 64 20 62 79 74 65 73 21}
		$a8 = {25 73 2e 32 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 78 25 78 2e 25 73}
		$a9 = {25 73 2e 32 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 78 25 78 2e 25 73}
		$a10 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 70 20 2d 65 78 65 63 20 62 79 70 61 73 73 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 20 22 25 73 22}
		$a11 = {43 6f 75 6c 64 20 6e 6f 74 20 6f 70 65 6e 20 73 65 72 76 69 63 65 20 63 6f 6e 74 72 6f 6c 20 6d 61 6e 61 67 65 72 20 6f 6e 20 25 73 3a 20 25 64}
		$a12 = {25 64 20 69 73 20 61 6e 20 78 36 34 20 70 72 6f 63 65 73 73 20 28 63 61 6e 27 74 20 69 6e 6a 65 63 74 20 78 38 36 20 63 6f 6e 74 65 6e 74 29}
		$a13 = {25 64 20 69 73 20 61 6e 20 78 38 36 20 70 72 6f 63 65 73 73 20 28 63 61 6e 27 74 20 69 6e 6a 65 63 74 20 78 36 34 20 63 6f 6e 74 65 6e 74 29}
		$a14 = {46 61 69 6c 65 64 20 74 6f 20 69 6d 70 65 72 73 6f 6e 61 74 65 20 6c 6f 67 67 65 64 20 6f 6e 20 75 73 65 72 20 25 64 20 28 25 75 29}
		$a15 = {63 6f 75 6c 64 20 6e 6f 74 20 63 72 65 61 74 65 20 72 65 6d 6f 74 65 20 74 68 72 65 61 64 20 69 6e 20 25 64 3a 20 25 64}
		$a16 = {25 73 2e 31 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 78 25 78 2e 25 73}
		$a17 = {63 6f 75 6c 64 20 6e 6f 74 20 77 72 69 74 65 20 74 6f 20 70 72 6f 63 65 73 73 20 6d 65 6d 6f 72 79 3a 20 25 64}
		$a18 = {43 6f 75 6c 64 20 6e 6f 74 20 63 72 65 61 74 65 20 73 65 72 76 69 63 65 20 25 73 20 6f 6e 20 25 73 3a 20 25 64}
		$a19 = {43 6f 75 6c 64 20 6e 6f 74 20 64 65 6c 65 74 65 20 73 65 72 76 69 63 65 20 25 73 20 6f 6e 20 25 73 3a 20 25 64}
		$a20 = {43 6f 75 6c 64 20 6e 6f 74 20 6f 70 65 6e 20 70 72 6f 63 65 73 73 20 74 6f 6b 65 6e 3a 20 25 64 20 28 25 75 29}
		$a21 = {25 73 2e 31 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 78 25 78 2e 25 73}
		$a22 = {43 6f 75 6c 64 20 6e 6f 74 20 73 74 61 72 74 20 73 65 72 76 69 63 65 20 25 73 20 6f 6e 20 25 73 3a 20 25 64}
		$a23 = {43 6f 75 6c 64 20 6e 6f 74 20 71 75 65 72 79 20 73 65 72 76 69 63 65 20 25 73 20 6f 6e 20 25 73 3a 20 25 64}
		$a24 = {43 6f 75 6c 64 20 6e 6f 74 20 63 6f 6e 6e 65 63 74 20 74 6f 20 70 69 70 65 20 28 25 73 29 3a 20 25 64}
		$a25 = {25 73 2e 31 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 78 25 78 2e 25 73}
		$a26 = {63 6f 75 6c 64 20 6e 6f 74 20 73 70 61 77 6e 20 25 73 20 28 74 6f 6b 65 6e 29 3a 20 25 64}
		$a27 = {63 6f 75 6c 64 20 6e 6f 74 20 6f 70 65 6e 20 70 72 6f 63 65 73 73 20 25 64 3a 20 25 64}
		$a28 = {63 6f 75 6c 64 20 6e 6f 74 20 72 75 6e 20 25 73 20 61 73 20 25 73 5c 25 73 3a 20 25 64}
		$a29 = {25 73 2e 31 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 78 25 78 2e 25 73}
		$a30 = {6b 65 72 62 65 72 6f 73 20 74 69 63 6b 65 74 20 75 73 65 20 66 61 69 6c 65 64 3a}
		$a31 = {53 74 61 72 74 65 64 20 73 65 72 76 69 63 65 20 25 73 20 6f 6e 20 25 73}
		$a32 = {25 73 2e 31 25 30 38 78 25 30 38 78 25 30 38 78 2e 25 78 25 78 2e 25 73}
		$a33 = {49 27 6d 20 61 6c 72 65 61 64 79 20 69 6e 20 53 4d 42 20 6d 6f 64 65}
		$a34 = {63 6f 75 6c 64 20 6e 6f 74 20 73 70 61 77 6e 20 25 73 3a 20 25 64}
		$a35 = {63 6f 75 6c 64 20 6e 6f 74 20 6f 70 65 6e 20 25 73 3a 20 25 64}
		$a36 = {25 73 2e 31 25 30 38 78 25 30 38 78 2e 25 78 25 78 2e 25 73}
		$a37 = {43 6f 75 6c 64 20 6e 6f 74 20 6f 70 65 6e 20 27 25 73 27}
		$a38 = {25 73 2e 31 25 30 38 78 2e 25 78 25 78 2e 25 73}
		$a39 = {25 73 20 61 73 20 25 73 5c 25 73 3a 20 25 64}
		$a40 = {25 73 2e 31 25 78 2e 25 78 25 78 2e 25 73}
		$a41 = {62 65 61 63 6f 6e 2e 78 36 34 2e 64 6c 6c}
		$a42 = {25 73 20 6f 6e 20 25 73 3a 20 25 64}
		$a43 = {77 77 77 36 2e 25 78 25 78 2e 25 73}
		$a44 = {63 64 6e 2e 25 78 25 78 2e 25 73}
		$a45 = {61 70 69 2e 25 78 25 78 2e 25 73}
		$a46 = {25 73 20 28 61 64 6d 69 6e 29}
		$a47 = {62 65 61 63 6f 6e 2e 64 6c 6c}
		$a48 = {25 73 25 73 3a 20 25 73}
		$a49 = {40 25 64 2e 25 73}
		$a50 = {25 30 32 64 2f 25 30 32 64 2f 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64}
		$a51 = {43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 25 64}

	condition:
		6 of ( $a* )
}

rule Windows_Trojan_CobaltStrike_9c0d5561 : hardened
{
	meta:
		author = "Elastic Security"
		id = "9c0d5561-5b09-44ae-8e8c-336dee606199"
		fingerprint = "01d53fcdb320f0cd468a2521c3e96dcb0b9aa00e7a7a9442069773c6b3759059"
		creation_date = "2021-03-23"
		last_modified = "2021-10-04"
		description = "Identifies PowerShell Runner module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 52 00 75 00 6e 00 6e 00 65 00 72 00 2e 00 64 00 6c 00 6c 00}
		$a2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 78 36 34 2e 64 6c 6c}
		$a3 = {70 6f 77 65 72 73 68 65 6c 6c 2e 64 6c 6c}
		$a4 = {5c 5c 2e 5c 70 69 70 65 5c 70 6f 77 65 72 73 68 65 6c 6c}
		$b1 = {50 6f 77 65 72 53 68 65 6c 6c 52 75 6e 6e 65 72 2e 50 6f 77 65 72 53 68 65 6c 6c 52 75 6e 6e 65 72}
		$b2 = {46 61 69 6c 65 64 20 74 6f 20 69 6e 76 6f 6b 65 20 47 65 74 4f 75 74 70 75 74 20 77 2f 68 72 20 30 78 25 30 38 6c 78}
		$b3 = {46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 64 65 66 61 75 6c 74 20 41 70 70 44 6f 6d 61 69 6e 20 77 2f 68 72 20 30 78 25 30 38 6c 78}
		$b4 = {49 43 4c 52 4d 65 74 61 48 6f 73 74 3a 3a 47 65 74 52 75 6e 74 69 6d 65 20 28 76 34 2e 30 2e 33 30 33 31 39 29 20 66 61 69 6c 65 64 20 77 2f 68 72 20 30 78 25 30 38 6c 78}
		$b5 = {43 75 73 74 6f 6d 50 53 48 6f 73 74 55 73 65 72 49 6e 74 65 72 66 61 63 65}
		$b6 = {52 75 6e 74 69 6d 65 43 6c 72 48 6f 73 74 3a 3a 47 65 74 43 75 72 72 65 6e 74 41 70 70 44 6f 6d 61 69 6e 49 64 20 66 61 69 6c 65 64 20 77 2f 68 72 20 30 78 25 30 38 6c 78}
		$b7 = {49 43 6f 72 52 75 6e 74 69 6d 65 48 6f 73 74 3a 3a 47 65 74 44 65 66 61 75 6c 74 44 6f 6d 61 69 6e 20 66 61 69 6c 65 64 20 77 2f 68 72 20 30 78 25 30 38 6c 78}
		$c1 = { 8B 08 50 FF 51 08 8B 7C 24 1C 8D 4C 24 10 51 C7 }
		$c2 = {7a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 50 6f 77 65 72 53 68 65 6c 6c 52 75 6e 6e 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 50 6f 77 65 72 53 68 65 6c 6c 52 75 6e 6e 65 72 2e 70 64 62}

	condition:
		(1 of ( $a* ) and 4 of ( $b* ) ) or 1 of ( $c* )
}

rule Windows_Trojan_CobaltStrike_59ed9124 : hardened
{
	meta:
		author = "Elastic Security"
		id = "59ed9124-bc20-4ea6-b0a7-63ee3359e69c"
		fingerprint = "7823e3b98e55a83bf94b0f07e4c116dbbda35adc09fa0b367f8a978a80c2efff"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies PsExec module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 70 73 65 78 65 63 5f 63 6f 6d 6d 61 6e 64 2e 78 36 34 2e 6f}
		$a2 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 70 73 65 78 65 63 5f 63 6f 6d 6d 61 6e 64 2e 78 38 36 2e 6f}
		$b1 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 44 61 74 61 45 78 74 72 61 63 74}
		$b2 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 44 61 74 61 50 61 72 73 65}
		$b3 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 44 61 74 61 50 61 72 73 65}
		$b4 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 44 61 74 61 50 61 72 73 65}
		$b5 = {5f 5f 69 6d 70 5f 41 44 56 41 50 49 33 32 24 53 74 61 72 74 53 65 72 76 69 63 65 41}
		$b6 = {5f 5f 69 6d 70 5f 41 44 56 41 50 49 33 32 24 44 65 6c 65 74 65 53 65 72 76 69 63 65}
		$b7 = {5f 5f 69 6d 70 5f 41 44 56 41 50 49 33 32 24 51 75 65 72 79 53 65 72 76 69 63 65 53 74 61 74 75 73}
		$b8 = {5f 5f 69 6d 70 5f 41 44 56 41 50 49 33 32 24 43 6c 6f 73 65 53 65 72 76 69 63 65 48 61 6e 64 6c 65}
		$c1 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 44 61 74 61 45 78 74 72 61 63 74}
		$c2 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 44 61 74 61 50 61 72 73 65}
		$c3 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 44 61 74 61 50 61 72 73 65}
		$c4 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 44 61 74 61 50 61 72 73 65}
		$c5 = {5f 5f 69 6d 70 5f 5f 41 44 56 41 50 49 33 32 24 53 74 61 72 74 53 65 72 76 69 63 65 41}
		$c6 = {5f 5f 69 6d 70 5f 5f 41 44 56 41 50 49 33 32 24 44 65 6c 65 74 65 53 65 72 76 69 63 65}
		$c7 = {5f 5f 69 6d 70 5f 5f 41 44 56 41 50 49 33 32 24 51 75 65 72 79 53 65 72 76 69 63 65 53 74 61 74 75 73}
		$c8 = {5f 5f 69 6d 70 5f 5f 41 44 56 41 50 49 33 32 24 43 6c 6f 73 65 53 65 72 76 69 63 65 48 61 6e 64 6c 65}

	condition:
		1 of ( $a* ) or 5 of ( $b* ) or 5 of ( $c* )
}

rule Windows_Trojan_CobaltStrike_8a791eb7 : hardened
{
	meta:
		author = "Elastic Security"
		id = "8a791eb7-dc0c-4150-9e5b-2dc21af0c77d"
		fingerprint = "4967886ba5e663f2e2dc0631939308d7d8f2194a30590a230973e1b91bd625e1"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Registry module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 72 65 67 69 73 74 72 79 2e 78 36 34 2e 6f}
		$a2 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 72 65 67 69 73 74 72 79 2e 78 38 36 2e 6f}
		$b1 = {5f 5f 69 6d 70 5f 41 44 56 41 50 49 33 32 24 52 65 67 4f 70 65 6e 4b 65 79 45 78 41}
		$b2 = {5f 5f 69 6d 70 5f 41 44 56 41 50 49 33 32 24 52 65 67 45 6e 75 6d 4b 65 79 41}
		$b3 = {5f 5f 69 6d 70 5f 41 44 56 41 50 49 33 32 24 52 65 67 4f 70 65 6e 43 75 72 72 65 6e 74 55 73 65 72}
		$b4 = {5f 5f 69 6d 70 5f 41 44 56 41 50 49 33 32 24 52 65 67 43 6c 6f 73 65 4b 65 79}
		$b5 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 46 6f 72 6d 61 74 41 6c 6c 6f 63}
		$b6 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 4f 75 74 70 75 74}
		$b7 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 46 6f 72 6d 61 74 46 72 65 65}
		$b8 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 44 61 74 61 50 74 72}
		$c1 = {5f 5f 69 6d 70 5f 5f 41 44 56 41 50 49 33 32 24 52 65 67 4f 70 65 6e 4b 65 79 45 78 41}
		$c2 = {5f 5f 69 6d 70 5f 5f 41 44 56 41 50 49 33 32 24 52 65 67 45 6e 75 6d 4b 65 79 41}
		$c3 = {5f 5f 69 6d 70 5f 5f 41 44 56 41 50 49 33 32 24 52 65 67 4f 70 65 6e 43 75 72 72 65 6e 74 55 73 65 72}
		$c4 = {5f 5f 69 6d 70 5f 5f 41 44 56 41 50 49 33 32 24 52 65 67 43 6c 6f 73 65 4b 65 79}
		$c5 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 46 6f 72 6d 61 74 41 6c 6c 6f 63}
		$c6 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 4f 75 74 70 75 74}
		$c7 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 46 6f 72 6d 61 74 46 72 65 65}
		$c8 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 44 61 74 61 50 74 72}

	condition:
		1 of ( $a* ) or 5 of ( $b* ) or 5 of ( $c* )
}

rule Windows_Trojan_CobaltStrike_d00573a3 : hardened
{
	meta:
		author = "Elastic Security"
		id = "d00573a3-db26-4e6b-aabf-7af4a818f383"
		fingerprint = "b6fa0792b99ea55f359858d225685647f54b55caabe53f58b413083b8ad60e79"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Screenshot module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {73 63 72 65 65 6e 73 68 6f 74 2e 78 36 34 2e 64 6c 6c}
		$a2 = {73 63 72 65 65 6e 73 68 6f 74 2e 64 6c 6c}
		$a3 = {5c 5c 2e 5c 70 69 70 65 5c 73 63 72 65 65 6e 73 68 6f 74}
		$b1 = {31 49 31 6e 31 51 33 4d 35 51 35 55 35 59 35 5d 35 61 35 65 35 69 35 75 35 7b 35}
		$b2 = {47 65 74 44 65 73 6b 74 6f 70 57 69 6e 64 6f 77}
		$b3 = {43 72 65 61 74 65 43 6f 6d 70 61 74 69 62 6c 65 42 69 74 6d 61 70}
		$b4 = {47 44 49 33 32 2e 64 6c 6c}
		$b5 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72}
		$b6 = {41 64 6f 62 65 20 41 50 50 31 34 20 6d 61 72 6b 65 72 3a 20 76 65 72 73 69 6f 6e 20 25 64 2c 20 66 6c 61 67 73 20 30 78 25 30 34 78 20 30 78 25 30 34 78 2c 20 74 72 61 6e 73 66 6f 72 6d 20 25 64}

	condition:
		2 of ( $a* ) or 5 of ( $b* )
}

rule Windows_Trojan_CobaltStrike_7bcd759c : hardened
{
	meta:
		author = "Elastic Security"
		id = "7bcd759c-8e3d-4559-9381-1f4fe8b3dd95"
		fingerprint = "553085f1d1ca8dcd797360b287951845753eee7370610a1223c815a200a5ed20"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies SSH Agent module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {73 73 68 61 67 65 6e 74 2e 78 36 34 2e 64 6c 6c}
		$a2 = {73 73 68 61 67 65 6e 74 2e 64 6c 6c}
		$b1 = {5c 5c 2e 5c 70 69 70 65 5c 73 73 68 61 67 65 6e 74}
		$b2 = {5c 5c 2e 5c 70 69 70 65 5c 50 49 50 45 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41}

	condition:
		1 of ( $a* ) and 1 of ( $b* )
}

rule Windows_Trojan_CobaltStrike_a56b820f : hardened
{
	meta:
		author = "Elastic Security"
		id = "a56b820f-0a20-4054-9c2d-008862646a78"
		fingerprint = "5418e695bcb1c37e72a7ff24a39219dc12b3fe06c29cedefd500c5e82c362b6d"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Timestomp module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 74 69 6d 65 73 74 6f 6d 70 2e 78 36 34 2e 6f}
		$a2 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 74 69 6d 65 73 74 6f 6d 70 2e 78 38 36 2e 6f}
		$b1 = {5f 5f 69 6d 70 5f 4b 45 52 4e 45 4c 33 32 24 47 65 74 46 69 6c 65 54 69 6d 65}
		$b2 = {5f 5f 69 6d 70 5f 4b 45 52 4e 45 4c 33 32 24 53 65 74 46 69 6c 65 54 69 6d 65}
		$b3 = {5f 5f 69 6d 70 5f 4b 45 52 4e 45 4c 33 32 24 43 6c 6f 73 65 48 61 6e 64 6c 65}
		$b4 = {5f 5f 69 6d 70 5f 4b 45 52 4e 45 4c 33 32 24 43 72 65 61 74 65 46 69 6c 65 41}
		$b5 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 44 61 74 61 45 78 74 72 61 63 74}
		$b6 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 50 72 69 6e 74 66}
		$b7 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 44 61 74 61 50 61 72 73 65}
		$b8 = {5f 5f 69 6d 70 5f 42 65 61 63 6f 6e 44 61 74 61 45 78 74 72 61 63 74}
		$c1 = {5f 5f 69 6d 70 5f 5f 4b 45 52 4e 45 4c 33 32 24 47 65 74 46 69 6c 65 54 69 6d 65}
		$c2 = {5f 5f 69 6d 70 5f 5f 4b 45 52 4e 45 4c 33 32 24 53 65 74 46 69 6c 65 54 69 6d 65}
		$c3 = {5f 5f 69 6d 70 5f 5f 4b 45 52 4e 45 4c 33 32 24 43 6c 6f 73 65 48 61 6e 64 6c 65}
		$c4 = {5f 5f 69 6d 70 5f 5f 4b 45 52 4e 45 4c 33 32 24 43 72 65 61 74 65 46 69 6c 65 41}
		$c5 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 44 61 74 61 45 78 74 72 61 63 74}
		$c6 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 50 72 69 6e 74 66}
		$c7 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 44 61 74 61 50 61 72 73 65}
		$c8 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 44 61 74 61 45 78 74 72 61 63 74}

	condition:
		1 of ( $a* ) or 5 of ( $b* ) or 5 of ( $c* )
}

rule Windows_Trojan_CobaltStrike_92f05172 : hardened
{
	meta:
		author = "Elastic Security"
		id = "92f05172-f15c-4077-a958-b8490378bf08"
		fingerprint = "09b1f7087d45fb4247a33ae3112910bf5426ed750e1e8fe7ba24a9047b76cc82"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies UAC cmstp module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 75 61 63 63 6d 73 74 70 2e 78 36 34 2e 6f}
		$a2 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 75 61 63 63 6d 73 74 70 2e 78 38 36 2e 6f}
		$b1 = {65 6c 65 76 61 74 65 5f 63 6d 73 74 70}
		$b2 = {24 70 64 61 74 61 24 65 6c 65 76 61 74 65 5f 63 6d 73 74 70}
		$b3 = {24 75 6e 77 69 6e 64 24 65 6c 65 76 61 74 65 5f 63 6d 73 74 70}
		$c1 = {5f 65 6c 65 76 61 74 65 5f 63 6d 73 74 70}
		$c2 = {5f 5f 69 6d 70 5f 5f 4f 4c 45 33 32 24 43 6f 47 65 74 4f 62 6a 65 63 74 40 31 36}
		$c3 = {5f 5f 69 6d 70 5f 5f 4b 45 52 4e 45 4c 33 32 24 47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41 40 31 32}
		$c4 = {5f 5f 69 6d 70 5f 5f 4b 45 52 4e 45 4c 33 32 24 47 65 74 53 79 73 74 65 6d 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 40 38}
		$c5 = {4f 4c 44 4e 41 4d 45 53}
		$c6 = {5f 5f 69 6d 70 5f 5f 42 65 61 63 6f 6e 44 61 74 61 50 61 72 73 65}
		$c7 = {5f 77 69 6c 6c 41 75 74 6f 45 6c 65 76 61 74 65}

	condition:
		1 of ( $a* ) or 3 of ( $b* ) or 4 of ( $c* )
}

rule Windows_Trojan_CobaltStrike_417239b5 : hardened
{
	meta:
		author = "Elastic Security"
		id = "417239b5-cf2d-4c85-a022-7a8459c26793"
		fingerprint = "292afee829e838f9623547f94d0561e8a9115ce7f4c40ae96c6493f3cc5ffa9b"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies UAC token module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 75 61 63 74 6f 6b 65 6e 2e 78 36 34 2e 6f}
		$a2 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 75 61 63 74 6f 6b 65 6e 2e 78 38 36 2e 6f}
		$a3 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 75 61 63 74 6f 6b 65 6e 32 2e 78 36 34 2e 6f}
		$a4 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 75 61 63 74 6f 6b 65 6e 32 2e 78 38 36 2e 6f}
		$b1 = {24 70 64 61 74 61 24 69 73 5f 61 64 6d 69 6e 5f 61 6c 72 65 61 64 79}
		$b2 = {24 75 6e 77 69 6e 64 24 69 73 5f 61 64 6d 69 6e}
		$b3 = {24 70 64 61 74 61 24 69 73 5f 61 64 6d 69 6e}
		$b4 = {24 75 6e 77 69 6e 64 24 69 73 5f 61 64 6d 69 6e 5f 61 6c 72 65 61 64 79}
		$b5 = {24 70 64 61 74 61 24 52 75 6e 41 73 41 64 6d 69 6e}
		$b6 = {24 75 6e 77 69 6e 64 24 52 75 6e 41 73 41 64 6d 69 6e}
		$b7 = {69 73 5f 61 64 6d 69 6e 5f 61 6c 72 65 61 64 79}
		$b8 = {69 73 5f 61 64 6d 69 6e}
		$b9 = {70 72 6f 63 65 73 73 5f 77 61 6c 6b}
		$b10 = {67 65 74 5f 63 75 72 72 65 6e 74 5f 73 65 73 73}
		$b11 = {65 6c 65 76 61 74 65 5f 74 72 79}
		$b12 = {52 75 6e 41 73 41 64 6d 69 6e}
		$b13 = {69 73 5f 63 74 66 6d 6f 6e}
		$c1 = {5f 69 73 5f 61 64 6d 69 6e 5f 61 6c 72 65 61 64 79}
		$c2 = {5f 69 73 5f 61 64 6d 69 6e}
		$c3 = {5f 70 72 6f 63 65 73 73 5f 77 61 6c 6b}
		$c4 = {5f 67 65 74 5f 63 75 72 72 65 6e 74 5f 73 65 73 73}
		$c5 = {5f 65 6c 65 76 61 74 65 5f 74 72 79}
		$c6 = {5f 52 75 6e 41 73 41 64 6d 69 6e}
		$c7 = {5f 69 73 5f 63 74 66 6d 6f 6e}
		$c8 = {5f 72 65 67 5f 71 75 65 72 79 5f 64 77 6f 72 64}
		$c9 = {2e 64 72 65 63 74 76 65}
		$c10 = {5f 69 73 5f 63 61 6e 64 69 64 61 74 65}
		$c11 = {5f 53 70 61 77 6e 41 73 41 64 6d 69 6e}
		$c12 = {5f 53 70 61 77 6e 41 73 41 64 6d 69 6e 58 36 34}

	condition:
		1 of ( $a* ) or 9 of ( $b* ) or 7 of ( $c* )
}

rule Windows_Trojan_CobaltStrike_29374056 : hardened
{
	meta:
		author = "Elastic Security"
		id = "29374056-03ce-484b-8b2d-fbf75be86e27"
		fingerprint = "4cd7552a499687ac0279fb2e25722f979fc5a22afd1ea4abba14a2ef2002dd0f"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Cobalt Strike MZ Reflective Loader."
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D ?? FF FF FF 48 81 C3 ?? ?? 00 00 FF D3 }
		$a2 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 }

	condition:
		1 of ( $a* )
}

rule Windows_Trojan_CobaltStrike_949f10e3 : hardened
{
	meta:
		author = "Elastic Security"
		id = "949f10e3-68c9-4600-a620-ed3119e09257"
		fingerprint = "34e04901126a91c866ebf61a61ccbc3ce0477d9614479c42d8ce97a98f2ce2a7"
		creation_date = "2021-03-25"
		last_modified = "2021-08-23"
		description = "Identifies the API address lookup function used by Cobalt Strike along with XOR implementation by Cobalt Strike."
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 }
		$a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }

	condition:
		all of them
}

rule Windows_Trojan_CobaltStrike_8751cdf9 : hardened
{
	meta:
		author = "Elastic Security"
		id = "8751cdf9-4038-42ba-a6eb-f8ac579a4fbb"
		fingerprint = "0988386ef4ba54dd90b0cf6d6a600b38db434e00e569d69d081919cdd3ea4d3f"
		creation_date = "2021-03-25"
		last_modified = "2021-08-23"
		description = "Identifies Cobalt Strike wininet reverse shellcode along with XOR implementation by Cobalt Strike."
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 99
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
		$a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }

	condition:
		all of them
}

rule Windows_Trojan_CobaltStrike_8519072e : hardened
{
	meta:
		author = "Elastic Security"
		id = "8519072e-3e43-470b-a3cf-18f92b3f31a2"
		fingerprint = "9fc88b798083adbcf25f9f0b35fbb5035a98cdfe55377de96fa0353821de1cc8"
		creation_date = "2021-03-25"
		last_modified = "2021-10-04"
		description = "Identifies Cobalt Strike trial/default versions"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {55 73 65 72 2d 41 67 65 6e 74 3a}
		$a2 = {77 69 6e 69}
		$a3 = {35 4f 21 50 25 40 41 50 5b 34 5c 50 5a 58 35 34 28 50 5e 29 37 43 43 29 37 7d 24 45 49 43 41 52 2d 53 54 41 4e 44 41 52 44 2d 41 4e 54 49 56 49 52 55 53 2d 54 45 53 54 2d 46 49 4c 45 21 24 48 2b 48 2a}

	condition:
		all of them
}

rule Windows_Trojan_CobaltStrike_663fc95d : hardened
{
	meta:
		author = "Elastic Security"
		id = "663fc95d-2472-4d52-ad75-c5d86cfc885f"
		fingerprint = "d0f781d7e485a7ecfbbfd068601e72430d57ef80fc92a993033deb1ddcee5c48"
		creation_date = "2021-04-01"
		last_modified = "2021-12-17"
		description = "Identifies CobaltStrike via unidentified function code"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 59 10 48 8B F9 48 8B 49 08 FF 17 33 D2 41 B8 00 80 00 00 }

	condition:
		all of them
}

rule Windows_Trojan_CobaltStrike_b54b94ac : hardened
{
	meta:
		author = "Elastic Security"
		id = "b54b94ac-6ef8-4ee9-a8a6-f7324c1974ca"
		fingerprint = "2344dd7820656f18cfb774a89d89f5ab65d46cc7761c1f16b7e768df66aa41c8"
		creation_date = "2021-10-21"
		last_modified = "2022-01-13"
		description = "Rule for beacon sleep obfuscation routine"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a_x64 = { 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03 }
		$a_x64_smbtcp = { 4C 8B 07 B8 4F EC C4 4E 41 F7 E1 41 8B C1 C1 EA 02 41 FF C1 6B D2 0D 2B C2 8A 4C 38 10 42 30 0C 06 48 }
		$a_x86 = { 8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2 }
		$a_x86_2 = { 8B 06 8D 3C 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 32 08 30 07 41 3B 4D 08 72 E6 8B 45 FC EB C7 }
		$a_x86_smbtcp = { 8B 07 8D 34 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 3A 08 30 06 41 3B 4D 08 72 E6 8B 45 FC EB }

	condition:
		any of them
}

rule Windows_Trojan_CobaltStrike_f0b627fc : hardened
{
	meta:
		author = "Elastic Security"
		id = "f0b627fc-97cd-42cb-9eae-1efb0672762d"
		fingerprint = "fbc94bedd50b5b943553dd438a183a1e763c098a385ac3a4fc9ff24ee30f91e1"
		creation_date = "2021-10-21"
		last_modified = "2022-01-13"
		description = "Rule for beacon reflective loader"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "b362951abd9d96d5ec15d281682fa1c8fe8f8e4e2f264ca86f6b061af607f79b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$beacon_loader_x64 = { 25 FF FF FF 00 3D 41 41 41 00 75 [5-10] 25 FF FF FF 00 3D 42 42 42 00 75 }
		$beacon_loader_x86 = { 25 FF FF FF 00 3D 41 41 41 00 75 [4-8] 81 E1 FF FF FF 00 81 F9 42 42 42 00 75 }
		$beacon_loader_x86_2 = { 81 E1 FF FF FF 00 81 F9 41 41 41 00 75 [4-8] 81 E2 FF FF FF 00 81 FA 42 42 42 00 75 }
		$generic_loader_x64 = { 89 44 24 20 48 8B 44 24 40 0F BE 00 8B 4C 24 20 03 C8 8B C1 89 44 24 20 48 8B 44 24 40 48 FF C0 }
		$generic_loader_x86 = { 83 C4 04 89 45 FC 8B 4D 08 0F BE 11 03 55 FC 89 55 FC 8B 45 08 83 C0 01 89 45 08 8B 4D 08 0F BE }

	condition:
		any of them
}

rule Windows_Trojan_CobaltStrike_dcdcdd8c : hardened
{
	meta:
		author = "Elastic Security"
		id = "dcdcdd8c-7395-4453-a74a-60ab8e251a5a"
		fingerprint = "8aed1ae470d06a7aac37896df22b2f915c36845099839a85009212d9051f71e9"
		creation_date = "2021-10-21"
		last_modified = "2022-01-13"
		description = "Rule for beacon sleep PDB"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 73 6c 65 65 70 6d 61 73 6b 5c 62 69 6e 5c 73 6c 65 65 70 6d 61 73 6b 2e 78 36 34 2e 6f}
		$a2 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 73 6c 65 65 70 6d 61 73 6b 5c 62 69 6e 5c 73 6c 65 65 70 6d 61 73 6b 2e 78 38 36 2e 6f}
		$a3 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 73 6c 65 65 70 6d 61 73 6b 5c 62 69 6e 5c 73 6c 65 65 70 6d 61 73 6b 5f 73 6d 62 2e 78 36 34 2e 6f}
		$a4 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 73 6c 65 65 70 6d 61 73 6b 5c 62 69 6e 5c 73 6c 65 65 70 6d 61 73 6b 5f 73 6d 62 2e 78 38 36 2e 6f}
		$a5 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 73 6c 65 65 70 6d 61 73 6b 5c 62 69 6e 5c 73 6c 65 65 70 6d 61 73 6b 5f 74 63 70 2e 78 36 34 2e 6f}
		$a6 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 73 6c 65 65 70 6d 61 73 6b 5c 62 69 6e 5c 73 6c 65 65 70 6d 61 73 6b 5f 74 63 70 2e 78 38 36 2e 6f}

	condition:
		any of them
}

rule Windows_Trojan_CobaltStrike_a3fb2616 : hardened
{
	meta:
		author = "Elastic Security"
		id = "a3fb2616-b03d-4399-9342-0fc684fb472e"
		fingerprint = "c15cf6aa7719dac6ed21c10117f28eb4ec56335f80a811b11ab2901ad36f8cf0"
		creation_date = "2021-10-21"
		last_modified = "2022-01-13"
		description = "Rule for browser pivot "
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {62 72 6f 77 73 65 72 70 69 76 6f 74 2e 64 6c 6c}
		$a2 = {62 72 6f 77 73 65 72 70 69 76 6f 74 2e 78 36 34 2e 64 6c 6c}
		$b1 = {24 24 24 54 48 52 45 41 44 2e 43 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24}
		$b2 = {43 4f 42 41 4c 54 53 54 52 49 4b 45}

	condition:
		1 of ( $a* ) and 2 of ( $b* )
}

rule Windows_Trojan_CobaltStrike_8ee55ee5 : hardened
{
	meta:
		author = "Elastic Security"
		id = "8ee55ee5-67f1-4f94-ab93-62bb5cfbeee9"
		fingerprint = "7e7ed4f00d0914ce0b9f77b6362742a9c8b93a16a6b2a62b70f0f7e15ba3a72b"
		creation_date = "2021-10-21"
		last_modified = "2022-01-13"
		description = "Rule for wmi exec module"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {5a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 77 6d 69 65 78 65 63 2e 78 36 34 2e 6f}
		$a2 = {7a 3a 5c 64 65 76 63 65 6e 74 65 72 5c 61 67 67 72 65 73 73 6f 72 5c 65 78 74 65 72 6e 61 6c 5c 70 78 6c 69 62 5c 62 69 6e 5c 77 6d 69 65 78 65 63 2e 78 38 36 2e 6f}

	condition:
		1 of ( $a* )
}

rule Windows_Trojan_CobaltStrike_8d5963a2 : hardened
{
	meta:
		author = "Elastic Security"
		id = "8d5963a2-54a9-4705-9f34-0d5f8e6345a2"
		fingerprint = "228cd65380cf4b04f9fd78e8c30c3352f649ce726202e2dac9f1a96211925e1c"
		creation_date = "2022-08-10"
		last_modified = "2022-09-29"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "9fe43996a5c4e99aff6e2a1be743fedec35e96d1e6670579beb4f7e7ad591af9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a = { 40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 D8 48 81 EC 28 01 00 00 45 33 F6 48 8B D9 48 }

	condition:
		all of them
}

rule Windows_Trojan_CobaltStrike_1787eef5 : hardened
{
	meta:
		author = "Elastic Security"
		id = "1787eef5-ff00-4e19-bd22-c5dfc9488c7b"
		fingerprint = "292f15bdc978fc29670126f1bdc72ade1e7faaf1948653f70b6789a82dbee67f"
		creation_date = "2022-08-29"
		last_modified = "2022-09-29"
		description = "CS shellcode variants"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "WKL-Sec/Malleable-CS-Profiles"
		source_url = "https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/05beb83d46bd7f62cad317d7ae4fd579609fafe5/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = { 55 89 E5 83 EC ?? A1 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 89 44 24 ?? E8 ?? ?? ?? ?? 31 C0 C9 C3 55 }
		$a2 = { 55 89 E5 83 EC ?? A1 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 31 C0 C9 C3 55 89 E5 83 EC ?? 83 7D ?? ?? }
		$a3 = { 55 89 E5 8B 45 ?? 5D FF E0 55 8B 15 ?? ?? ?? ?? 89 E5 8B 45 ?? 85 D2 7E ?? 83 3D ?? ?? ?? ?? ?? }
		$a4 = { 55 89 E5 8B 45 ?? 5D FF E0 55 89 E5 83 EC ?? 8B 15 ?? ?? ?? ?? 8B 45 ?? 85 D2 7E ?? 83 3D ?? ?? ?? ?? ?? }
		$a5 = { 4D 5A 41 52 55 48 89 E5 48 81 EC ?? ?? ?? ?? 48 8D 1D ?? ?? ?? ?? 48 89 DF 48 81 C3 ?? ?? ?? ?? }

	condition:
		1 of ( $a* )
}

rule HKTL_CobaltStrike_SleepMask_Jul22 : hardened
{
	meta:
		description = "Detects static bytes in Cobalt Strike 4.5 sleep mask function that are not obfuscated"
		author = "CodeX"
		date = "2022-07-04"
		reference = "https://codex-7.gitbook.io/codexs-terminal-window/blue-team/detecting-cobalt-strike/sleep-mask-kit-iocs"
		score = 80
		id = "d396ab0e-b584-5a7c-8627-5f318a20f9dd"
		ruleset = "gen_cobaltstrike.yar"
		repository = "Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/007d9ddee386f68aca3a3aac5e1514782f02ed2d/yara/gen_cobaltstrike.yar"
		license = "Other"

	strings:
		$sleep_mask = { 48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 45 33 DB 45 33 D2 33 FF 33 F6 48 8B E9 BB 03 00 00 00 85 D2 0F 84 81 00 00 00 0F B6 45 }

	condition:
		$sleep_mask
}

rule Windows_Trojan_CobaltStrike_4106070a : hardened
{
	meta:
		author = "Elastic Security"
		id = "4106070a-24e2-421b-ab83-67b817a9f019"
		fingerprint = "c12b919064a9cd2a603c134c5f73f6d05ffbf4cbed1e5b5246687378102e4338"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "98789a11c06c1dfff7e02f66146afca597233c17e0d4900d6a683a150f16b3a4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = { 48 8B 44 24 48 0F B7 00 66 C1 E8 0C 66 83 E0 0F 0F B7 C0 83 }
		$a2 = { 44 24 48 0F B7 00 66 C1 E8 0C 66 83 E0 0F 0F B7 C0 83 F8 0A }

	condition:
		all of them
}

rule Windows_Trojan_CobaltStrike_3dc22d14 : hardened
{
	meta:
		author = "Elastic Security"
		id = "3dc22d14-a2f4-49cd-a3a8-3f071eddf028"
		fingerprint = "0e029fac50ffe8ea3fc5bc22290af69e672895eaa8a1b9f3e9953094c133392c"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "7898194ae0244611117ec948eb0b0a5acbc15cd1419b1ecc553404e63bc519f9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = {25 30 32 64 2f 25 30 32 64 2f 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64}
		$a2 = {25 73 20 61 73 20 25 73 5c 25 73 3a 20 25 64}

	condition:
		all of them
}

rule Windows_Trojan_CobaltStrike_7f8da98a : hardened
{
	meta:
		author = "Elastic Security"
		id = "7f8da98a-3336-482b-91da-82c7cef34c62"
		fingerprint = "c375492960a6277bf665bea86302cec774c0d79506e5cb2e456ce59f5e68aa2e"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "e3bc2bec4a55ad6cfdf49e5dbd4657fc704af1758ca1d6e31b83dcfb8bf0f89d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		ruleset = "Windows_Trojan_CobaltStrike.yar"
		repository = "elastic/protections-artifacts"
		source_url = "https://github.com/elastic/protections-artifacts/blob/3bbef930abab9814b2fdb4704be075ab1daf2ea0/yara/rules/Windows_Trojan_CobaltStrike.yar"
		score = 75

	strings:
		$a1 = { 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4D 53 53 45 2D 25 64 2D 73 65 72 76 65 72 }

	condition:
		all of them
}

rule CobaltStrikeStager : hardened
{
	meta:
		author = "@dan__mayer <daniel@stairwell.com>"
		description = "Cobalt Strike Stager Payload"
		cape_type = "CobaltStrikeStager Payload"
		ruleset = "CobaltStrikeStager.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9c8d6da44b595f8140a5cd76edd8101f6812c3b0/data/yara/CAPE/CobaltStrikeStager.yar"
		license = "Other"
		score = 75

	strings:
		$smb = { 68 00 B0 04 00 68 00 B0 04 00 6A 01 6A 06 6A 03 52 68 45 70 DF D4 }
		$http_x86 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
		$http_x64 = { 49 BE 77 69 6E 69 6E 65 74 00 41 56 49 89 E6 4C 89 F1 41 BA 4C 77 26 07 }
		$dns = { 68 00 10 00 00 68 FF FF 07 00 6A 00 68 58 A4 53 E5 }

	condition:
		any of them
}

rule fsCobalt : hardened
{
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "cobalt"
		score = 75

	condition:
		Cobalt_functions or cobalt_strike_indicator or CobaltStrikeBeacon or MALW_cobaltrike or cobaltstrike_beacon_raw or cobaltstrike_beacon_b64 or CobaltStrike_Sleeve_BeaconLoader_HA_x86_o_v4_3_v4_4_v4_5_and_v4_6 or CobaltStrike_Sleeve_BeaconLoader_MVF_x86_o_v4_3_v4_4_v4_5_and_v4_6 or CobaltStrike_Sleeve_BeaconLoader_VA_x86_o_v4_3_v4_4_v4_5_and_v4_6 or CobaltStrike_Sleeve_BeaconLoader_x86_o_v4_3_v4_4_v4_5_and_v4_6 or CobaltStrike_Sleeve_BeaconLoader_HA_x64_o_v4_3_v4_4_v4_5_and_v4_6 or CobaltStrike_Sleeve_BeaconLoader_MVF_x64_o_v4_3_v4_4_v4_5_and_v4_6 or CobaltStrike_Sleeve_BeaconLoader_VA_x64_o_v4_3_v4_4_v4_5_and_v4_6 or CobaltStrike_Sleeve_BeaconLoader_x64_o_v4_3_v4_4_v4_5_and_v4_6 or MAL_CobaltStrike_Oct_2021_1 or Windows_Trojan_CobaltStrike_c851687a or Windows_Trojan_CobaltStrike_0b58325e or Windows_Trojan_CobaltStrike_2b8cddf8 or Windows_Trojan_CobaltStrike_59b44767 or Windows_Trojan_CobaltStrike_7efd3c3f or Windows_Trojan_CobaltStrike_6e971281 or Windows_Trojan_CobaltStrike_09b79efa or Windows_Trojan_CobaltStrike_6e77233e or Windows_Trojan_CobaltStrike_de42495a or Windows_Trojan_CobaltStrike_72f68375 or Windows_Trojan_CobaltStrike_15f680fb or Windows_Trojan_CobaltStrike_5b4383ec or Windows_Trojan_CobaltStrike_91e08059 or Windows_Trojan_CobaltStrike_ee756db7 or Windows_Trojan_CobaltStrike_9c0d5561 or Windows_Trojan_CobaltStrike_59ed9124 or Windows_Trojan_CobaltStrike_8a791eb7 or Windows_Trojan_CobaltStrike_d00573a3 or Windows_Trojan_CobaltStrike_7bcd759c or Windows_Trojan_CobaltStrike_a56b820f or Windows_Trojan_CobaltStrike_92f05172 or Windows_Trojan_CobaltStrike_417239b5 or Windows_Trojan_CobaltStrike_29374056 or Windows_Trojan_CobaltStrike_949f10e3 or Windows_Trojan_CobaltStrike_8751cdf9 or Windows_Trojan_CobaltStrike_8519072e or Windows_Trojan_CobaltStrike_663fc95d or Windows_Trojan_CobaltStrike_b54b94ac or Windows_Trojan_CobaltStrike_f0b627fc or Windows_Trojan_CobaltStrike_dcdcdd8c or Windows_Trojan_CobaltStrike_a3fb2616 or Windows_Trojan_CobaltStrike_8ee55ee5 or Windows_Trojan_CobaltStrike_8d5963a2 or Windows_Trojan_CobaltStrike_1787eef5 or HKTL_CobaltStrike_SleepMask_Jul22 or Windows_Trojan_CobaltStrike_4106070a or Windows_Trojan_CobaltStrike_3dc22d14 or Windows_Trojan_CobaltStrike_7f8da98a or CobaltStrikeStager
}

