rule APT_Sandworm_Keywords_May20_1 : hardened
{
	meta:
		description = "Detects commands used by Sandworm group to exploit critical vulernability CVE-2019-10149 in Exim"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		date = "2020-05-28"
		id = "e0d4e90e-5547-5487-8d0c-a141d88fff7c"

	strings:
		$x1 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c 24 28 72 75 6e 28}
		$x2 = {65 78 65 63 5c 78 32 30 5c 78 32 46 75 73 72 5c 78 32 46 62 69 6e 5c 78 32 46 77 67 65 74 5c 78 32 30 5c 78 32 44 4f 5c 78 32 30 5c 78 32 44 5c 78 32 30 68 74 74 70}

	condition:
		filesize < 8000KB and 1 of them
}

rule APT_Sandworm_SSH_Key_May20_1 : hardened
{
	meta:
		description = "Detects SSH key used by Sandworm on exploited machines"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		date = "2020-05-28"
		hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
		id = "ea2968b8-7ae4-56b8-9547-816c5e37c50a"

	strings:
		$x1 = {73 73 68 2d 72 73 61 20 41 41 41 41 42 33 4e 7a 61 43 31 79 63 32 45 41 41 41 41 44 41 51 41 42 41 41 41 42 41 51 43 32 71 2f 4e 47 4e 2f 62 72 7a 4e 66 4a 69 49 70 32 7a 73 77 74 4c 33 33 74 72 37 34 70 49 41 6a 4d 65 57 74 58 4e 31 70 35 48 71 70 35 66 54 70 30 35 38 55 31 45 4e 34 4e 6d 67 6d 6a 58 30 4b 7a 4e 6a 6a 56}

	condition:
		filesize < 1000KB and 1 of them
}

rule APT_Sandworm_SSHD_Config_Modification_May20_1 : hardened
{
	meta:
		description = "Detects ssh config entry inserted by Sandworm on compromised machines"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		date = "2020-05-28"
		hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
		id = "dd60eeb7-3d4b-5a6a-8054-50c617ee8c73"

	strings:
		$x1 = {41 6c 6c 6f 77 55 73 65 72 73 20 6d 79 73 71 6c 5f 64 62}
		$a1 = {4c 69 73 74 65 6e 41 64 64 72 65 73 73}

	condition:
		filesize < 10KB and all of them
}

rule APT_Sandworm_InitFile_May20_1 : hardened
{
	meta:
		description = "Detects mysql init script used by Sandworm on compromised machines"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		date = "2020-05-28"
		hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
		id = "0bd613e3-6bd4-5cec-bc0d-2bdb83caf142"

	strings:
		$s1 = {47 52 41 4e 54 20 41 4c 4c 20 50 52 49 56 49 4c 45 47 45 53 20 4f 4e 20 2a 20 2e 20 2a 20 54 4f 20 27 6d 79 73 71 6c 64 62 27 40 27 6c 6f 63 61 6c 68 6f 73 74 27 3b}
		$s2 = {43 52 45 41 54 45 20 55 53 45 52 20 27 6d 79 73 71 6c 64 62 27 40 27 6c 6f 63 61 6c 68 6f 73 74 27 20 49 44 45 4e 54 49 46 49 45 44 20 42 59 20 27}

	condition:
		filesize < 10KB and all of them
}

rule APT_Sandworm_User_May20_1 : hardened
{
	meta:
		description = "Detects user added by Sandworm on compromised machines"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		date = "2020-05-28"
		hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
		id = "ada549a4-abcc-5c0a-9601-75631e78c835"

	strings:
		$s1 = {6d 79 73 71 6c 5f 64 62 3a 78 3a}
		$a1 = {72 6f 6f 74 3a 78 3a}
		$a2 = {64 61 65 6d 6f 6e 3a 78 3a}

	condition:
		filesize < 4KB and all of them
}

rule APT_WEBSHELL_PHP_Sandworm_May20_1 : hardened
{
	meta:
		description = "Detects GIF header PHP webshell used by Sandworm on compromised machines"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		date = "2020-05-28"
		hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
		id = "b9ec02c2-fa83-5f21-95cf-3528047b2d01"

	strings:
		$h1 = {47 49 46 38 39 61 20 3c 3f 70 68 70 20 24}
		$s1 = {73 74 72 5f 72 65 70 6c 61 63 65 28}

	condition:
		filesize < 10KB and $h1 at 0 and $s1
}

rule APT_SH_Sandworm_Shell_Script_May20_1 : hardened
{
	meta:
		description = "Detects shell script used by Sandworm in attack against Exim mail server"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		date = "2020-05-28"
		hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
		id = "21cf2c89-5511-5eb6-a2dd-4ad54ebfa2d1"

	strings:
		$x1 = {65 63 68 6f 20 22 47 52 41 4e 54 20 41 4c 4c 20 50 52 49 56 49 4c 45 47 45 53 20 4f 4e 20 2a 20 2e 20 2a 20 54 4f 20 27 6d 79 73 71 6c 64 62 27 40 27 6c 6f 63 61 6c 68 6f 73 74 27 3b 22 20 3e 3e 20 69 6e 69 74 2d 66 69 6c 65 2e 74 78 74}
		$x2 = {69 6d 70 6f 72 74 20 62 61 73 65 36 34 2c 73 79 73 3b 65 78 65 63 28 62 61 73 65 36 34 2e 62 36 34 64 65 63 6f 64 65 28 7b 32 3a 73 74 72 2c 33 3a 6c 61 6d 62 64 61 20 62 3a 62 79 74 65 73 28 62 2c 27 55 54 46 2d 38 27 29 7d 5b 73 79 73 2e 76 65 72 73 69 6f 6e}
		$x3 = {73 65 64 20 2d 69 20 2d 65 20 27 2f 50 61 73 73 77 6f 72 64 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 2f 73 2f 6e 6f 2f 79 65 73 2f 67 3b 20 2f 50 65 72 6d 69 74 52 6f 6f 74 4c 6f 67 69 6e 2f 73 2f 6e 6f 2f 79 65 73 2f 67 3b}
		$x4 = {75 73 65 72 61 64 64 20 2d 4d 20 2d 6c 20 2d 67 20 72 6f 6f 74 20 2d 47 20 72 6f 6f 74 20 2d 62 20 2f 72 6f 6f 74 20 2d 75 20 30 20 2d 6f 20 6d 79 73 71 6c 5f 64 62}
		$s1 = {2f 69 70 2e 70 68 70 3f 70 6f 72 74 3d 24 7b 50 4f 52 54 7d 22}
		$s2 = {73 65 64 20 2d 69 20 2d 65 20 27 2f 50 61 73 73 77 6f 72 64 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e}
		$s3 = {50 41 54 48 5f 4b 45 59 3d 2f 72 6f 6f 74 2f 2e 73 73 68 2f 61 75 74 68 6f 72 69 7a 65 64 5f 6b 65 79 73}
		$s4 = {43 52 45 41 54 45 20 55 53 45 52}
		$s5 = {63 72 6f 6e 74 61 62 20 2d 6c 20 7c 20 7b 20 63 61 74 3b 20 65 63 68 6f}
		$s6 = {6d 79 73 71 6c 64 20 2d 2d 75 73 65 72 3d 6d 79 73 71 6c 20 2d 2d 69 6e 69 74 2d 66 69 6c 65 3d 2f 65 74 63 2f 6f 70 74 2f 69 6e 69 74 2d 66 69 6c 65 2e 74 78 74 20 2d 2d 63 6f 6e 73 6f 6c 65}
		$s7 = {73 73 68 6b 65 79 2e 70 68 70}

	condition:
		uint16( 0 ) == 0x2123 and filesize < 20KB and 1 of ( $x* ) or 4 of them
}

rule APT_RU_Sandworm_PY_May20_1 : hardened
{
	meta:
		description = "Detects Sandworm Python loader"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/billyleonard/status/1266054881225236482"
		date = "2020-05-28"
		hash1 = "c025008463fdbf44b2f845f2d82702805d931771aea4b506573b83c8f58bccca"
		id = "a392d800-1fe8-5ae9-b813-e1dfcedecda6"

	strings:
		$x1 = {6f 2e 61 64 64 68 65 61 64 65 72 73 3d 5b 28 27 55 73 65 72 2d 41 67 65 6e 74 27 2c 27 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 54 72 69 64 65 6e 74 2f 37 2e 30 3b 20 72 76 3a 31 31 2e 30 29 20 6c 69 6b 65 20 47 65 63 6b 6f 27 29 5d}
		$s1 = {65 78 65 63 28 6f 2e 6f 70 65 6e 28 27 68 74 74 70 3a 2f 2f}
		$s2 = {5f 5f 69 6d 70 6f 72 74 5f 5f 28 7b 32 3a 27 75 72 6c 6c 69 62 32 27 2c 33 3a 27 75 72 6c 6c 69 62 2e 72 65 71 75 65 73 74 27 7d}

	condition:
		uint16( 0 ) == 0x6d69 and filesize < 1KB and 1 of ( $x* ) or 2 of them
}

rule APT_RU_Sandworm_PY_May20_2 : hardened
{
	meta:
		description = "Detects Sandworm Python loader"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/billyleonard/status/1266054881225236482"
		date = "2020-05-28"
		hash1 = "abfa83cf54db8fa548942acd845b4f34acc94c46d4e1fb5ce7e97cc0c6596676"
		id = "5b32ad64-d959-5632-a03c-17aa055b213f"

	strings:
		$x1 = {69 6d 70 6f 72 74 20 73 79 73 3b 69 6d 70 6f 72 74 20 72 65 2c 20 73 75 62 70 72 6f 63 65 73 73 3b 63 6d 64}
		$x2 = {55 41 3d 27 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 57 4f 57 36 34 3b 20 54 72 69 64 65 6e 74 2f 37 2e 30 3b 20 72 76 3a 31 31 2e 30 29 20 6c 69 6b 65 20 47 65 63 6b 6f 27 3b 73 65 72 76 65 72 3d 27 68 74 74 70}
		$x3 = {27 3b 74 3d 27 2f 61 64 6d 69 6e 2f 67 65 74 2e 70 68 70 27 3b 72 65 71}
		$x4 = {70 73 20 2d 65 66 20 7c 20 67 72 65 70 20 4c 69 74 74 6c 65 5c 20 53 6e 69 74 63 68 20 7c 20 67 72 65 70 20}

	condition:
		uint16( 0 ) == 0x6d69 and filesize < 2KB and 1 of them
}

