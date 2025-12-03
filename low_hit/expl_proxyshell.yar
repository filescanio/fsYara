rule EXPL_Exchange_ProxyShell_Failed_Aug21_1 : SCRIPT hardened
{
	meta:
		description = "Detects ProxyShell exploitation attempts in log files"
		author = "Florian Roth (Nextron Systems)"
		score = 50
		reference = "https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html"
		date = "2021-08-08"
		modified = "2021-08-09"
		id = "9b849042-8918-5322-a35a-2165d4b541d5"

	strings:
		$xr1 = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(powershell|mapi\/nspi|EWS\/|X-Rps-CAT)[^\n]{1,400}401 0 0/ nocase ascii
		$xr3 = /Email=autodiscover\/autodiscover\.json[^\n]{1,400}401 0 0/ nocase ascii

	condition:
		1 of them
}

rule EXPL_Exchange_ProxyShell_Successful_Aug21_1 : SCRIPT hardened
{
	meta:
		description = "Detects successful ProxyShell exploitation attempts in log files"
		author = "Florian Roth (Nextron Systems)"
		score = 85
		reference = "https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html"
		date = "2021-08-08"
		modified = "2021-08-09"
		id = "8c11cd1a-6d3f-5f29-af61-17179b01ca8b"

	strings:
		$xr1a = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(powershell|X-Rps-CAT)/ nocase ascii
		$xr1b = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(mapi\/nspi|EWS\/)[^\n]{1,400}(200|302) 0 0/
		$xr2 = /autodiscover\/autodiscover\.json[^\n]{1,60}&X-Rps-CAT=/ nocase ascii
		$xr3 = /Email=autodiscover\/autodiscover\.json[^\n]{1,400}200 0 0/ nocase ascii

	condition:
		1 of them
}

rule APT_IIS_Config_ProxyShell_Artifacts : hardened
{
	meta:
		description = "Detects virtual directory configured in IIS pointing to a ProgramData folder (as found in attacks against Exchange servers in August 2021)"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit"
		date = "2021-08-25"
		score = 90
		id = "21888fc0-82c6-555a-9320-9cbb8332a843"

	strings:
		$a1 = {3c 73 69 74 65 20 6e 61 6d 65 3d}
		$a2 = {3c 73 65 63 74 69 6f 6e 47 72 6f 75 70 20 6e 61 6d 65 3d 22 73 79 73 74 65 6d 2e 77 65 62 53 65 72 76 65 72 22 3e}
		$sa1 = {20 70 68 79 73 69 63 61 6c 50 61 74 68 3d 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 43 4f 4d}
		$sa2 = {20 70 68 79 73 69 63 61 6c 50 61 74 68 3d 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 57 48 4f}
		$sa3 = {20 70 68 79 73 69 63 61 6c 50 61 74 68 3d 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 5a 49 4e 47}
		$sa4 = {20 70 68 79 73 69 63 61 6c 50 61 74 68 3d 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 5a 4f 4f}
		$sa5 = {20 70 68 79 73 69 63 61 6c 50 61 74 68 3d 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 58 59 5a}
		$sa6 = {20 70 68 79 73 69 63 61 6c 50 61 74 68 3d 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 41 55 58}
		$sa7 = {20 70 68 79 73 69 63 61 6c 50 61 74 68 3d 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 43 4f 4e 5c}
		$sb1 = {20 70 68 79 73 69 63 61 6c 50 61 74 68 3d 22 43 3a 5c 55 73 65 72 73 5c 41 6c 6c 20 55 73 65 72 73 5c}

	condition:
		filesize < 500KB and all of ( $a* ) and 1 of ( $s* )
}

rule SUSP_IIS_Config_ProxyShell_Artifacts : hardened
{
	meta:
		description = "Detects suspicious virtual directory configured in IIS pointing to a ProgramData folder (as found in attacks against Exchange servers in August 2021)"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit"
		date = "2021-08-25"
		score = 70
		id = "bde65d9e-b17d-5746-8d29-8419363d0511"

	strings:
		$a1 = {3c 73 69 74 65 20 6e 61 6d 65 3d}
		$a2 = {3c 73 65 63 74 69 6f 6e 47 72 6f 75 70 20 6e 61 6d 65 3d 22 73 79 73 74 65 6d 2e 77 65 62 53 65 72 76 65 72 22 3e}
		$s1 = {20 70 68 79 73 69 63 61 6c 50 61 74 68 3d 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c}

	condition:
		filesize < 500KB and all of ( $a* ) and 1 of ( $s* )
}

rule SUSP_IIS_Config_VirtualDir : hardened
{
	meta:
		description = "Detects suspicious virtual directory configured in IIS pointing to a User folder"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit"
		date = "2021-08-25"
		modified = "2022-09-17"
		score = 60
		id = "cfe5ca5e-a0cc-5f60-84d2-1b0538e999c7"

	strings:
		$a1 = {3c 73 69 74 65 20 6e 61 6d 65 3d}
		$a2 = {3c 73 65 63 74 69 6f 6e 47 72 6f 75 70 20 6e 61 6d 65 3d 22 73 79 73 74 65 6d 2e 77 65 62 53 65 72 76 65 72 22 3e}
		$s2 = {20 70 68 79 73 69 63 61 6c 50 61 74 68 3d 22 43 3a 5c 55 73 65 72 73 5c}
		$fp1 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 57 00 65 00 62 00 2e 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 69 00 6f 00 6e 00}
		$fp2 = {3c 76 69 72 74 75 61 6c 44 69 72 65 63 74 6f 72 79 20 70 61 74 68 3d 22 2f 22 20 70 68 79 73 69 63 61 6c 50 61 74 68 3d 22 43 3a 5c 55 73 65 72 73 5c 61 64 6d 69 6e 5c}

	condition:
		filesize < 500KB and all of ( $a* ) and 1 of ( $s* ) and not 1 of ( $fp* )
}

rule SUSP_ASPX_PossibleDropperArtifact_Aug21 : hardened limited
{
	meta:
		description = "Detects an ASPX file with a non-ASCII header, often a result of MS Exchange drop techniques"
		reference = "Internal Research"
		author = "Max Altgelt"
		date = "2021-08-23"
		score = 60
		id = "52016598-74a1-53d6-812a-40b078ba0bb9"

	strings:
		$s1 = {50 61 67 65 20 4c 61 6e 67 75 61 67 65 3d}
		$fp1 = {50 61 67 65 20 4c 61 6e 67 75 61 67 65 3d 22 6a 61 76 61 22}

	condition:
		filesize < 500KB and not uint16( 0 ) == 0x4B50 and not uint16( 0 ) == 0x6152 and not uint16( 0 ) == 0x8b1f and not uint16( 0 ) == 0x5A4D and not uint16( 0 ) == 0xCFD0 and not uint16( 0 ) == 0xC3D4 and not uint16( 0 ) == 0x534D and all of ( $s* ) and not 1 of ( $fp* ) and ( ( ( uint8( 0 ) < 0x20 or uint8( 0 ) > 0x7E ) and uint8( 0 ) != 0x9 and uint8( 0 ) != 0x0D and uint8( 0 ) != 0x0A and uint8( 0 ) != 0xEF ) or ( ( uint8( 1 ) < 0x20 or uint8( 1 ) > 0x7E ) and uint8( 1 ) != 0x9 and uint8( 1 ) != 0x0D and uint8( 1 ) != 0x0A and uint8( 1 ) != 0xBB ) or ( ( uint8( 2 ) < 0x20 or uint8( 2 ) > 0x7E ) and uint8( 2 ) != 0x9 and uint8( 2 ) != 0x0D and uint8( 2 ) != 0x0A and uint8( 2 ) != 0xBF ) or ( ( uint8( 3 ) < 0x20 or uint8( 3 ) > 0x7E ) and uint8( 3 ) != 0x9 and uint8( 3 ) != 0x0D and uint8( 3 ) != 0x0A ) or ( ( uint8( 4 ) < 0x20 or uint8( 4 ) > 0x7E ) and uint8( 4 ) != 0x9 and uint8( 4 ) != 0x0D and uint8( 4 ) != 0x0A ) or ( ( uint8( 5 ) < 0x20 or uint8( 5 ) > 0x7E ) and uint8( 5 ) != 0x9 and uint8( 5 ) != 0x0D and uint8( 5 ) != 0x0A ) or ( ( uint8( 6 ) < 0x20 or uint8( 6 ) > 0x7E ) and uint8( 6 ) != 0x9 and uint8( 6 ) != 0x0D and uint8( 6 ) != 0x0A ) or ( ( uint8( 7 ) < 0x20 or uint8( 7 ) > 0x7E ) and uint8( 7 ) != 0x9 and uint8( 7 ) != 0x0D and uint8( 7 ) != 0x0A ) )
}

