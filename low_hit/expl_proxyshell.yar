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

rule WEBSHELL_ASPX_ProxyShell_Aug21_2 : hardened limited
{
	meta:
		description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be PST), size and content"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-servers-are-getting-hacked-via-proxyshell-exploits/"
		date = "2021-08-13"
		id = "a351a466-695e-570e-8c7f-9c6c0534839c"

	strings:
		$s1 = {50 61 67 65 20 4c 61 6e 67 75 61 67 65 3d}

	condition:
		uint32( 0 ) == 0x4e444221 and filesize < 2MB and $s1
}

rule WEBSHELL_ASPX_ProxyShell_Aug21_3 : hardened limited
{
	meta:
		description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be DER), size and content"
		author = "Max Altgelt"
		reference = "https://twitter.com/gossithedog/status/1429175908905127938?s=12"
		date = "2021-08-23"
		score = 75
		id = "a7bca62b-c8f1-5a38-81df-f3d4582a590b"

	strings:
		$s1 = {50 61 67 65 20 4c 61 6e 67 75 61 67 65 3d}

	condition:
		uint16( 0 ) == 0x8230 and filesize < 10KB and $s1
}

rule WEBSHELL_ASPX_ProxyShell_Sep21_1 : hardened
{
	meta:
		description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be PST) and base64 decoded request"
		author = "Tobias Michalski"
		date = "2021-09-17"
		reference = "Internal Research"
		hash = "219468c10d2b9d61a8ae70dc8b6d2824ca8fbe4e53bbd925eeca270fef0fd640"
		score = 75
		id = "d0d23e17-6b6a-51d1-afd9-59cc2404bcd8"

	strings:
		$s = {2e 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 52 65 71 75 65 73 74 5b}

	condition:
		uint32( 0 ) == 0x4e444221 and any of them
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

rule WEBSHELL_ASPX_ProxyShell_Exploitation_Aug21_1 : hardened
{
	meta:
		description = "Detects unknown malicious loaders noticed in August 2021"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/VirITeXplorer/status/1430206853733097473"
		date = "2021-08-25"
		score = 90
		id = "1fa563fc-c91c-5f4e-98f1-b895e1acb4f4"

	strings:
		$x1 = {29 3b 65 76 61 6c 2f 2a 61 73 66}

	condition:
		filesize < 600KB and 1 of them
}

rule WEBSHELL_ASPX_ProxyShell_Aug15 : hardened
{
	meta:
		description = "Webshells iisstart.aspx and Logout.aspx"
		author = "Moritz Oettle"
		reference = "https://github.com/hvs-consulting/ioc_signatures/tree/main/Proxyshell"
		date = "2021-09-04"
		score = 75
		id = "b1e6c0f3-787f-59b8-8123-4045522047ca"

	strings:
		$g1 = {6c 61 6e 67 75 61 67 65 3d 22 4a 53 63 72 69 70 74 22}
		$g2 = {66 75 6e 63 74 69 6f 6e 20 67 65 74 45 72 72 6f 72 57 6f 72 64}
		$g3 = {65 72 72 6f 72 57 6f 72 64}
		$g4 = {52 65 73 70 6f 6e 73 65 2e 52 65 64 69 72 65 63 74}
		$g5 = {66 75 6e 63 74 69 6f 6e 20 50 61 67 65 5f 4c 6f 61 64}
		$g6 = {72 75 6e 61 74 3d 22 73 65 72 76 65 72 22}
		$g7 = {52 65 71 75 65 73 74 5b}
		$g8 = {65 76 61 6c 2f 2a}
		$s1 = {41 70 70 63 61 63 68 65 56 65 72}
		$s2 = {63 6c 69 65 6e 74 43 6f 64 65}
		$s3 = {4c 61 54 6b 57 66 49 36 34 58 65 44 41 58 5a 53 36 70 55 31 4b 72 73 76 4c 41 63 47 48 37 41 5a 4f 51 58 6a 72 46 6b 54 38 31 36 52 6e 46 59 4a 51 52}

	condition:
		filesize < 1KB and ( 1 of ( $s* ) or 4 of ( $g* ) )
}

rule WEBSHELL_Mailbox_Export_PST_ProxyShell_Aug26 : hardened
{
	meta:
		description = "Webshells generated by an Mailbox export to PST and stored as aspx: 570221043.aspx 689193944.aspx luifdecggoqmansn.aspx"
		author = "Moritz Oettle"
		reference = "https://github.com/hvs-consulting/ioc_signatures/tree/main/Proxyshell"
		date = "2021-09-04"
		score = 85
		id = "6aea414f-d27c-5202-84f8-b8620782fc90"

	strings:
		$x1 = {21 42 44 4e}
		$g1 = {50 61 67 65 20 6c 61 6e 67 75 61 67 65 3d}
		$g2 = {3c 25 40 20 50 61 67 65}
		$g3 = {52 65 71 75 65 73 74 2e 49 74 65 6d 5b}
		$g4 = {22 75 6e 73 61 66 65 22 29 3b}
		$g5 = {3c 25 65 76 61 6c 28}
		$g6 = {73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d}
		$g7 = {52 65 71 75 65 73 74 5b}
		$s1 = {67 6f 6c 64 38 38 39 39}
		$s2 = {65 78 65 63 5f 63 6f 64 65}
		$s3 = {6f 72 61 6e 67 65 6e 62}

	condition:
		filesize < 500KB and $x1 at 0 and ( 1 of ( $s* ) or 3 of ( $g* ) )
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

rule WEBSHELL_ProxyShell_Exploitation_Nov21_1 : hardened
{
	meta:
		description = "Detects webshells dropped by DropHell malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.deepinstinct.com/blog/do-not-exchange-it-has-a-shell-inside"
		date = "2021-11-01"
		score = 85
		id = "300eaadf-db0c-5591-84fc-abdf7cdd90c1"

	strings:
		$s01 = {((2e 4c 6f 61 64 58 6d 6c 28 53 79 73 74 65 6d 2e 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 2e 55 54 46 38 2e 47 65 74 53 74 72 69 6e 67 28 53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 2e 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 52 65 71 75 65 73 74 5b) | (2e 00 4c 00 6f 00 61 00 64 00 58 00 6d 00 6c 00 28 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 54 00 65 00 78 00 74 00 2e 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 2e 00 55 00 54 00 46 00 38 00 2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 2e 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 5b 00))}
		$s02 = {((6e 65 77 20 53 79 73 74 65 6d 2e 49 4f 2e 4d 65 6d 6f 72 79 53 74 72 65 61 6d 28 29) | (6e 00 65 00 77 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 49 00 4f 00 2e 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 53 00 74 00 72 00 65 00 61 00 6d 00 28 00 29 00))}
		$s03 = {((54 72 61 6e 73 66 6f 72 6d 28) | (54 00 72 00 61 00 6e 00 73 00 66 00 6f 00 72 00 6d 00 28 00))}

	condition:
		all of ( $s* )
}

