rule HKTL_NET_NAME_FakeFileMaker : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/DamonMohammadbagher/FakeFileMaker"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((46 61 6b 65 46 69 6c 65 4d 61 6b 65 72) | (46 00 61 00 6b 00 65 00 46 00 69 00 6c 00 65 00 4d 00 61 00 6b 00 65 00 72 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_pentestscripts : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/c4bbage/pentestscripts"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((70 65 6e 74 65 73 74 73 63 72 69 70 74 73) | (70 00 65 00 6e 00 74 00 65 00 73 00 74 00 73 00 63 00 72 00 69 00 70 00 74 00 73 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_WMIPersistence : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/mdsecactivebreach/WMIPersistence"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((57 4d 49 50 65 72 73 69 73 74 65 6e 63 65) | (57 00 4d 00 49 00 50 00 65 00 72 00 73 00 69 00 73 00 74 00 65 00 6e 00 63 00 65 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_ADCollector : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/dev-2null/ADCollector"
		hash = "5391239f479c26e699b6f3a1d6a0a8aa1a0cf9a8"
		hash = "9dd0f322dd57b906da1e543c44e764954704abae"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((41 44 43 6f 6c 6c 65 63 74 6f 72) | (41 00 44 00 43 00 6f 00 6c 00 6c 00 65 00 63 00 74 00 6f 00 72 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_MaliciousClickOnceGenerator : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/Mr-Un1k0d3r/MaliciousClickOnceGenerator"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((4d 61 6c 69 63 69 6f 75 73 43 6c 69 63 6b 4f 6e 63 65 47 65 6e 65 72 61 74 6f 72) | (4d 00 61 00 6c 00 69 00 63 00 69 00 6f 00 75 00 73 00 43 00 6c 00 69 00 63 00 6b 00 4f 00 6e 00 63 00 65 00 47 00 65 00 6e 00 65 00 72 00 61 00 74 00 6f 00 72 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_directInjectorPOC : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/badBounty/directInjectorPOC"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((64 69 72 65 63 74 49 6e 6a 65 63 74 6f 72 50 4f 43) | (64 00 69 00 72 00 65 00 63 00 74 00 49 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00 50 00 4f 00 43 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_AsStrongAsFuck : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/Charterino/AsStrongAsFuck"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((41 73 53 74 72 6f 6e 67 41 73 46 75 63 6b) | (41 00 73 00 53 00 74 00 72 00 6f 00 6e 00 67 00 41 00 73 00 46 00 75 00 63 00 6b 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_MagentoScanner : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/soufianetahiri/MagentoScanner"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((4d 61 67 65 6e 74 6f 53 63 61 6e 6e 65 72) | (4d 00 61 00 67 00 65 00 6e 00 74 00 6f 00 53 00 63 00 61 00 6e 00 6e 00 65 00 72 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_RevengeRAT_Stub_CSsharp : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/NYAN-x-CAT/RevengeRAT-Stub-CSsharp"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((52 65 76 65 6e 67 65 52 41 54 2d 53 74 75 62 2d 43 53 73 68 61 72 70) | (52 00 65 00 76 00 65 00 6e 00 67 00 65 00 52 00 41 00 54 00 2d 00 53 00 74 00 75 00 62 00 2d 00 43 00 53 00 73 00 68 00 61 00 72 00 70 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_SharPyShell : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/antonioCoco/SharPyShell"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((53 68 61 72 50 79 53 68 65 6c 6c) | (53 00 68 00 61 00 72 00 50 00 79 00 53 00 68 00 65 00 6c 00 6c 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_GhostLoader : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/TheWover/GhostLoader"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((47 68 6f 73 74 4c 6f 61 64 65 72) | (47 00 68 00 6f 00 73 00 74 00 4c 00 6f 00 61 00 64 00 65 00 72 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_DotNetInject : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/dtrizna/DotNetInject"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((44 6f 74 4e 65 74 49 6e 6a 65 63 74) | (44 00 6f 00 74 00 4e 00 65 00 74 00 49 00 6e 00 6a 00 65 00 63 00 74 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_ATPMiniDump : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/b4rtik/ATPMiniDump"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((41 54 50 4d 69 6e 69 44 75 6d 70) | (41 00 54 00 50 00 4d 00 69 00 6e 00 69 00 44 00 75 00 6d 00 70 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_ConfuserEx : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/yck1509/ConfuserEx"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((43 6f 6e 66 75 73 65 72 45 78) | (43 00 6f 00 6e 00 66 00 75 00 73 00 65 00 72 00 45 00 78 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_SharpBuster : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/passthehashbrowns/SharpBuster"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((53 68 61 72 70 42 75 73 74 65 72) | (53 00 68 00 61 00 72 00 70 00 42 00 75 00 73 00 74 00 65 00 72 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_AmsiBypass : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/0xB455/AmsiBypass"
		hash = "8fa4ba512b34a898c4564a8eac254b6a786d195b"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((41 6d 73 69 42 79 70 61 73 73) | (41 00 6d 00 73 00 69 00 42 00 79 00 70 00 61 00 73 00 73 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_Recon_AD : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/outflanknl/Recon-AD"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((52 65 63 6f 6e 2d 41 44) | (52 00 65 00 63 00 6f 00 6e 00 2d 00 41 00 44 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_SharpWatchdogs : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/RITRedteam/SharpWatchdogs"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((53 68 61 72 70 57 61 74 63 68 64 6f 67 73) | (53 00 68 00 61 00 72 00 70 00 57 00 61 00 74 00 63 00 68 00 64 00 6f 00 67 00 73 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_SharpCat : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/Cn33liz/SharpCat"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((53 68 61 72 70 43 61 74) | (53 00 68 00 61 00 72 00 70 00 43 00 61 00 74 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_aspnetcore_bypassing_authentication : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/jackowild/aspnetcore-bypassing-authentication"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((61 73 70 6e 65 74 63 6f 72 65 2d 62 79 70 61 73 73 69 6e 67 2d 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e) | (61 00 73 00 70 00 6e 00 65 00 74 00 63 00 6f 00 72 00 65 00 2d 00 62 00 79 00 70 00 61 00 73 00 73 00 69 00 6e 00 67 00 2d 00 61 00 75 00 74 00 68 00 65 00 6e 00 74 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_K8tools : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/k8gege/K8tools"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((4b 38 74 6f 6f 6c 73) | (4b 00 38 00 74 00 6f 00 6f 00 6c 00 73 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_HTTPSBeaconShell : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/limbenjamin/HTTPSBeaconShell"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((48 54 54 50 53 42 65 61 63 6f 6e 53 68 65 6c 6c) | (48 00 54 00 54 00 50 00 53 00 42 00 65 00 61 00 63 00 6f 00 6e 00 53 00 68 00 65 00 6c 00 6c 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_Ghostpack_CompiledBinaries : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((47 68 6f 73 74 70 61 63 6b 2d 43 6f 6d 70 69 6c 65 64 42 69 6e 61 72 69 65 73) | (47 00 68 00 6f 00 73 00 74 00 70 00 61 00 63 00 6b 00 2d 00 43 00 6f 00 6d 00 70 00 69 00 6c 00 65 00 64 00 42 00 69 00 6e 00 61 00 72 00 69 00 65 00 73 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_metasploit_sharp : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/VolatileMindsLLC/metasploit-sharp"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((6d 65 74 61 73 70 6c 6f 69 74 2d 73 68 61 72 70) | (6d 00 65 00 74 00 61 00 73 00 70 00 6c 00 6f 00 69 00 74 00 2d 00 73 00 68 00 61 00 72 00 70 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_trevorc2 : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/trustedsec/trevorc2"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((74 72 65 76 6f 72 63 32) | (74 00 72 00 65 00 76 00 6f 00 72 00 63 00 32 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_petaqc2 : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/fozavci/petaqc2"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((70 65 74 61 71 63 32) | (70 00 65 00 74 00 61 00 71 00 63 00 32 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_NativePayload_DNS2 : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/DamonMohammadbagher/NativePayload_DNS2"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((4e 61 74 69 76 65 50 61 79 6c 6f 61 64 5f 44 4e 53 32) | (4e 00 61 00 74 00 69 00 76 00 65 00 50 00 61 00 79 00 6c 00 6f 00 61 00 64 00 5f 00 44 00 4e 00 53 00 32 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_cve_2017_7269_tool : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/zcgonvh/cve-2017-7269-tool"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((63 76 65 2d 32 30 31 37 2d 37 32 36 39 2d 74 6f 6f 6c) | (63 00 76 00 65 00 2d 00 32 00 30 00 31 00 37 00 2d 00 37 00 32 00 36 00 39 00 2d 00 74 00 6f 00 6f 00 6c 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_AggressiveProxy : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/EncodeGroup/AggressiveProxy"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((41 67 67 72 65 73 73 69 76 65 50 72 6f 78 79) | (41 00 67 00 67 00 72 00 65 00 73 00 73 00 69 00 76 00 65 00 50 00 72 00 6f 00 78 00 79 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_MSBuildAPICaller : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/rvrsh3ll/MSBuildAPICaller"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((4d 53 42 75 69 6c 64 41 50 49 43 61 6c 6c 65 72) | (4d 00 53 00 42 00 75 00 69 00 6c 00 64 00 41 00 50 00 49 00 43 00 61 00 6c 00 6c 00 65 00 72 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_GrayKeylogger : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/DarkSecDevelopers/GrayKeylogger"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((47 72 61 79 4b 65 79 6c 6f 67 67 65 72) | (47 00 72 00 61 00 79 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_weevely3 : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/epinna/weevely3"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((77 65 65 76 65 6c 79 33) | (77 00 65 00 65 00 76 00 65 00 6c 00 79 00 33 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_FudgeC2 : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/Ziconius/FudgeC2"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((46 75 64 67 65 43 32) | (46 00 75 00 64 00 67 00 65 00 43 00 32 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_NativePayload_Reverse_tcp : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/DamonMohammadbagher/NativePayload_Reverse_tcp"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((4e 61 74 69 76 65 50 61 79 6c 6f 61 64 5f 52 65 76 65 72 73 65 5f 74 63 70) | (4e 00 61 00 74 00 69 00 76 00 65 00 50 00 61 00 79 00 6c 00 6f 00 61 00 64 00 5f 00 52 00 65 00 76 00 65 00 72 00 73 00 65 00 5f 00 74 00 63 00 70 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_SharpHose : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/ustayready/SharpHose"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((53 68 61 72 70 48 6f 73 65) | (53 00 68 00 61 00 72 00 70 00 48 00 6f 00 73 00 65 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_RAT_NjRat_0_7d_modded_source_code : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/AliBawazeEer/RAT-NjRat-0.7d-modded-source-code"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((52 41 54 2d 4e 6a 52 61 74 2d 30 2e 37 64 2d 6d 6f 64 64 65 64 2d 73 6f 75 72 63 65 2d 63 6f 64 65) | (52 00 41 00 54 00 2d 00 4e 00 6a 00 52 00 61 00 74 00 2d 00 30 00 2e 00 37 00 64 00 2d 00 6d 00 6f 00 64 00 64 00 65 00 64 00 2d 00 73 00 6f 00 75 00 72 00 63 00 65 00 2d 00 63 00 6f 00 64 00 65 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_RdpThief : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/0x09AL/RdpThief"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((52 64 70 54 68 69 65 66) | (52 00 64 00 70 00 54 00 68 00 69 00 65 00 66 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_RunasCs : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/antonioCoco/RunasCs"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((52 75 6e 61 73 43 73) | (52 00 75 00 6e 00 61 00 73 00 43 00 73 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_NativePayload_IP6DNS : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/DamonMohammadbagher/NativePayload_IP6DNS"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((4e 61 74 69 76 65 50 61 79 6c 6f 61 64 5f 49 50 36 44 4e 53) | (4e 00 61 00 74 00 69 00 76 00 65 00 50 00 61 00 79 00 6c 00 6f 00 61 00 64 00 5f 00 49 00 50 00 36 00 44 00 4e 00 53 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_NativePayload_ARP : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/DamonMohammadbagher/NativePayload_ARP"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((4e 61 74 69 76 65 50 61 79 6c 6f 61 64 5f 41 52 50) | (4e 00 61 00 74 00 69 00 76 00 65 00 50 00 61 00 79 00 6c 00 6f 00 61 00 64 00 5f 00 41 00 52 00 50 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_C2Bridge : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/cobbr/C2Bridge"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((43 32 42 72 69 64 67 65) | (43 00 32 00 42 00 72 00 69 00 64 00 67 00 65 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_Infrastructure_Assessment : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/NyaMeeEain/Infrastructure-Assessment"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((49 6e 66 72 61 73 74 72 75 63 74 75 72 65 2d 41 73 73 65 73 73 6d 65 6e 74) | (49 00 6e 00 66 00 72 00 61 00 73 00 74 00 72 00 75 00 63 00 74 00 75 00 72 00 65 00 2d 00 41 00 73 00 73 00 65 00 73 00 73 00 6d 00 65 00 6e 00 74 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_shellcodeTester : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/tophertimzen/shellcodeTester"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((73 68 65 6c 6c 63 6f 64 65 54 65 73 74 65 72) | (73 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00 54 00 65 00 73 00 74 00 65 00 72 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_gray_hat_csharp_code : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/brandonprry/gray_hat_csharp_code"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((67 72 61 79 5f 68 61 74 5f 63 73 68 61 72 70 5f 63 6f 64 65) | (67 00 72 00 61 00 79 00 5f 00 68 00 61 00 74 00 5f 00 63 00 73 00 68 00 61 00 72 00 70 00 5f 00 63 00 6f 00 64 00 65 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_NativePayload_ReverseShell : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/DamonMohammadbagher/NativePayload_ReverseShell"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((4e 61 74 69 76 65 50 61 79 6c 6f 61 64 5f 52 65 76 65 72 73 65 53 68 65 6c 6c) | (4e 00 61 00 74 00 69 00 76 00 65 00 50 00 61 00 79 00 6c 00 6f 00 61 00 64 00 5f 00 52 00 65 00 76 00 65 00 72 00 73 00 65 00 53 00 68 00 65 00 6c 00 6c 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_DotNetAVBypass : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/mandreko/DotNetAVBypass"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((44 6f 74 4e 65 74 41 56 42 79 70 61 73 73) | (44 00 6f 00 74 00 4e 00 65 00 74 00 41 00 56 00 42 00 79 00 70 00 61 00 73 00 73 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_HexyRunner : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/bao7uo/HexyRunner"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((48 65 78 79 52 75 6e 6e 65 72) | (48 00 65 00 78 00 79 00 52 00 75 00 6e 00 6e 00 65 00 72 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_SharpOffensiveShell : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/darkr4y/SharpOffensiveShell"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((53 68 61 72 70 4f 66 66 65 6e 73 69 76 65 53 68 65 6c 6c) | (53 00 68 00 61 00 72 00 70 00 4f 00 66 00 66 00 65 00 6e 00 73 00 69 00 76 00 65 00 53 00 68 00 65 00 6c 00 6c 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_reconness : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/reconness/reconness"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((72 65 63 6f 6e 6e 65 73 73) | (72 00 65 00 63 00 6f 00 6e 00 6e 00 65 00 73 00 73 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_tvasion : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/loadenmb/tvasion"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((74 76 61 73 69 6f 6e) | (74 00 76 00 61 00 73 00 69 00 6f 00 6e 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_ibombshell : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/Telefonica/ibombshell"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((69 62 6f 6d 62 73 68 65 6c 6c) | (69 00 62 00 6f 00 6d 00 62 00 73 00 68 00 65 00 6c 00 6c 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_RemoteProcessInjection : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/Mr-Un1k0d3r/RemoteProcessInjection"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((52 65 6d 6f 74 65 50 72 6f 63 65 73 73 49 6e 6a 65 63 74 69 6f 6e) | (52 00 65 00 6d 00 6f 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 49 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6f 00 6e 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_njRAT_0_7d_Stub_CSharp : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/NYAN-x-CAT/njRAT-0.7d-Stub-CSharp"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((6e 6a 52 41 54 2d 30 2e 37 64 2d 53 74 75 62 2d 43 53 68 61 72 70) | (6e 00 6a 00 52 00 41 00 54 00 2d 00 30 00 2e 00 37 00 64 00 2d 00 53 00 74 00 75 00 62 00 2d 00 43 00 53 00 68 00 61 00 72 00 70 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_CACTUSTORCH : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/mdsecactivebreach/CACTUSTORCH"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((43 41 43 54 55 53 54 4f 52 43 48) | (43 00 41 00 43 00 54 00 55 00 53 00 54 00 4f 00 52 00 43 00 48 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_PandaSniper : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/QAX-A-Team/PandaSniper"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((50 61 6e 64 61 53 6e 69 70 65 72) | (50 00 61 00 6e 00 64 00 61 00 53 00 6e 00 69 00 70 00 65 00 72 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_xbapAppWhitelistBypassPOC : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/jpginc/xbapAppWhitelistBypassPOC"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((78 62 61 70 41 70 70 57 68 69 74 65 6c 69 73 74 42 79 70 61 73 73 50 4f 43) | (78 00 62 00 61 00 70 00 41 00 70 00 70 00 57 00 68 00 69 00 74 00 65 00 6c 00 69 00 73 00 74 00 42 00 79 00 70 00 61 00 73 00 73 00 50 00 4f 00 43 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule HKTL_NET_NAME_StageStrike : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/RedXRanger/StageStrike"
		author = "Arnim Rupp"
		date = "2021-01-22"

	strings:
		$name = {((53 74 61 67 65 53 74 72 69 6b 65) | (53 00 74 00 61 00 67 00 65 00 53 00 74 00 72 00 69 00 6b 00 65 00))}
		$compile = {((41 73 73 65 6d 62 6c 79 54 69 74 6c 65) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 54 00 69 00 74 00 6c 00 65 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

