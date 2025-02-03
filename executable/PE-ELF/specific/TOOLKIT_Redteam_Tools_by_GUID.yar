rule HKTL_NET_GUID_CSharpSetThreadContext : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/djhohnstein/CSharpSetThreadContext"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "883bb859-d5ab-501d-8c83-0c5a2cf1f6c8"

	strings:
		$typelibguid0lo = {((61 31 65 32 38 63 38 63 2d 62 33 62 64 2d 34 34 64 65 2d 38 35 62 39 2d 38 61 61 37 63 31 38 61 37 31 34 64) | (61 00 31 00 65 00 32 00 38 00 63 00 38 00 63 00 2d 00 62 00 33 00 62 00 64 00 2d 00 34 00 34 00 64 00 65 00 2d 00 38 00 35 00 62 00 39 00 2d 00 38 00 61 00 61 00 37 00 63 00 31 00 38 00 61 00 37 00 31 00 34 00 64 00))}
		$typelibguid0up = {((41 31 45 32 38 43 38 43 2d 42 33 42 44 2d 34 34 44 45 2d 38 35 42 39 2d 38 41 41 37 43 31 38 41 37 31 34 44) | (41 00 31 00 45 00 32 00 38 00 43 00 38 00 43 00 2d 00 42 00 33 00 42 00 44 00 2d 00 34 00 34 00 44 00 45 00 2d 00 38 00 35 00 42 00 39 00 2d 00 38 00 41 00 41 00 37 00 43 00 31 00 38 00 41 00 37 00 31 00 34 00 44 00))}
		$typelibguid1lo = {((38 37 63 35 39 37 30 65 2d 30 63 37 37 2d 34 31 38 32 2d 61 66 65 32 2d 33 66 65 39 36 66 37 38 35 65 62 62) | (38 00 37 00 63 00 35 00 39 00 37 00 30 00 65 00 2d 00 30 00 63 00 37 00 37 00 2d 00 34 00 31 00 38 00 32 00 2d 00 61 00 66 00 65 00 32 00 2d 00 33 00 66 00 65 00 39 00 36 00 66 00 37 00 38 00 35 00 65 00 62 00 62 00))}
		$typelibguid1up = {((38 37 43 35 39 37 30 45 2d 30 43 37 37 2d 34 31 38 32 2d 41 46 45 32 2d 33 46 45 39 36 46 37 38 35 45 42 42) | (38 00 37 00 43 00 35 00 39 00 37 00 30 00 45 00 2d 00 30 00 43 00 37 00 37 00 2d 00 34 00 31 00 38 00 32 00 2d 00 41 00 46 00 45 00 32 00 2d 00 33 00 46 00 45 00 39 00 36 00 46 00 37 00 38 00 35 00 45 00 42 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_DLL_Injection : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ihack4falafel/DLL-Injection"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "aec4fc28-9aa2-5eef-9fb1-d187a83a72b3"

	strings:
		$typelibguid0lo = {((33 64 37 65 31 34 33 33 2d 66 38 31 61 2d 34 32 38 61 2d 39 33 34 66 2d 37 63 63 37 66 63 66 31 31 34 39 64) | (33 00 64 00 37 00 65 00 31 00 34 00 33 00 33 00 2d 00 66 00 38 00 31 00 61 00 2d 00 34 00 32 00 38 00 61 00 2d 00 39 00 33 00 34 00 66 00 2d 00 37 00 63 00 63 00 37 00 66 00 63 00 66 00 31 00 31 00 34 00 39 00 64 00))}
		$typelibguid0up = {((33 44 37 45 31 34 33 33 2d 46 38 31 41 2d 34 32 38 41 2d 39 33 34 46 2d 37 43 43 37 46 43 46 31 31 34 39 44) | (33 00 44 00 37 00 45 00 31 00 34 00 33 00 33 00 2d 00 46 00 38 00 31 00 41 00 2d 00 34 00 32 00 38 00 41 00 2d 00 39 00 33 00 34 00 46 00 2d 00 37 00 43 00 43 00 37 00 46 00 43 00 46 00 31 00 31 00 34 00 39 00 44 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_LimeUSB_Csharp : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/LimeUSB-Csharp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "dfa96b36-e84c-510b-b16b-bd686777b83d"
		score = 60

	strings:
		$typelibguid0lo = {((39 34 65 61 34 33 61 62 2d 37 38 37 38 2d 34 30 34 38 2d 61 36 34 65 2d 32 62 32 31 62 33 62 34 33 36 36 64) | (39 00 34 00 65 00 61 00 34 00 33 00 61 00 62 00 2d 00 37 00 38 00 37 00 38 00 2d 00 34 00 30 00 34 00 38 00 2d 00 61 00 36 00 34 00 65 00 2d 00 32 00 62 00 32 00 31 00 62 00 33 00 62 00 34 00 33 00 36 00 36 00 64 00))}
		$typelibguid0up = {((39 34 45 41 34 33 41 42 2d 37 38 37 38 2d 34 30 34 38 2d 41 36 34 45 2d 32 42 32 31 42 33 42 34 33 36 36 44) | (39 00 34 00 45 00 41 00 34 00 33 00 41 00 42 00 2d 00 37 00 38 00 37 00 38 00 2d 00 34 00 30 00 34 00 38 00 2d 00 41 00 36 00 34 00 45 00 2d 00 32 00 42 00 32 00 31 00 42 00 33 00 42 00 34 00 33 00 36 00 36 00 44 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Ladon : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/k8gege/Ladon"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "57e3d2fa-d430-561b-9d42-cf58cda5ed7a"

	strings:
		$typelibguid0lo = {((63 33 33 35 34 30 35 66 2d 35 64 66 32 2d 34 63 37 64 2d 39 62 35 33 2d 64 36 35 61 64 66 62 65 64 34 31 32) | (63 00 33 00 33 00 35 00 34 00 30 00 35 00 66 00 2d 00 35 00 64 00 66 00 32 00 2d 00 34 00 63 00 37 00 64 00 2d 00 39 00 62 00 35 00 33 00 2d 00 64 00 36 00 35 00 61 00 64 00 66 00 62 00 65 00 64 00 34 00 31 00 32 00))}
		$typelibguid0up = {((43 33 33 35 34 30 35 46 2d 35 44 46 32 2d 34 43 37 44 2d 39 42 35 33 2d 44 36 35 41 44 46 42 45 44 34 31 32) | (43 00 33 00 33 00 35 00 34 00 30 00 35 00 46 00 2d 00 35 00 44 00 46 00 32 00 2d 00 34 00 43 00 37 00 44 00 2d 00 39 00 42 00 35 00 33 00 2d 00 44 00 36 00 35 00 41 00 44 00 46 00 42 00 45 00 44 00 34 00 31 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_WhiteListEvasion : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/khr0x40sh/WhiteListEvasion"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "cd2740d0-0315-5a32-b34a-1998024fcc06"

	strings:
		$typelibguid0lo = {((38 35 38 33 38 36 64 66 2d 34 36 35 36 2d 34 61 31 65 2d 39 34 62 37 2d 34 37 66 36 61 61 35 35 35 36 35 38) | (38 00 35 00 38 00 33 00 38 00 36 00 64 00 66 00 2d 00 34 00 36 00 35 00 36 00 2d 00 34 00 61 00 31 00 65 00 2d 00 39 00 34 00 62 00 37 00 2d 00 34 00 37 00 66 00 36 00 61 00 61 00 35 00 35 00 35 00 36 00 35 00 38 00))}
		$typelibguid0up = {((38 35 38 33 38 36 44 46 2d 34 36 35 36 2d 34 41 31 45 2d 39 34 42 37 2d 34 37 46 36 41 41 35 35 35 36 35 38) | (38 00 35 00 38 00 33 00 38 00 36 00 44 00 46 00 2d 00 34 00 36 00 35 00 36 00 2d 00 34 00 41 00 31 00 45 00 2d 00 39 00 34 00 42 00 37 00 2d 00 34 00 37 00 46 00 36 00 41 00 41 00 35 00 35 00 35 00 36 00 35 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Lime_Downloader : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Lime-Downloader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "bfb0f97c-6d95-5e11-ad11-5297bcf7c3df"

	strings:
		$typelibguid0lo = {((65 63 37 61 66 64 34 63 2d 66 62 63 34 2d 34 37 63 31 2d 39 39 61 61 2d 36 65 62 62 30 35 30 39 34 31 37 33) | (65 00 63 00 37 00 61 00 66 00 64 00 34 00 63 00 2d 00 66 00 62 00 63 00 34 00 2d 00 34 00 37 00 63 00 31 00 2d 00 39 00 39 00 61 00 61 00 2d 00 36 00 65 00 62 00 62 00 30 00 35 00 30 00 39 00 34 00 31 00 37 00 33 00))}
		$typelibguid0up = {((45 43 37 41 46 44 34 43 2d 46 42 43 34 2d 34 37 43 31 2d 39 39 41 41 2d 36 45 42 42 30 35 30 39 34 31 37 33) | (45 00 43 00 37 00 41 00 46 00 44 00 34 00 43 00 2d 00 46 00 42 00 43 00 34 00 2d 00 34 00 37 00 43 00 31 00 2d 00 39 00 39 00 41 00 41 00 2d 00 36 00 45 00 42 00 42 00 30 00 35 00 30 00 39 00 34 00 31 00 37 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_DarkEye : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/K1ngSoul/DarkEye"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "5dc6702f-a398-5be2-9df8-9a2ddc636a1f"

	strings:
		$typelibguid0lo = {((30 62 64 62 39 63 36 35 2d 31 34 65 64 2d 34 32 30 35 2d 61 62 30 63 2d 65 61 32 31 35 31 38 36 36 61 37 66) | (30 00 62 00 64 00 62 00 39 00 63 00 36 00 35 00 2d 00 31 00 34 00 65 00 64 00 2d 00 34 00 32 00 30 00 35 00 2d 00 61 00 62 00 30 00 63 00 2d 00 65 00 61 00 32 00 31 00 35 00 31 00 38 00 36 00 36 00 61 00 37 00 66 00))}
		$typelibguid0up = {((30 42 44 42 39 43 36 35 2d 31 34 45 44 2d 34 32 30 35 2d 41 42 30 43 2d 45 41 32 31 35 31 38 36 36 41 37 46) | (30 00 42 00 44 00 42 00 39 00 43 00 36 00 35 00 2d 00 31 00 34 00 45 00 44 00 2d 00 34 00 32 00 30 00 35 00 2d 00 41 00 42 00 30 00 43 00 2d 00 45 00 41 00 32 00 31 00 35 00 31 00 38 00 36 00 36 00 41 00 37 00 46 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpKatz : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/b4rtik/SharpKatz"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "ff084b4c-4b00-5504-85ee-d6d17b5be504"

	strings:
		$typelibguid0lo = {((38 35 36 38 62 34 63 31 2d 32 39 34 30 2d 34 66 36 63 2d 62 66 34 65 2d 34 33 38 33 65 66 32 36 38 62 65 39) | (38 00 35 00 36 00 38 00 62 00 34 00 63 00 31 00 2d 00 32 00 39 00 34 00 30 00 2d 00 34 00 66 00 36 00 63 00 2d 00 62 00 66 00 34 00 65 00 2d 00 34 00 33 00 38 00 33 00 65 00 66 00 32 00 36 00 38 00 62 00 65 00 39 00))}
		$typelibguid0up = {((38 35 36 38 42 34 43 31 2d 32 39 34 30 2d 34 46 36 43 2d 42 46 34 45 2d 34 33 38 33 45 46 32 36 38 42 45 39) | (38 00 35 00 36 00 38 00 42 00 34 00 43 00 31 00 2d 00 32 00 39 00 34 00 30 00 2d 00 34 00 46 00 36 00 43 00 2d 00 42 00 46 00 34 00 45 00 2d 00 34 00 33 00 38 00 33 00 45 00 46 00 32 00 36 00 38 00 42 00 45 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_ExternalC2 : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ryhanson/ExternalC2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "1bbdfbb9-a3e8-5ffe-9db9-b50937e6a14d"

	strings:
		$typelibguid0lo = {((37 32 36 36 61 63 62 62 2d 62 31 30 64 2d 34 38 37 33 2d 39 62 39 39 2d 31 32 64 32 30 34 33 62 31 64 34 65) | (37 00 32 00 36 00 36 00 61 00 63 00 62 00 62 00 2d 00 62 00 31 00 30 00 64 00 2d 00 34 00 38 00 37 00 33 00 2d 00 39 00 62 00 39 00 39 00 2d 00 31 00 32 00 64 00 32 00 30 00 34 00 33 00 62 00 31 00 64 00 34 00 65 00))}
		$typelibguid0up = {((37 32 36 36 41 43 42 42 2d 42 31 30 44 2d 34 38 37 33 2d 39 42 39 39 2d 31 32 44 32 30 34 33 42 31 44 34 45) | (37 00 32 00 36 00 36 00 41 00 43 00 42 00 42 00 2d 00 42 00 31 00 30 00 44 00 2d 00 34 00 38 00 37 00 33 00 2d 00 39 00 42 00 39 00 39 00 2d 00 31 00 32 00 44 00 32 00 30 00 34 00 33 00 42 00 31 00 44 00 34 00 45 00))}
		$typelibguid1lo = {((35 64 39 35 31 35 64 30 2d 64 66 36 37 2d 34 30 65 64 2d 61 36 62 32 2d 36 36 31 39 36 32 30 65 66 30 65 66) | (35 00 64 00 39 00 35 00 31 00 35 00 64 00 30 00 2d 00 64 00 66 00 36 00 37 00 2d 00 34 00 30 00 65 00 64 00 2d 00 61 00 36 00 62 00 32 00 2d 00 36 00 36 00 31 00 39 00 36 00 32 00 30 00 65 00 66 00 30 00 65 00 66 00))}
		$typelibguid1up = {((35 44 39 35 31 35 44 30 2d 44 46 36 37 2d 34 30 45 44 2d 41 36 42 32 2d 36 36 31 39 36 32 30 45 46 30 45 46) | (35 00 44 00 39 00 35 00 31 00 35 00 44 00 30 00 2d 00 44 00 46 00 36 00 37 00 2d 00 34 00 30 00 45 00 44 00 2d 00 41 00 36 00 42 00 32 00 2d 00 36 00 36 00 31 00 39 00 36 00 32 00 30 00 45 00 46 00 30 00 45 00 46 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Povlsomware : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/povlteksttv/Povlsomware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "0eba43d2-b415-5e72-9677-4a3238ff7c34"

	strings:
		$typelibguid0lo = {((66 65 30 64 35 61 61 37 2d 35 33 38 66 2d 34 32 66 36 2d 39 65 63 65 2d 62 31 34 31 35 36 30 66 37 37 38 31) | (66 00 65 00 30 00 64 00 35 00 61 00 61 00 37 00 2d 00 35 00 33 00 38 00 66 00 2d 00 34 00 32 00 66 00 36 00 2d 00 39 00 65 00 63 00 65 00 2d 00 62 00 31 00 34 00 31 00 35 00 36 00 30 00 66 00 37 00 37 00 38 00 31 00))}
		$typelibguid0up = {((46 45 30 44 35 41 41 37 2d 35 33 38 46 2d 34 32 46 36 2d 39 45 43 45 2d 42 31 34 31 35 36 30 46 37 37 38 31) | (46 00 45 00 30 00 44 00 35 00 41 00 41 00 37 00 2d 00 35 00 33 00 38 00 46 00 2d 00 34 00 32 00 46 00 36 00 2d 00 39 00 45 00 43 00 45 00 2d 00 42 00 31 00 34 00 31 00 35 00 36 00 30 00 46 00 37 00 37 00 38 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_RunShellcode : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/zerosum0x0/RunShellcode"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "249da967-68b0-59b1-b414-4eb4fe67b8f3"

	strings:
		$typelibguid0lo = {((61 33 65 63 31 38 61 33 2d 36 37 34 63 2d 34 31 33 31 2d 61 37 66 35 2d 61 63 62 65 64 30 33 34 62 38 31 39) | (61 00 33 00 65 00 63 00 31 00 38 00 61 00 33 00 2d 00 36 00 37 00 34 00 63 00 2d 00 34 00 31 00 33 00 31 00 2d 00 61 00 37 00 66 00 35 00 2d 00 61 00 63 00 62 00 65 00 64 00 30 00 33 00 34 00 62 00 38 00 31 00 39 00))}
		$typelibguid0up = {((41 33 45 43 31 38 41 33 2d 36 37 34 43 2d 34 31 33 31 2d 41 37 46 35 2d 41 43 42 45 44 30 33 34 42 38 31 39) | (41 00 33 00 45 00 43 00 31 00 38 00 41 00 33 00 2d 00 36 00 37 00 34 00 43 00 2d 00 34 00 31 00 33 00 31 00 2d 00 41 00 37 00 46 00 35 00 2d 00 41 00 43 00 42 00 45 00 44 00 30 00 33 00 34 00 42 00 38 00 31 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpLoginPrompt : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/shantanu561993/SharpLoginPrompt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "e9a493d9-21b6-5ff1-9e5e-e8fbacc34c0c"

	strings:
		$typelibguid0lo = {((63 31 32 65 36 39 63 64 2d 37 38 61 30 2d 34 39 36 30 2d 61 66 37 65 2d 38 38 63 62 64 37 39 34 61 66 39 37) | (63 00 31 00 32 00 65 00 36 00 39 00 63 00 64 00 2d 00 37 00 38 00 61 00 30 00 2d 00 34 00 39 00 36 00 30 00 2d 00 61 00 66 00 37 00 65 00 2d 00 38 00 38 00 63 00 62 00 64 00 37 00 39 00 34 00 61 00 66 00 39 00 37 00))}
		$typelibguid0up = {((43 31 32 45 36 39 43 44 2d 37 38 41 30 2d 34 39 36 30 2d 41 46 37 45 2d 38 38 43 42 44 37 39 34 41 46 39 37) | (43 00 31 00 32 00 45 00 36 00 39 00 43 00 44 00 2d 00 37 00 38 00 41 00 30 00 2d 00 34 00 39 00 36 00 30 00 2d 00 41 00 46 00 37 00 45 00 2d 00 38 00 38 00 43 00 42 00 44 00 37 00 39 00 34 00 41 00 46 00 39 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Adamantium_Thief : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/LimerBoy/Adamantium-Thief"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "82225b2e-ab4a-50b8-a3fd-7ad4947d052e"

	strings:
		$typelibguid0lo = {((65 36 31 30 34 62 63 39 2d 66 65 61 39 2d 34 65 65 39 2d 62 39 31 39 2d 32 38 31 35 36 63 31 66 32 65 64 65) | (65 00 36 00 31 00 30 00 34 00 62 00 63 00 39 00 2d 00 66 00 65 00 61 00 39 00 2d 00 34 00 65 00 65 00 39 00 2d 00 62 00 39 00 31 00 39 00 2d 00 32 00 38 00 31 00 35 00 36 00 63 00 31 00 66 00 32 00 65 00 64 00 65 00))}
		$typelibguid0up = {((45 36 31 30 34 42 43 39 2d 46 45 41 39 2d 34 45 45 39 2d 42 39 31 39 2d 32 38 31 35 36 43 31 46 32 45 44 45) | (45 00 36 00 31 00 30 00 34 00 42 00 43 00 39 00 2d 00 46 00 45 00 41 00 39 00 2d 00 34 00 45 00 45 00 39 00 2d 00 42 00 39 00 31 00 39 00 2d 00 32 00 38 00 31 00 35 00 36 00 43 00 31 00 46 00 32 00 45 00 44 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_PSByPassCLM : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/padovah4ck/PSByPassCLM"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "dad6729f-3d96-5d2d-b72c-a96d1a3eae74"

	strings:
		$typelibguid0lo = {((34 36 30 33 34 30 33 38 2d 30 31 31 33 2d 34 64 37 35 2d 38 31 66 64 2d 65 62 33 62 34 38 33 66 32 36 36 32) | (34 00 36 00 30 00 33 00 34 00 30 00 33 00 38 00 2d 00 30 00 31 00 31 00 33 00 2d 00 34 00 64 00 37 00 35 00 2d 00 38 00 31 00 66 00 64 00 2d 00 65 00 62 00 33 00 62 00 34 00 38 00 33 00 66 00 32 00 36 00 36 00 32 00))}
		$typelibguid0up = {((34 36 30 33 34 30 33 38 2d 30 31 31 33 2d 34 44 37 35 2d 38 31 46 44 2d 45 42 33 42 34 38 33 46 32 36 36 32) | (34 00 36 00 30 00 33 00 34 00 30 00 33 00 38 00 2d 00 30 00 31 00 31 00 33 00 2d 00 34 00 44 00 37 00 35 00 2d 00 38 00 31 00 46 00 44 00 2d 00 45 00 42 00 33 00 42 00 34 00 38 00 33 00 46 00 32 00 36 00 36 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_physmem2profit : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FSecureLABS/physmem2profit"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "75a27970-c469-53da-b0c3-b3d0faea0b6f"

	strings:
		$typelibguid0lo = {((38 31 34 37 30 38 63 39 2d 32 33 32 30 2d 34 32 64 32 2d 61 34 35 66 2d 33 31 65 34 32 64 61 30 36 61 39 34) | (38 00 31 00 34 00 37 00 30 00 38 00 63 00 39 00 2d 00 32 00 33 00 32 00 30 00 2d 00 34 00 32 00 64 00 32 00 2d 00 61 00 34 00 35 00 66 00 2d 00 33 00 31 00 65 00 34 00 32 00 64 00 61 00 30 00 36 00 61 00 39 00 34 00))}
		$typelibguid0up = {((38 31 34 37 30 38 43 39 2d 32 33 32 30 2d 34 32 44 32 2d 41 34 35 46 2d 33 31 45 34 32 44 41 30 36 41 39 34) | (38 00 31 00 34 00 37 00 30 00 38 00 43 00 39 00 2d 00 32 00 33 00 32 00 30 00 2d 00 34 00 32 00 44 00 32 00 2d 00 41 00 34 00 35 00 46 00 2d 00 33 00 31 00 45 00 34 00 32 00 44 00 41 00 30 00 36 00 41 00 39 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_NoAmci : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/med0x2e/NoAmci"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "5fab1551-9d35-53cf-a04f-c14370119553"

	strings:
		$typelibguid0lo = {((33 35 32 65 38 30 65 63 2d 37 32 61 35 2d 34 61 61 36 2d 61 61 62 65 2d 34 66 39 61 32 30 33 39 33 65 38 65) | (33 00 35 00 32 00 65 00 38 00 30 00 65 00 63 00 2d 00 37 00 32 00 61 00 35 00 2d 00 34 00 61 00 61 00 36 00 2d 00 61 00 61 00 62 00 65 00 2d 00 34 00 66 00 39 00 61 00 32 00 30 00 33 00 39 00 33 00 65 00 38 00 65 00))}
		$typelibguid0up = {((33 35 32 45 38 30 45 43 2d 37 32 41 35 2d 34 41 41 36 2d 41 41 42 45 2d 34 46 39 41 32 30 33 39 33 45 38 45) | (33 00 35 00 32 00 45 00 38 00 30 00 45 00 43 00 2d 00 37 00 32 00 41 00 35 00 2d 00 34 00 41 00 41 00 36 00 2d 00 41 00 41 00 42 00 45 00 2d 00 34 00 46 00 39 00 41 00 32 00 30 00 33 00 39 00 33 00 45 00 38 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpBlock : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/CCob/SharpBlock"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "b84538da-1b0e-50c7-abfa-e93d6de5a49b"

	strings:
		$typelibguid0lo = {((33 63 66 32 35 65 30 34 2d 32 37 65 34 2d 34 64 31 39 2d 39 34 35 65 2d 64 61 64 63 33 37 63 38 31 31 35 32) | (33 00 63 00 66 00 32 00 35 00 65 00 30 00 34 00 2d 00 32 00 37 00 65 00 34 00 2d 00 34 00 64 00 31 00 39 00 2d 00 39 00 34 00 35 00 65 00 2d 00 64 00 61 00 64 00 63 00 33 00 37 00 63 00 38 00 31 00 31 00 35 00 32 00))}
		$typelibguid0up = {((33 43 46 32 35 45 30 34 2d 32 37 45 34 2d 34 44 31 39 2d 39 34 35 45 2d 44 41 44 43 33 37 43 38 31 31 35 32) | (33 00 43 00 46 00 32 00 35 00 45 00 30 00 34 00 2d 00 32 00 37 00 45 00 34 00 2d 00 34 00 44 00 31 00 39 00 2d 00 39 00 34 00 35 00 45 00 2d 00 44 00 41 00 44 00 43 00 33 00 37 00 43 00 38 00 31 00 31 00 35 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_nopowershell : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/bitsadmin/nopowershell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "0fd7496b-e34f-51f7-9270-ad424ed6a7a8"

	strings:
		$typelibguid0lo = {((35 35 35 61 64 30 61 63 2d 31 66 64 62 2d 34 30 31 36 2d 38 32 35 37 2d 31 37 30 61 37 34 63 62 32 66 35 35) | (35 00 35 00 35 00 61 00 64 00 30 00 61 00 63 00 2d 00 31 00 66 00 64 00 62 00 2d 00 34 00 30 00 31 00 36 00 2d 00 38 00 32 00 35 00 37 00 2d 00 31 00 37 00 30 00 61 00 37 00 34 00 63 00 62 00 32 00 66 00 35 00 35 00))}
		$typelibguid0up = {((35 35 35 41 44 30 41 43 2d 31 46 44 42 2d 34 30 31 36 2d 38 32 35 37 2d 31 37 30 41 37 34 43 42 32 46 35 35) | (35 00 35 00 35 00 41 00 44 00 30 00 41 00 43 00 2d 00 31 00 46 00 44 00 42 00 2d 00 34 00 30 00 31 00 36 00 2d 00 38 00 32 00 35 00 37 00 2d 00 31 00 37 00 30 00 41 00 37 00 34 00 43 00 42 00 32 00 46 00 35 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_LimeLogger : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/LimeLogger"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "0798f01b-76b7-5c4d-9ddb-5e377b86f8b9"

	strings:
		$typelibguid0lo = {((30 36 38 64 31 34 65 66 2d 66 30 61 31 2d 34 66 39 64 2d 38 65 32 37 2d 35 38 62 34 33 31 37 38 33 30 63 36) | (30 00 36 00 38 00 64 00 31 00 34 00 65 00 66 00 2d 00 66 00 30 00 61 00 31 00 2d 00 34 00 66 00 39 00 64 00 2d 00 38 00 65 00 32 00 37 00 2d 00 35 00 38 00 62 00 34 00 33 00 31 00 37 00 38 00 33 00 30 00 63 00 36 00))}
		$typelibguid0up = {((30 36 38 44 31 34 45 46 2d 46 30 41 31 2d 34 46 39 44 2d 38 45 32 37 2d 35 38 42 34 33 31 37 38 33 30 43 36) | (30 00 36 00 38 00 44 00 31 00 34 00 45 00 46 00 2d 00 46 00 30 00 41 00 31 00 2d 00 34 00 46 00 39 00 44 00 2d 00 38 00 45 00 32 00 37 00 2d 00 35 00 38 00 42 00 34 00 33 00 31 00 37 00 38 00 33 00 30 00 43 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_AggressorScripts : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/harleyQu1nn/AggressorScripts"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "d5903db5-010b-5b9d-8a5b-5d61aec52e7a"

	strings:
		$typelibguid0lo = {((61 66 64 31 66 66 30 39 2d 32 36 33 32 2d 34 30 38 37 2d 61 33 30 63 2d 34 33 35 39 31 66 33 32 65 34 65 38) | (61 00 66 00 64 00 31 00 66 00 66 00 30 00 39 00 2d 00 32 00 36 00 33 00 32 00 2d 00 34 00 30 00 38 00 37 00 2d 00 61 00 33 00 30 00 63 00 2d 00 34 00 33 00 35 00 39 00 31 00 66 00 33 00 32 00 65 00 34 00 65 00 38 00))}
		$typelibguid0up = {((41 46 44 31 46 46 30 39 2d 32 36 33 32 2d 34 30 38 37 2d 41 33 30 43 2d 34 33 35 39 31 46 33 32 45 34 45 38) | (41 00 46 00 44 00 31 00 46 00 46 00 30 00 39 00 2d 00 32 00 36 00 33 00 32 00 2d 00 34 00 30 00 38 00 37 00 2d 00 41 00 33 00 30 00 43 00 2d 00 34 00 33 00 35 00 39 00 31 00 46 00 33 00 32 00 45 00 34 00 45 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Gopher : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/EncodeGroup/Gopher"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "e3015719-9085-584d-8237-f377ec995149"

	strings:
		$typelibguid0lo = {((62 35 31 35 32 36 38 33 2d 32 35 31 34 2d 34 39 63 65 2d 39 61 63 61 2d 31 62 63 34 33 64 66 31 65 32 33 34) | (62 00 35 00 31 00 35 00 32 00 36 00 38 00 33 00 2d 00 32 00 35 00 31 00 34 00 2d 00 34 00 39 00 63 00 65 00 2d 00 39 00 61 00 63 00 61 00 2d 00 31 00 62 00 63 00 34 00 33 00 64 00 66 00 31 00 65 00 32 00 33 00 34 00))}
		$typelibguid0up = {((42 35 31 35 32 36 38 33 2d 32 35 31 34 2d 34 39 43 45 2d 39 41 43 41 2d 31 42 43 34 33 44 46 31 45 32 33 34) | (42 00 35 00 31 00 35 00 32 00 36 00 38 00 33 00 2d 00 32 00 35 00 31 00 34 00 2d 00 34 00 39 00 43 00 45 00 2d 00 39 00 41 00 43 00 41 00 2d 00 31 00 42 00 43 00 34 00 33 00 44 00 46 00 31 00 45 00 32 00 33 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_AVIator : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Ch0pin/AVIator"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "52acd520-52aa-5bb9-ab3b-66a940aa5f5a"

	strings:
		$typelibguid0lo = {((34 38 38 35 61 34 61 33 2d 34 64 66 61 2d 34 38 36 63 2d 62 33 37 38 2d 61 65 39 34 61 32 32 31 36 36 31 61) | (34 00 38 00 38 00 35 00 61 00 34 00 61 00 33 00 2d 00 34 00 64 00 66 00 61 00 2d 00 34 00 38 00 36 00 63 00 2d 00 62 00 33 00 37 00 38 00 2d 00 61 00 65 00 39 00 34 00 61 00 32 00 32 00 31 00 36 00 36 00 31 00 61 00))}
		$typelibguid0up = {((34 38 38 35 41 34 41 33 2d 34 44 46 41 2d 34 38 36 43 2d 42 33 37 38 2d 41 45 39 34 41 32 32 31 36 36 31 41) | (34 00 38 00 38 00 35 00 41 00 34 00 41 00 33 00 2d 00 34 00 44 00 46 00 41 00 2d 00 34 00 38 00 36 00 43 00 2d 00 42 00 33 00 37 00 38 00 2d 00 41 00 45 00 39 00 34 00 41 00 32 00 32 00 31 00 36 00 36 00 31 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_njCrypter : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xPh0enix/njCrypter"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "c30c8323-9418-521a-a4fc-6be0113b99b5"

	strings:
		$typelibguid0lo = {((38 61 38 37 62 30 30 33 2d 34 62 34 33 2d 34 36 37 62 2d 61 35 30 39 2d 30 63 38 62 65 30 35 62 66 35 61 35) | (38 00 61 00 38 00 37 00 62 00 30 00 30 00 33 00 2d 00 34 00 62 00 34 00 33 00 2d 00 34 00 36 00 37 00 62 00 2d 00 61 00 35 00 30 00 39 00 2d 00 30 00 63 00 38 00 62 00 65 00 30 00 35 00 62 00 66 00 35 00 61 00 35 00))}
		$typelibguid0up = {((38 41 38 37 42 30 30 33 2d 34 42 34 33 2d 34 36 37 42 2d 41 35 30 39 2d 30 43 38 42 45 30 35 42 46 35 41 35) | (38 00 41 00 38 00 37 00 42 00 30 00 30 00 33 00 2d 00 34 00 42 00 34 00 33 00 2d 00 34 00 36 00 37 00 42 00 2d 00 41 00 35 00 30 00 39 00 2d 00 30 00 43 00 38 00 42 00 45 00 30 00 35 00 42 00 46 00 35 00 41 00 35 00))}
		$typelibguid1lo = {((38 30 62 31 33 62 66 66 2d 32 34 61 35 2d 34 31 39 33 2d 38 65 35 31 2d 63 36 32 61 34 31 34 30 36 30 65 63) | (38 00 30 00 62 00 31 00 33 00 62 00 66 00 66 00 2d 00 32 00 34 00 61 00 35 00 2d 00 34 00 31 00 39 00 33 00 2d 00 38 00 65 00 35 00 31 00 2d 00 63 00 36 00 32 00 61 00 34 00 31 00 34 00 30 00 36 00 30 00 65 00 63 00))}
		$typelibguid1up = {((38 30 42 31 33 42 46 46 2d 32 34 41 35 2d 34 31 39 33 2d 38 45 35 31 2d 43 36 32 41 34 31 34 30 36 30 45 43) | (38 00 30 00 42 00 31 00 33 00 42 00 46 00 46 00 2d 00 32 00 34 00 41 00 35 00 2d 00 34 00 31 00 39 00 33 00 2d 00 38 00 45 00 35 00 31 00 2d 00 43 00 36 00 32 00 41 00 34 00 31 00 34 00 30 00 36 00 30 00 45 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpMiniDump : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/b4rtik/SharpMiniDump"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "e91e6711-d992-5a8a-97e6-1ed7847f38a4"

	strings:
		$typelibguid0lo = {((36 66 66 63 63 66 38 31 2d 36 63 33 63 2d 34 64 33 66 2d 62 31 35 66 2d 33 35 61 38 36 64 30 62 34 39 37 66) | (36 00 66 00 66 00 63 00 63 00 66 00 38 00 31 00 2d 00 36 00 63 00 33 00 63 00 2d 00 34 00 64 00 33 00 66 00 2d 00 62 00 31 00 35 00 66 00 2d 00 33 00 35 00 61 00 38 00 36 00 64 00 30 00 62 00 34 00 39 00 37 00 66 00))}
		$typelibguid0up = {((36 46 46 43 43 46 38 31 2d 36 43 33 43 2d 34 44 33 46 2d 42 31 35 46 2d 33 35 41 38 36 44 30 42 34 39 37 46) | (36 00 46 00 46 00 43 00 43 00 46 00 38 00 31 00 2d 00 36 00 43 00 33 00 43 00 2d 00 34 00 44 00 33 00 46 00 2d 00 42 00 31 00 35 00 46 00 2d 00 33 00 35 00 41 00 38 00 36 00 44 00 30 00 42 00 34 00 39 00 37 00 46 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_CinaRAT : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/wearelegal/CinaRAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "c6b4c919-0fc6-5096-b29b-963142a2c831"

	strings:
		$typelibguid0lo = {((38 35 38 36 66 35 62 31 2d 32 65 66 34 2d 34 66 33 35 2d 62 64 34 35 2d 63 36 32 30 36 66 64 63 30 65 62 63) | (38 00 35 00 38 00 36 00 66 00 35 00 62 00 31 00 2d 00 32 00 65 00 66 00 34 00 2d 00 34 00 66 00 33 00 35 00 2d 00 62 00 64 00 34 00 35 00 2d 00 63 00 36 00 32 00 30 00 36 00 66 00 64 00 63 00 30 00 65 00 62 00 63 00))}
		$typelibguid0up = {((38 35 38 36 46 35 42 31 2d 32 45 46 34 2d 34 46 33 35 2d 42 44 34 35 2d 43 36 32 30 36 46 44 43 30 45 42 43) | (38 00 35 00 38 00 36 00 46 00 35 00 42 00 31 00 2d 00 32 00 45 00 46 00 34 00 2d 00 34 00 46 00 33 00 35 00 2d 00 42 00 44 00 34 00 35 00 2d 00 43 00 36 00 32 00 30 00 36 00 46 00 44 00 43 00 30 00 45 00 42 00 43 00))}
		$typelibguid1lo = {((66 65 31 38 34 61 62 35 2d 66 31 35 33 2d 34 31 37 39 2d 39 62 66 35 2d 35 30 35 32 33 39 38 37 63 66 31 66) | (66 00 65 00 31 00 38 00 34 00 61 00 62 00 35 00 2d 00 66 00 31 00 35 00 33 00 2d 00 34 00 31 00 37 00 39 00 2d 00 39 00 62 00 66 00 35 00 2d 00 35 00 30 00 35 00 32 00 33 00 39 00 38 00 37 00 63 00 66 00 31 00 66 00))}
		$typelibguid1up = {((46 45 31 38 34 41 42 35 2d 46 31 35 33 2d 34 31 37 39 2d 39 42 46 35 2d 35 30 35 32 33 39 38 37 43 46 31 46) | (46 00 45 00 31 00 38 00 34 00 41 00 42 00 35 00 2d 00 46 00 31 00 35 00 33 00 2d 00 34 00 31 00 37 00 39 00 2d 00 39 00 42 00 46 00 35 00 2d 00 35 00 30 00 35 00 32 00 33 00 39 00 38 00 37 00 43 00 46 00 31 00 46 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_ToxicEye : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/LimerBoy/ToxicEye"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "0b7b62ce-9c24-5d81-8d87-22f6e461a62b"

	strings:
		$typelibguid0lo = {((31 62 63 66 65 35 33 38 2d 31 34 66 34 2d 34 62 65 62 2d 39 61 33 66 2d 33 66 39 34 37 32 37 39 34 39 30 32) | (31 00 62 00 63 00 66 00 65 00 35 00 33 00 38 00 2d 00 31 00 34 00 66 00 34 00 2d 00 34 00 62 00 65 00 62 00 2d 00 39 00 61 00 33 00 66 00 2d 00 33 00 66 00 39 00 34 00 37 00 32 00 37 00 39 00 34 00 39 00 30 00 32 00))}
		$typelibguid0up = {((31 42 43 46 45 35 33 38 2d 31 34 46 34 2d 34 42 45 42 2d 39 41 33 46 2d 33 46 39 34 37 32 37 39 34 39 30 32) | (31 00 42 00 43 00 46 00 45 00 35 00 33 00 38 00 2d 00 31 00 34 00 46 00 34 00 2d 00 34 00 42 00 45 00 42 00 2d 00 39 00 41 00 33 00 46 00 2d 00 33 00 46 00 39 00 34 00 37 00 32 00 37 00 39 00 34 00 39 00 30 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Disable_Windows_Defender : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Disable-Windows-Defender"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "9a673427-e66e-594b-942a-64a2272319f3"

	strings:
		$typelibguid0lo = {((35 30 31 65 33 66 64 63 2d 35 37 35 64 2d 34 39 32 65 2d 39 30 62 63 2d 37 30 33 66 62 36 32 38 30 65 65 32) | (35 00 30 00 31 00 65 00 33 00 66 00 64 00 63 00 2d 00 35 00 37 00 35 00 64 00 2d 00 34 00 39 00 32 00 65 00 2d 00 39 00 30 00 62 00 63 00 2d 00 37 00 30 00 33 00 66 00 62 00 36 00 32 00 38 00 30 00 65 00 65 00 32 00))}
		$typelibguid0up = {((35 30 31 45 33 46 44 43 2d 35 37 35 44 2d 34 39 32 45 2d 39 30 42 43 2d 37 30 33 46 42 36 32 38 30 45 45 32) | (35 00 30 00 31 00 45 00 33 00 46 00 44 00 43 00 2d 00 35 00 37 00 35 00 44 00 2d 00 34 00 39 00 32 00 45 00 2d 00 39 00 30 00 42 00 43 00 2d 00 37 00 30 00 33 00 46 00 42 00 36 00 32 00 38 00 30 00 45 00 45 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_DInvoke_PoC : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/dtrizna/DInvoke_PoC"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "f3b0ef47-a92c-5c5d-a9e2-09579fcb438e"

	strings:
		$typelibguid0lo = {((35 61 38 36 39 61 62 32 2d 32 39 31 61 2d 34 39 65 36 2d 61 31 62 37 2d 30 64 30 66 30 35 31 62 65 66 30 65) | (35 00 61 00 38 00 36 00 39 00 61 00 62 00 32 00 2d 00 32 00 39 00 31 00 61 00 2d 00 34 00 39 00 65 00 36 00 2d 00 61 00 31 00 62 00 37 00 2d 00 30 00 64 00 30 00 66 00 30 00 35 00 31 00 62 00 65 00 66 00 30 00 65 00))}
		$typelibguid0up = {((35 41 38 36 39 41 42 32 2d 32 39 31 41 2d 34 39 45 36 2d 41 31 42 37 2d 30 44 30 46 30 35 31 42 45 46 30 45) | (35 00 41 00 38 00 36 00 39 00 41 00 42 00 32 00 2d 00 32 00 39 00 31 00 41 00 2d 00 34 00 39 00 45 00 36 00 2d 00 41 00 31 00 42 00 37 00 2d 00 30 00 44 00 30 00 46 00 30 00 35 00 31 00 42 00 45 00 46 00 30 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_ReverseShell : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/chango77747/ReverseShell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "876932d5-a65d-5230-9cb8-24038ad8af0d"

	strings:
		$typelibguid0lo = {((39 38 30 31 30 39 65 34 2d 63 39 38 38 2d 34 37 66 39 2d 62 32 62 33 2d 38 38 64 36 33 66 61 62 61 62 64 63) | (39 00 38 00 30 00 31 00 30 00 39 00 65 00 34 00 2d 00 63 00 39 00 38 00 38 00 2d 00 34 00 37 00 66 00 39 00 2d 00 62 00 32 00 62 00 33 00 2d 00 38 00 38 00 64 00 36 00 33 00 66 00 61 00 62 00 61 00 62 00 64 00 63 00))}
		$typelibguid0up = {((39 38 30 31 30 39 45 34 2d 43 39 38 38 2d 34 37 46 39 2d 42 32 42 33 2d 38 38 44 36 33 46 41 42 41 42 44 43) | (39 00 38 00 30 00 31 00 30 00 39 00 45 00 34 00 2d 00 43 00 39 00 38 00 38 00 2d 00 34 00 37 00 46 00 39 00 2d 00 42 00 32 00 42 00 33 00 2d 00 38 00 38 00 44 00 36 00 33 00 46 00 41 00 42 00 41 00 42 00 44 00 43 00))}
		$typelibguid1lo = {((38 61 62 65 38 64 61 31 2d 34 35 37 65 2d 34 39 33 33 2d 61 34 30 64 2d 30 39 35 38 63 38 39 32 35 39 38 35) | (38 00 61 00 62 00 65 00 38 00 64 00 61 00 31 00 2d 00 34 00 35 00 37 00 65 00 2d 00 34 00 39 00 33 00 33 00 2d 00 61 00 34 00 30 00 64 00 2d 00 30 00 39 00 35 00 38 00 63 00 38 00 39 00 32 00 35 00 39 00 38 00 35 00))}
		$typelibguid1up = {((38 41 42 45 38 44 41 31 2d 34 35 37 45 2d 34 39 33 33 2d 41 34 30 44 2d 30 39 35 38 43 38 39 32 35 39 38 35) | (38 00 41 00 42 00 45 00 38 00 44 00 41 00 31 00 2d 00 34 00 35 00 37 00 45 00 2d 00 34 00 39 00 33 00 33 00 2d 00 41 00 34 00 30 00 44 00 2d 00 30 00 39 00 35 00 38 00 43 00 38 00 39 00 32 00 35 00 39 00 38 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpC2 : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/SharpC2/SharpC2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "2ed6d74e-2b95-5c70-807a-4da5e62f5853"

	strings:
		$typelibguid0lo = {((36 32 62 39 65 65 34 66 2d 31 34 33 36 2d 34 30 39 38 2d 39 62 63 31 2d 64 64 36 31 62 34 32 64 38 62 38 31) | (36 00 32 00 62 00 39 00 65 00 65 00 34 00 66 00 2d 00 31 00 34 00 33 00 36 00 2d 00 34 00 30 00 39 00 38 00 2d 00 39 00 62 00 63 00 31 00 2d 00 64 00 64 00 36 00 31 00 62 00 34 00 32 00 64 00 38 00 62 00 38 00 31 00))}
		$typelibguid0up = {((36 32 42 39 45 45 34 46 2d 31 34 33 36 2d 34 30 39 38 2d 39 42 43 31 2d 44 44 36 31 42 34 32 44 38 42 38 31) | (36 00 32 00 42 00 39 00 45 00 45 00 34 00 46 00 2d 00 31 00 34 00 33 00 36 00 2d 00 34 00 30 00 39 00 38 00 2d 00 39 00 42 00 43 00 31 00 2d 00 44 00 44 00 36 00 31 00 42 00 34 00 32 00 44 00 38 00 42 00 38 00 31 00))}
		$typelibguid1lo = {((64 32 66 31 37 61 39 31 2d 65 62 32 64 2d 34 33 37 33 2d 39 30 62 66 2d 61 32 36 65 34 36 63 36 38 66 37 36) | (64 00 32 00 66 00 31 00 37 00 61 00 39 00 31 00 2d 00 65 00 62 00 32 00 64 00 2d 00 34 00 33 00 37 00 33 00 2d 00 39 00 30 00 62 00 66 00 2d 00 61 00 32 00 36 00 65 00 34 00 36 00 63 00 36 00 38 00 66 00 37 00 36 00))}
		$typelibguid1up = {((44 32 46 31 37 41 39 31 2d 45 42 32 44 2d 34 33 37 33 2d 39 30 42 46 2d 41 32 36 45 34 36 43 36 38 46 37 36) | (44 00 32 00 46 00 31 00 37 00 41 00 39 00 31 00 2d 00 45 00 42 00 32 00 44 00 2d 00 34 00 33 00 37 00 33 00 2d 00 39 00 30 00 42 00 46 00 2d 00 41 00 32 00 36 00 45 00 34 00 36 00 43 00 36 00 38 00 46 00 37 00 36 00))}
		$typelibguid2lo = {((61 39 64 62 39 66 63 63 2d 37 35 30 32 2d 34 32 63 64 2d 38 31 65 63 2d 33 63 64 36 36 66 35 31 31 33 34 36) | (61 00 39 00 64 00 62 00 39 00 66 00 63 00 63 00 2d 00 37 00 35 00 30 00 32 00 2d 00 34 00 32 00 63 00 64 00 2d 00 38 00 31 00 65 00 63 00 2d 00 33 00 63 00 64 00 36 00 36 00 66 00 35 00 31 00 31 00 33 00 34 00 36 00))}
		$typelibguid2up = {((41 39 44 42 39 46 43 43 2d 37 35 30 32 2d 34 32 43 44 2d 38 31 45 43 2d 33 43 44 36 36 46 35 31 31 33 34 36) | (41 00 39 00 44 00 42 00 39 00 46 00 43 00 43 00 2d 00 37 00 35 00 30 00 32 00 2d 00 34 00 32 00 43 00 44 00 2d 00 38 00 31 00 45 00 43 00 2d 00 33 00 43 00 44 00 36 00 36 00 46 00 35 00 31 00 31 00 33 00 34 00 36 00))}
		$typelibguid3lo = {((63 61 36 63 63 32 65 65 2d 37 35 66 64 2d 34 66 30 30 2d 62 36 38 37 2d 39 31 37 66 61 35 35 61 34 66 61 65) | (63 00 61 00 36 00 63 00 63 00 32 00 65 00 65 00 2d 00 37 00 35 00 66 00 64 00 2d 00 34 00 66 00 30 00 30 00 2d 00 62 00 36 00 38 00 37 00 2d 00 39 00 31 00 37 00 66 00 61 00 35 00 35 00 61 00 34 00 66 00 61 00 65 00))}
		$typelibguid3up = {((43 41 36 43 43 32 45 45 2d 37 35 46 44 2d 34 46 30 30 2d 42 36 38 37 2d 39 31 37 46 41 35 35 41 34 46 41 45) | (43 00 41 00 36 00 43 00 43 00 32 00 45 00 45 00 2d 00 37 00 35 00 46 00 44 00 2d 00 34 00 46 00 30 00 30 00 2d 00 42 00 36 00 38 00 37 00 2d 00 39 00 31 00 37 00 46 00 41 00 35 00 35 00 41 00 34 00 46 00 41 00 45 00))}
		$typelibguid4lo = {((61 31 31 36 37 62 36 38 2d 34 34 36 62 2d 34 63 30 63 2d 61 38 62 38 2d 32 61 37 32 37 38 62 36 37 35 31 31) | (61 00 31 00 31 00 36 00 37 00 62 00 36 00 38 00 2d 00 34 00 34 00 36 00 62 00 2d 00 34 00 63 00 30 00 63 00 2d 00 61 00 38 00 62 00 38 00 2d 00 32 00 61 00 37 00 32 00 37 00 38 00 62 00 36 00 37 00 35 00 31 00 31 00))}
		$typelibguid4up = {((41 31 31 36 37 42 36 38 2d 34 34 36 42 2d 34 43 30 43 2d 41 38 42 38 2d 32 41 37 32 37 38 42 36 37 35 31 31) | (41 00 31 00 31 00 36 00 37 00 42 00 36 00 38 00 2d 00 34 00 34 00 36 00 42 00 2d 00 34 00 43 00 30 00 43 00 2d 00 41 00 38 00 42 00 38 00 2d 00 32 00 41 00 37 00 32 00 37 00 38 00 42 00 36 00 37 00 35 00 31 00 31 00))}
		$typelibguid5lo = {((34 64 38 63 32 61 38 38 2d 31 64 61 35 2d 34 61 62 65 2d 38 39 39 35 2d 36 36 30 36 34 37 33 64 37 63 66 31) | (34 00 64 00 38 00 63 00 32 00 61 00 38 00 38 00 2d 00 31 00 64 00 61 00 35 00 2d 00 34 00 61 00 62 00 65 00 2d 00 38 00 39 00 39 00 35 00 2d 00 36 00 36 00 30 00 36 00 34 00 37 00 33 00 64 00 37 00 63 00 66 00 31 00))}
		$typelibguid5up = {((34 44 38 43 32 41 38 38 2d 31 44 41 35 2d 34 41 42 45 2d 38 39 39 35 2d 36 36 30 36 34 37 33 44 37 43 46 31) | (34 00 44 00 38 00 43 00 32 00 41 00 38 00 38 00 2d 00 31 00 44 00 41 00 35 00 2d 00 34 00 41 00 42 00 45 00 2d 00 38 00 39 00 39 00 35 00 2d 00 36 00 36 00 30 00 36 00 34 00 37 00 33 00 44 00 37 00 43 00 46 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SneakyExec : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/HackingThings/SneakyExec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "853b630d-77ba-5847-a129-c9fa0538f81b"

	strings:
		$typelibguid0lo = {((36 31 32 35 39 30 61 61 2d 61 66 36 38 2d 34 31 65 36 2d 38 63 65 32 2d 65 38 33 31 66 37 66 65 34 63 63 63) | (36 00 31 00 32 00 35 00 39 00 30 00 61 00 61 00 2d 00 61 00 66 00 36 00 38 00 2d 00 34 00 31 00 65 00 36 00 2d 00 38 00 63 00 65 00 32 00 2d 00 65 00 38 00 33 00 31 00 66 00 37 00 66 00 65 00 34 00 63 00 63 00 63 00))}
		$typelibguid0up = {((36 31 32 35 39 30 41 41 2d 41 46 36 38 2d 34 31 45 36 2d 38 43 45 32 2d 45 38 33 31 46 37 46 45 34 43 43 43) | (36 00 31 00 32 00 35 00 39 00 30 00 41 00 41 00 2d 00 41 00 46 00 36 00 38 00 2d 00 34 00 31 00 45 00 36 00 2d 00 38 00 43 00 45 00 32 00 2d 00 45 00 38 00 33 00 31 00 46 00 37 00 46 00 45 00 34 00 43 00 43 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_UrbanBishopLocal : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/slyd0g/UrbanBishopLocal"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "53b690ec-7d20-5e46-b368-b458ce56073d"

	strings:
		$typelibguid0lo = {((38 38 62 38 35 31 35 65 2d 61 30 65 38 2d 34 32 30 38 2d 61 39 61 30 2d 33 34 62 30 31 64 37 62 61 35 33 33) | (38 00 38 00 62 00 38 00 35 00 31 00 35 00 65 00 2d 00 61 00 30 00 65 00 38 00 2d 00 34 00 32 00 30 00 38 00 2d 00 61 00 39 00 61 00 30 00 2d 00 33 00 34 00 62 00 30 00 31 00 64 00 37 00 62 00 61 00 35 00 33 00 33 00))}
		$typelibguid0up = {((38 38 42 38 35 31 35 45 2d 41 30 45 38 2d 34 32 30 38 2d 41 39 41 30 2d 33 34 42 30 31 44 37 42 41 35 33 33) | (38 00 38 00 42 00 38 00 35 00 31 00 35 00 45 00 2d 00 41 00 30 00 45 00 38 00 2d 00 34 00 32 00 30 00 38 00 2d 00 41 00 39 00 41 00 30 00 2d 00 33 00 34 00 42 00 30 00 31 00 44 00 37 00 42 00 41 00 35 00 33 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpShell : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/cobbr/SharpShell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "5966be44-c010-5c63-9576-1aaf36397d6c"

	strings:
		$typelibguid0lo = {((62 64 62 61 34 37 63 35 2d 65 38 32 33 2d 34 34 30 34 2d 39 31 64 30 2d 37 66 36 35 36 31 32 37 39 35 32 35) | (62 00 64 00 62 00 61 00 34 00 37 00 63 00 35 00 2d 00 65 00 38 00 32 00 33 00 2d 00 34 00 34 00 30 00 34 00 2d 00 39 00 31 00 64 00 30 00 2d 00 37 00 66 00 36 00 35 00 36 00 31 00 32 00 37 00 39 00 35 00 32 00 35 00))}
		$typelibguid0up = {((42 44 42 41 34 37 43 35 2d 45 38 32 33 2d 34 34 30 34 2d 39 31 44 30 2d 37 46 36 35 36 31 32 37 39 35 32 35) | (42 00 44 00 42 00 41 00 34 00 37 00 43 00 35 00 2d 00 45 00 38 00 32 00 33 00 2d 00 34 00 34 00 30 00 34 00 2d 00 39 00 31 00 44 00 30 00 2d 00 37 00 46 00 36 00 35 00 36 00 31 00 32 00 37 00 39 00 35 00 32 00 35 00))}
		$typelibguid1lo = {((62 38 34 35 34 38 64 63 2d 64 39 32 36 2d 34 62 33 39 2d 38 32 39 33 2d 66 61 30 62 64 65 66 33 34 64 34 39) | (62 00 38 00 34 00 35 00 34 00 38 00 64 00 63 00 2d 00 64 00 39 00 32 00 36 00 2d 00 34 00 62 00 33 00 39 00 2d 00 38 00 32 00 39 00 33 00 2d 00 66 00 61 00 30 00 62 00 64 00 65 00 66 00 33 00 34 00 64 00 34 00 39 00))}
		$typelibguid1up = {((42 38 34 35 34 38 44 43 2d 44 39 32 36 2d 34 42 33 39 2d 38 32 39 33 2d 46 41 30 42 44 45 46 33 34 44 34 39) | (42 00 38 00 34 00 35 00 34 00 38 00 44 00 43 00 2d 00 44 00 39 00 32 00 36 00 2d 00 34 00 42 00 33 00 39 00 2d 00 38 00 32 00 39 00 33 00 2d 00 46 00 41 00 30 00 42 00 44 00 45 00 46 00 33 00 34 00 44 00 34 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_EvilWMIProvider : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/sunnyc7/EvilWMIProvider"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "3a6cf00e-28c4-5e6f-a28d-b3f28fca6eed"

	strings:
		$typelibguid0lo = {((61 34 30 32 30 36 32 36 2d 66 31 65 63 2d 34 30 31 32 2d 38 62 31 37 2d 61 32 63 38 61 30 32 30 34 61 34 62) | (61 00 34 00 30 00 32 00 30 00 36 00 32 00 36 00 2d 00 66 00 31 00 65 00 63 00 2d 00 34 00 30 00 31 00 32 00 2d 00 38 00 62 00 31 00 37 00 2d 00 61 00 32 00 63 00 38 00 61 00 30 00 32 00 30 00 34 00 61 00 34 00 62 00))}
		$typelibguid0up = {((41 34 30 32 30 36 32 36 2d 46 31 45 43 2d 34 30 31 32 2d 38 42 31 37 2d 41 32 43 38 41 30 32 30 34 41 34 42) | (41 00 34 00 30 00 32 00 30 00 36 00 32 00 36 00 2d 00 46 00 31 00 45 00 43 00 2d 00 34 00 30 00 31 00 32 00 2d 00 38 00 42 00 31 00 37 00 2d 00 41 00 32 00 43 00 38 00 41 00 30 00 32 00 30 00 34 00 41 00 34 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_GadgetToJScript : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/med0x2e/GadgetToJScript"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "e296795f-d006-52a9-92c4-fb60c930564b"

	strings:
		$typelibguid0lo = {((61 66 39 63 36 32 61 31 2d 66 38 64 32 2d 34 62 65 30 2d 62 30 31 39 2d 30 61 37 38 37 33 65 38 31 65 61 39) | (61 00 66 00 39 00 63 00 36 00 32 00 61 00 31 00 2d 00 66 00 38 00 64 00 32 00 2d 00 34 00 62 00 65 00 30 00 2d 00 62 00 30 00 31 00 39 00 2d 00 30 00 61 00 37 00 38 00 37 00 33 00 65 00 38 00 31 00 65 00 61 00 39 00))}
		$typelibguid0up = {((41 46 39 43 36 32 41 31 2d 46 38 44 32 2d 34 42 45 30 2d 42 30 31 39 2d 30 41 37 38 37 33 45 38 31 45 41 39) | (41 00 46 00 39 00 43 00 36 00 32 00 41 00 31 00 2d 00 46 00 38 00 44 00 32 00 2d 00 34 00 42 00 45 00 30 00 2d 00 42 00 30 00 31 00 39 00 2d 00 30 00 41 00 37 00 38 00 37 00 33 00 45 00 38 00 31 00 45 00 41 00 39 00))}
		$typelibguid1lo = {((62 32 62 33 61 64 62 30 2d 31 36 36 39 2d 34 62 39 34 2d 38 36 63 62 2d 36 64 64 36 38 32 64 64 62 65 61 33) | (62 00 32 00 62 00 33 00 61 00 64 00 62 00 30 00 2d 00 31 00 36 00 36 00 39 00 2d 00 34 00 62 00 39 00 34 00 2d 00 38 00 36 00 63 00 62 00 2d 00 36 00 64 00 64 00 36 00 38 00 32 00 64 00 64 00 62 00 65 00 61 00 33 00))}
		$typelibguid1up = {((42 32 42 33 41 44 42 30 2d 31 36 36 39 2d 34 42 39 34 2d 38 36 43 42 2d 36 44 44 36 38 32 44 44 42 45 41 33) | (42 00 32 00 42 00 33 00 41 00 44 00 42 00 30 00 2d 00 31 00 36 00 36 00 39 00 2d 00 34 00 42 00 39 00 34 00 2d 00 38 00 36 00 43 00 42 00 2d 00 36 00 44 00 44 00 36 00 38 00 32 00 44 00 44 00 42 00 45 00 41 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_AzureCLI_Extractor : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0x09AL/AzureCLI-Extractor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "f595545a-a7a6-577c-b3f4-febf7bf1b6c3"

	strings:
		$typelibguid0lo = {((61 37 33 63 61 64 37 34 2d 66 38 64 36 2d 34 33 65 36 2d 39 61 34 63 2d 62 38 37 38 33 32 63 64 65 61 63 65) | (61 00 37 00 33 00 63 00 61 00 64 00 37 00 34 00 2d 00 66 00 38 00 64 00 36 00 2d 00 34 00 33 00 65 00 36 00 2d 00 39 00 61 00 34 00 63 00 2d 00 62 00 38 00 37 00 38 00 33 00 32 00 63 00 64 00 65 00 61 00 63 00 65 00))}
		$typelibguid0up = {((41 37 33 43 41 44 37 34 2d 46 38 44 36 2d 34 33 45 36 2d 39 41 34 43 2d 42 38 37 38 33 32 43 44 45 41 43 45) | (41 00 37 00 33 00 43 00 41 00 44 00 37 00 34 00 2d 00 46 00 38 00 44 00 36 00 2d 00 34 00 33 00 45 00 36 00 2d 00 39 00 41 00 34 00 43 00 2d 00 42 00 38 00 37 00 38 00 33 00 32 00 43 00 44 00 45 00 41 00 43 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_UAC_Escaper : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/UAC-Escaper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "ea95ff3c-0cbb-5230-b5e4-bd8b2ff975eb"

	strings:
		$typelibguid0lo = {((39 35 33 35 39 32 37 39 2d 35 63 66 61 2d 34 36 66 36 2d 62 34 30 30 2d 65 38 30 35 34 32 61 37 33 33 36 61) | (39 00 35 00 33 00 35 00 39 00 32 00 37 00 39 00 2d 00 35 00 63 00 66 00 61 00 2d 00 34 00 36 00 66 00 36 00 2d 00 62 00 34 00 30 00 30 00 2d 00 65 00 38 00 30 00 35 00 34 00 32 00 61 00 37 00 33 00 33 00 36 00 61 00))}
		$typelibguid0up = {((39 35 33 35 39 32 37 39 2d 35 43 46 41 2d 34 36 46 36 2d 42 34 30 30 2d 45 38 30 35 34 32 41 37 33 33 36 41) | (39 00 35 00 33 00 35 00 39 00 32 00 37 00 39 00 2d 00 35 00 43 00 46 00 41 00 2d 00 34 00 36 00 46 00 36 00 2d 00 42 00 34 00 30 00 30 00 2d 00 45 00 38 00 30 00 35 00 34 00 32 00 41 00 37 00 33 00 33 00 36 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_HTTPSBeaconShell : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/limbenjamin/HTTPSBeaconShell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "d66e3566-6082-570a-a168-f44c9d8c7619"

	strings:
		$typelibguid0lo = {((61 63 61 38 35 33 64 63 2d 39 65 37 34 2d 34 31 37 35 2d 38 31 37 30 2d 65 38 35 33 37 32 64 35 66 32 61 39) | (61 00 63 00 61 00 38 00 35 00 33 00 64 00 63 00 2d 00 39 00 65 00 37 00 34 00 2d 00 34 00 31 00 37 00 35 00 2d 00 38 00 31 00 37 00 30 00 2d 00 65 00 38 00 35 00 33 00 37 00 32 00 64 00 35 00 66 00 32 00 61 00 39 00))}
		$typelibguid0up = {((41 43 41 38 35 33 44 43 2d 39 45 37 34 2d 34 31 37 35 2d 38 31 37 30 2d 45 38 35 33 37 32 44 35 46 32 41 39) | (41 00 43 00 41 00 38 00 35 00 33 00 44 00 43 00 2d 00 39 00 45 00 37 00 34 00 2d 00 34 00 31 00 37 00 35 00 2d 00 38 00 31 00 37 00 30 00 2d 00 45 00 38 00 35 00 33 00 37 00 32 00 44 00 35 00 46 00 32 00 41 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_AmsiScanBufferBypass : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rasta-mouse/AmsiScanBufferBypass"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "12a15e61-30fb-50a3-a59b-39f9871444f0"

	strings:
		$typelibguid0lo = {((34 33 31 65 66 32 64 39 2d 35 63 63 61 2d 34 31 64 33 2d 38 37 62 61 2d 63 37 66 35 65 34 35 38 32 64 64 32) | (34 00 33 00 31 00 65 00 66 00 32 00 64 00 39 00 2d 00 35 00 63 00 63 00 61 00 2d 00 34 00 31 00 64 00 33 00 2d 00 38 00 37 00 62 00 61 00 2d 00 63 00 37 00 66 00 35 00 65 00 34 00 35 00 38 00 32 00 64 00 64 00 32 00))}
		$typelibguid0up = {((34 33 31 45 46 32 44 39 2d 35 43 43 41 2d 34 31 44 33 2d 38 37 42 41 2d 43 37 46 35 45 34 35 38 32 44 44 32) | (34 00 33 00 31 00 45 00 46 00 32 00 44 00 39 00 2d 00 35 00 43 00 43 00 41 00 2d 00 34 00 31 00 44 00 33 00 2d 00 38 00 37 00 42 00 41 00 2d 00 43 00 37 00 46 00 35 00 45 00 34 00 35 00 38 00 32 00 44 00 44 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_ShellcodeLoader : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Hzllaga/ShellcodeLoader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "b8787dac-48a3-5711-86ba-0fda86b6224e"

	strings:
		$typelibguid0lo = {((61 34 38 66 65 30 65 31 2d 33 30 64 65 2d 34 36 61 36 2d 39 38 35 61 2d 33 66 32 64 65 33 63 38 61 63 39 36) | (61 00 34 00 38 00 66 00 65 00 30 00 65 00 31 00 2d 00 33 00 30 00 64 00 65 00 2d 00 34 00 36 00 61 00 36 00 2d 00 39 00 38 00 35 00 61 00 2d 00 33 00 66 00 32 00 64 00 65 00 33 00 63 00 38 00 61 00 63 00 39 00 36 00))}
		$typelibguid0up = {((41 34 38 46 45 30 45 31 2d 33 30 44 45 2d 34 36 41 36 2d 39 38 35 41 2d 33 46 32 44 45 33 43 38 41 43 39 36) | (41 00 34 00 38 00 46 00 45 00 30 00 45 00 31 00 2d 00 33 00 30 00 44 00 45 00 2d 00 34 00 36 00 41 00 36 00 2d 00 39 00 38 00 35 00 41 00 2d 00 33 00 46 00 32 00 44 00 45 00 33 00 43 00 38 00 41 00 43 00 39 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_KeystrokeAPI : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/fabriciorissetto/KeystrokeAPI"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "e715bce8-531b-5e2a-bd02-b2fc4990c499"

	strings:
		$typelibguid0lo = {((66 36 66 65 63 31 37 65 2d 65 32 32 64 2d 34 31 34 39 2d 61 38 61 38 2d 39 66 36 34 63 33 63 39 30 35 64 33) | (66 00 36 00 66 00 65 00 63 00 31 00 37 00 65 00 2d 00 65 00 32 00 32 00 64 00 2d 00 34 00 31 00 34 00 39 00 2d 00 61 00 38 00 61 00 38 00 2d 00 39 00 66 00 36 00 34 00 63 00 33 00 63 00 39 00 30 00 35 00 64 00 33 00))}
		$typelibguid0up = {((46 36 46 45 43 31 37 45 2d 45 32 32 44 2d 34 31 34 39 2d 41 38 41 38 2d 39 46 36 34 43 33 43 39 30 35 44 33) | (46 00 36 00 46 00 45 00 43 00 31 00 37 00 45 00 2d 00 45 00 32 00 32 00 44 00 2d 00 34 00 31 00 34 00 39 00 2d 00 41 00 38 00 41 00 38 00 2d 00 39 00 46 00 36 00 34 00 43 00 33 00 43 00 39 00 30 00 35 00 44 00 33 00))}
		$typelibguid1lo = {((62 37 61 61 34 65 32 33 2d 33 39 61 34 2d 34 39 64 35 2d 38 35 39 61 2d 30 38 33 63 37 38 39 62 66 65 61 32) | (62 00 37 00 61 00 61 00 34 00 65 00 32 00 33 00 2d 00 33 00 39 00 61 00 34 00 2d 00 34 00 39 00 64 00 35 00 2d 00 38 00 35 00 39 00 61 00 2d 00 30 00 38 00 33 00 63 00 37 00 38 00 39 00 62 00 66 00 65 00 61 00 32 00))}
		$typelibguid1up = {((42 37 41 41 34 45 32 33 2d 33 39 41 34 2d 34 39 44 35 2d 38 35 39 41 2d 30 38 33 43 37 38 39 42 46 45 41 32) | (42 00 37 00 41 00 41 00 34 00 45 00 32 00 33 00 2d 00 33 00 39 00 41 00 34 00 2d 00 34 00 39 00 44 00 35 00 2d 00 38 00 35 00 39 00 41 00 2d 00 30 00 38 00 33 00 43 00 37 00 38 00 39 00 42 00 46 00 45 00 41 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_ShellCodeRunner : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/antman1p/ShellCodeRunner"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "949364e7-dcb6-5afd-ade9-cc34a6e15e97"

	strings:
		$typelibguid0lo = {((36 33 34 38 37 34 62 37 2d 62 66 38 35 2d 34 30 30 63 2d 38 32 66 30 2d 37 66 33 62 34 36 35 39 35 34 39 61) | (36 00 33 00 34 00 38 00 37 00 34 00 62 00 37 00 2d 00 62 00 66 00 38 00 35 00 2d 00 34 00 30 00 30 00 63 00 2d 00 38 00 32 00 66 00 30 00 2d 00 37 00 66 00 33 00 62 00 34 00 36 00 35 00 39 00 35 00 34 00 39 00 61 00))}
		$typelibguid0up = {((36 33 34 38 37 34 42 37 2d 42 46 38 35 2d 34 30 30 43 2d 38 32 46 30 2d 37 46 33 42 34 36 35 39 35 34 39 41) | (36 00 33 00 34 00 38 00 37 00 34 00 42 00 37 00 2d 00 42 00 46 00 38 00 35 00 2d 00 34 00 30 00 30 00 43 00 2d 00 38 00 32 00 46 00 30 00 2d 00 37 00 46 00 33 00 42 00 34 00 36 00 35 00 39 00 35 00 34 00 39 00 41 00))}
		$typelibguid1lo = {((32 66 39 63 33 30 35 33 2d 30 37 37 66 2d 34 35 66 32 2d 62 32 30 37 2d 38 37 63 33 63 37 62 38 66 30 35 34) | (32 00 66 00 39 00 63 00 33 00 30 00 35 00 33 00 2d 00 30 00 37 00 37 00 66 00 2d 00 34 00 35 00 66 00 32 00 2d 00 62 00 32 00 30 00 37 00 2d 00 38 00 37 00 63 00 33 00 63 00 37 00 62 00 38 00 66 00 30 00 35 00 34 00))}
		$typelibguid1up = {((32 46 39 43 33 30 35 33 2d 30 37 37 46 2d 34 35 46 32 2d 42 32 30 37 2d 38 37 43 33 43 37 42 38 46 30 35 34) | (32 00 46 00 39 00 43 00 33 00 30 00 35 00 33 00 2d 00 30 00 37 00 37 00 46 00 2d 00 34 00 35 00 46 00 32 00 2d 00 42 00 32 00 30 00 37 00 2d 00 38 00 37 00 43 00 33 00 43 00 37 00 42 00 38 00 46 00 30 00 35 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_OffensiveCSharp : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/diljith369/OffensiveCSharp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "339f6858-6076-5320-ba5f-2903e642ea42"

	strings:
		$typelibguid0lo = {((36 63 33 66 62 63 36 35 2d 62 36 37 33 2d 34 30 66 30 2d 62 31 61 63 2d 32 30 36 33 36 64 66 30 31 61 38 35) | (36 00 63 00 33 00 66 00 62 00 63 00 36 00 35 00 2d 00 62 00 36 00 37 00 33 00 2d 00 34 00 30 00 66 00 30 00 2d 00 62 00 31 00 61 00 63 00 2d 00 32 00 30 00 36 00 33 00 36 00 64 00 66 00 30 00 31 00 61 00 38 00 35 00))}
		$typelibguid0up = {((36 43 33 46 42 43 36 35 2d 42 36 37 33 2d 34 30 46 30 2d 42 31 41 43 2d 32 30 36 33 36 44 46 30 31 41 38 35) | (36 00 43 00 33 00 46 00 42 00 43 00 36 00 35 00 2d 00 42 00 36 00 37 00 33 00 2d 00 34 00 30 00 46 00 30 00 2d 00 42 00 31 00 41 00 43 00 2d 00 32 00 30 00 36 00 33 00 36 00 44 00 46 00 30 00 31 00 41 00 38 00 35 00))}
		$typelibguid1lo = {((32 62 61 64 39 64 36 39 2d 61 64 61 39 2d 34 66 31 65 2d 62 38 33 38 2d 39 35 36 37 65 31 35 30 33 65 39 33) | (32 00 62 00 61 00 64 00 39 00 64 00 36 00 39 00 2d 00 61 00 64 00 61 00 39 00 2d 00 34 00 66 00 31 00 65 00 2d 00 62 00 38 00 33 00 38 00 2d 00 39 00 35 00 36 00 37 00 65 00 31 00 35 00 30 00 33 00 65 00 39 00 33 00))}
		$typelibguid1up = {((32 42 41 44 39 44 36 39 2d 41 44 41 39 2d 34 46 31 45 2d 42 38 33 38 2d 39 35 36 37 45 31 35 30 33 45 39 33) | (32 00 42 00 41 00 44 00 39 00 44 00 36 00 39 00 2d 00 41 00 44 00 41 00 39 00 2d 00 34 00 46 00 31 00 45 00 2d 00 42 00 38 00 33 00 38 00 2d 00 39 00 35 00 36 00 37 00 45 00 31 00 35 00 30 00 33 00 45 00 39 00 33 00))}
		$typelibguid2lo = {((35 31 32 30 31 35 64 65 2d 61 37 30 66 2d 34 38 38 37 2d 38 65 61 65 2d 65 35 30 30 66 64 32 38 39 38 61 62) | (35 00 31 00 32 00 30 00 31 00 35 00 64 00 65 00 2d 00 61 00 37 00 30 00 66 00 2d 00 34 00 38 00 38 00 37 00 2d 00 38 00 65 00 61 00 65 00 2d 00 65 00 35 00 30 00 30 00 66 00 64 00 32 00 38 00 39 00 38 00 61 00 62 00))}
		$typelibguid2up = {((35 31 32 30 31 35 44 45 2d 41 37 30 46 2d 34 38 38 37 2d 38 45 41 45 2d 45 35 30 30 46 44 32 38 39 38 41 42) | (35 00 31 00 32 00 30 00 31 00 35 00 44 00 45 00 2d 00 41 00 37 00 30 00 46 00 2d 00 34 00 38 00 38 00 37 00 2d 00 38 00 45 00 41 00 45 00 2d 00 45 00 35 00 30 00 30 00 46 00 44 00 32 00 38 00 39 00 38 00 41 00 42 00))}
		$typelibguid3lo = {((31 65 65 34 31 38 38 63 2d 32 34 61 63 2d 34 34 37 38 2d 62 38 39 32 2d 33 36 62 31 30 32 39 61 31 33 62 33) | (31 00 65 00 65 00 34 00 31 00 38 00 38 00 63 00 2d 00 32 00 34 00 61 00 63 00 2d 00 34 00 34 00 37 00 38 00 2d 00 62 00 38 00 39 00 32 00 2d 00 33 00 36 00 62 00 31 00 30 00 32 00 39 00 61 00 31 00 33 00 62 00 33 00))}
		$typelibguid3up = {((31 45 45 34 31 38 38 43 2d 32 34 41 43 2d 34 34 37 38 2d 42 38 39 32 2d 33 36 42 31 30 32 39 41 31 33 42 33) | (31 00 45 00 45 00 34 00 31 00 38 00 38 00 43 00 2d 00 32 00 34 00 41 00 43 00 2d 00 34 00 34 00 37 00 38 00 2d 00 42 00 38 00 39 00 32 00 2d 00 33 00 36 00 42 00 31 00 30 00 32 00 39 00 41 00 31 00 33 00 42 00 33 00))}
		$typelibguid4lo = {((35 63 36 62 37 33 36 31 2d 66 39 61 62 2d 34 31 64 63 2d 62 66 61 30 2d 65 64 35 64 34 62 30 30 33 32 61 38) | (35 00 63 00 36 00 62 00 37 00 33 00 36 00 31 00 2d 00 66 00 39 00 61 00 62 00 2d 00 34 00 31 00 64 00 63 00 2d 00 62 00 66 00 61 00 30 00 2d 00 65 00 64 00 35 00 64 00 34 00 62 00 30 00 30 00 33 00 32 00 61 00 38 00))}
		$typelibguid4up = {((35 43 36 42 37 33 36 31 2d 46 39 41 42 2d 34 31 44 43 2d 42 46 41 30 2d 45 44 35 44 34 42 30 30 33 32 41 38) | (35 00 43 00 36 00 42 00 37 00 33 00 36 00 31 00 2d 00 46 00 39 00 41 00 42 00 2d 00 34 00 31 00 44 00 43 00 2d 00 42 00 46 00 41 00 30 00 2d 00 45 00 44 00 35 00 44 00 34 00 42 00 30 00 30 00 33 00 32 00 41 00 38 00))}
		$typelibguid5lo = {((30 34 38 61 36 35 35 39 2d 64 34 64 33 2d 34 61 64 38 2d 61 66 30 66 2d 62 37 66 37 32 62 32 31 32 65 39 30) | (30 00 34 00 38 00 61 00 36 00 35 00 35 00 39 00 2d 00 64 00 34 00 64 00 33 00 2d 00 34 00 61 00 64 00 38 00 2d 00 61 00 66 00 30 00 66 00 2d 00 62 00 37 00 66 00 37 00 32 00 62 00 32 00 31 00 32 00 65 00 39 00 30 00))}
		$typelibguid5up = {((30 34 38 41 36 35 35 39 2d 44 34 44 33 2d 34 41 44 38 2d 41 46 30 46 2d 42 37 46 37 32 42 32 31 32 45 39 30) | (30 00 34 00 38 00 41 00 36 00 35 00 35 00 39 00 2d 00 44 00 34 00 44 00 33 00 2d 00 34 00 41 00 44 00 38 00 2d 00 41 00 46 00 30 00 46 00 2d 00 42 00 37 00 46 00 37 00 32 00 42 00 32 00 31 00 32 00 45 00 39 00 30 00))}
		$typelibguid6lo = {((33 34 31 32 66 62 65 39 2d 31 39 64 33 2d 34 31 64 38 2d 39 61 64 32 2d 36 34 36 31 66 63 62 33 39 34 64 63) | (33 00 34 00 31 00 32 00 66 00 62 00 65 00 39 00 2d 00 31 00 39 00 64 00 33 00 2d 00 34 00 31 00 64 00 38 00 2d 00 39 00 61 00 64 00 32 00 2d 00 36 00 34 00 36 00 31 00 66 00 63 00 62 00 33 00 39 00 34 00 64 00 63 00))}
		$typelibguid6up = {((33 34 31 32 46 42 45 39 2d 31 39 44 33 2d 34 31 44 38 2d 39 41 44 32 2d 36 34 36 31 46 43 42 33 39 34 44 43) | (33 00 34 00 31 00 32 00 46 00 42 00 45 00 39 00 2d 00 31 00 39 00 44 00 33 00 2d 00 34 00 31 00 44 00 38 00 2d 00 39 00 41 00 44 00 32 00 2d 00 36 00 34 00 36 00 31 00 46 00 43 00 42 00 33 00 39 00 34 00 44 00 43 00))}
		$typelibguid7lo = {((39 65 61 34 65 30 64 63 2d 39 37 32 33 2d 34 64 39 33 2d 38 35 62 62 2d 61 34 66 63 61 62 30 61 64 32 31 30) | (39 00 65 00 61 00 34 00 65 00 30 00 64 00 63 00 2d 00 39 00 37 00 32 00 33 00 2d 00 34 00 64 00 39 00 33 00 2d 00 38 00 35 00 62 00 62 00 2d 00 61 00 34 00 66 00 63 00 61 00 62 00 30 00 61 00 64 00 32 00 31 00 30 00))}
		$typelibguid7up = {((39 45 41 34 45 30 44 43 2d 39 37 32 33 2d 34 44 39 33 2d 38 35 42 42 2d 41 34 46 43 41 42 30 41 44 32 31 30) | (39 00 45 00 41 00 34 00 45 00 30 00 44 00 43 00 2d 00 39 00 37 00 32 00 33 00 2d 00 34 00 44 00 39 00 33 00 2d 00 38 00 35 00 42 00 42 00 2d 00 41 00 34 00 46 00 43 00 41 00 42 00 30 00 41 00 44 00 32 00 31 00 30 00))}
		$typelibguid8lo = {((36 64 32 62 32 33 39 63 2d 62 61 31 65 2d 34 33 65 63 2d 38 33 33 34 2d 64 36 37 64 35 32 62 37 37 31 38 31) | (36 00 64 00 32 00 62 00 32 00 33 00 39 00 63 00 2d 00 62 00 61 00 31 00 65 00 2d 00 34 00 33 00 65 00 63 00 2d 00 38 00 33 00 33 00 34 00 2d 00 64 00 36 00 37 00 64 00 35 00 32 00 62 00 37 00 37 00 31 00 38 00 31 00))}
		$typelibguid8up = {((36 44 32 42 32 33 39 43 2d 42 41 31 45 2d 34 33 45 43 2d 38 33 33 34 2d 44 36 37 44 35 32 42 37 37 31 38 31) | (36 00 44 00 32 00 42 00 32 00 33 00 39 00 43 00 2d 00 42 00 41 00 31 00 45 00 2d 00 34 00 33 00 45 00 43 00 2d 00 38 00 33 00 33 00 34 00 2d 00 44 00 36 00 37 00 44 00 35 00 32 00 42 00 37 00 37 00 31 00 38 00 31 00))}
		$typelibguid9lo = {((34 32 65 38 62 39 65 31 2d 30 63 66 34 2d 34 36 61 65 2d 62 35 37 33 2d 39 64 30 35 36 33 65 34 31 32 33 38) | (34 00 32 00 65 00 38 00 62 00 39 00 65 00 31 00 2d 00 30 00 63 00 66 00 34 00 2d 00 34 00 36 00 61 00 65 00 2d 00 62 00 35 00 37 00 33 00 2d 00 39 00 64 00 30 00 35 00 36 00 33 00 65 00 34 00 31 00 32 00 33 00 38 00))}
		$typelibguid9up = {((34 32 45 38 42 39 45 31 2d 30 43 46 34 2d 34 36 41 45 2d 42 35 37 33 2d 39 44 30 35 36 33 45 34 31 32 33 38) | (34 00 32 00 45 00 38 00 42 00 39 00 45 00 31 00 2d 00 30 00 43 00 46 00 34 00 2d 00 34 00 36 00 41 00 45 00 2d 00 42 00 35 00 37 00 33 00 2d 00 39 00 44 00 30 00 35 00 36 00 33 00 45 00 34 00 31 00 32 00 33 00 38 00))}
		$typelibguid10lo = {((30 64 31 35 65 30 65 33 2d 62 63 66 64 2d 34 61 38 35 2d 61 64 63 64 2d 30 65 37 35 31 64 61 62 34 64 64 36) | (30 00 64 00 31 00 35 00 65 00 30 00 65 00 33 00 2d 00 62 00 63 00 66 00 64 00 2d 00 34 00 61 00 38 00 35 00 2d 00 61 00 64 00 63 00 64 00 2d 00 30 00 65 00 37 00 35 00 31 00 64 00 61 00 62 00 34 00 64 00 64 00 36 00))}
		$typelibguid10up = {((30 44 31 35 45 30 45 33 2d 42 43 46 44 2d 34 41 38 35 2d 41 44 43 44 2d 30 45 37 35 31 44 41 42 34 44 44 36) | (30 00 44 00 31 00 35 00 45 00 30 00 45 00 33 00 2d 00 42 00 43 00 46 00 44 00 2d 00 34 00 41 00 38 00 35 00 2d 00 41 00 44 00 43 00 44 00 2d 00 30 00 45 00 37 00 35 00 31 00 44 00 41 00 42 00 34 00 44 00 44 00 36 00))}
		$typelibguid11lo = {((36 34 34 64 66 64 31 61 2d 66 64 61 35 2d 34 39 34 38 2d 38 33 63 32 2d 38 64 33 62 35 65 64 61 31 34 33 61) | (36 00 34 00 34 00 64 00 66 00 64 00 31 00 61 00 2d 00 66 00 64 00 61 00 35 00 2d 00 34 00 39 00 34 00 38 00 2d 00 38 00 33 00 63 00 32 00 2d 00 38 00 64 00 33 00 62 00 35 00 65 00 64 00 61 00 31 00 34 00 33 00 61 00))}
		$typelibguid11up = {((36 34 34 44 46 44 31 41 2d 46 44 41 35 2d 34 39 34 38 2d 38 33 43 32 2d 38 44 33 42 35 45 44 41 31 34 33 41) | (36 00 34 00 34 00 44 00 46 00 44 00 31 00 41 00 2d 00 46 00 44 00 41 00 35 00 2d 00 34 00 39 00 34 00 38 00 2d 00 38 00 33 00 43 00 32 00 2d 00 38 00 44 00 33 00 42 00 35 00 45 00 44 00 41 00 31 00 34 00 33 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SHAPESHIFTER : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/matterpreter/SHAPESHIFTER"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "8903c65a-624f-5e8d-a3f6-4572b56bd2f7"

	strings:
		$typelibguid0lo = {((61 33 64 64 66 63 61 61 2d 36 36 65 37 2d 34 34 66 64 2d 61 64 34 38 2d 39 64 38 30 64 31 36 35 31 32 32 38) | (61 00 33 00 64 00 64 00 66 00 63 00 61 00 61 00 2d 00 36 00 36 00 65 00 37 00 2d 00 34 00 34 00 66 00 64 00 2d 00 61 00 64 00 34 00 38 00 2d 00 39 00 64 00 38 00 30 00 64 00 31 00 36 00 35 00 31 00 32 00 32 00 38 00))}
		$typelibguid0up = {((41 33 44 44 46 43 41 41 2d 36 36 45 37 2d 34 34 46 44 2d 41 44 34 38 2d 39 44 38 30 44 31 36 35 31 32 32 38) | (41 00 33 00 44 00 44 00 46 00 43 00 41 00 41 00 2d 00 36 00 36 00 45 00 37 00 2d 00 34 00 34 00 46 00 44 00 2d 00 41 00 44 00 34 00 38 00 2d 00 39 00 44 00 38 00 30 00 44 00 31 00 36 00 35 00 31 00 32 00 32 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Evasor : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/cyberark/Evasor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "457959ed-3e90-52c7-89f9-e1b17b35260e"

	strings:
		$typelibguid0lo = {((31 63 38 38 34 39 65 66 2d 61 64 30 39 2d 34 37 32 37 2d 62 66 38 31 2d 31 66 37 37 37 62 64 31 61 65 66 38) | (31 00 63 00 38 00 38 00 34 00 39 00 65 00 66 00 2d 00 61 00 64 00 30 00 39 00 2d 00 34 00 37 00 32 00 37 00 2d 00 62 00 66 00 38 00 31 00 2d 00 31 00 66 00 37 00 37 00 37 00 62 00 64 00 31 00 61 00 65 00 66 00 38 00))}
		$typelibguid0up = {((31 43 38 38 34 39 45 46 2d 41 44 30 39 2d 34 37 32 37 2d 42 46 38 31 2d 31 46 37 37 37 42 44 31 41 45 46 38) | (31 00 43 00 38 00 38 00 34 00 39 00 45 00 46 00 2d 00 41 00 44 00 30 00 39 00 2d 00 34 00 37 00 32 00 37 00 2d 00 42 00 46 00 38 00 31 00 2d 00 31 00 46 00 37 00 37 00 37 00 42 00 44 00 31 00 41 00 45 00 46 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Stracciatella : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mgeeky/Stracciatella"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "5b1a8102-6d59-5f2f-8ae2-b3c1f75a561d"

	strings:
		$typelibguid0lo = {((65 61 61 66 61 30 61 63 2d 65 34 36 34 2d 34 66 63 34 2d 39 37 31 33 2d 34 38 61 61 39 61 36 37 31 36 66 62) | (65 00 61 00 61 00 66 00 61 00 30 00 61 00 63 00 2d 00 65 00 34 00 36 00 34 00 2d 00 34 00 66 00 63 00 34 00 2d 00 39 00 37 00 31 00 33 00 2d 00 34 00 38 00 61 00 61 00 39 00 61 00 36 00 37 00 31 00 36 00 66 00 62 00))}
		$typelibguid0up = {((45 41 41 46 41 30 41 43 2d 45 34 36 34 2d 34 46 43 34 2d 39 37 31 33 2d 34 38 41 41 39 41 36 37 31 36 46 42) | (45 00 41 00 41 00 46 00 41 00 30 00 41 00 43 00 2d 00 45 00 34 00 36 00 34 00 2d 00 34 00 46 00 43 00 34 00 2d 00 39 00 37 00 31 00 33 00 2d 00 34 00 38 00 41 00 41 00 39 00 41 00 36 00 37 00 31 00 36 00 46 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_logger : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/xxczaki/logger"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "82937fef-8280-5bc6-af4a-55c5cb3a7553"

	strings:
		$typelibguid0lo = {((39 65 39 32 61 38 38 33 2d 33 63 38 62 2d 34 35 37 32 2d 61 37 33 65 2d 62 62 33 65 36 31 63 66 64 63 31 36) | (39 00 65 00 39 00 32 00 61 00 38 00 38 00 33 00 2d 00 33 00 63 00 38 00 62 00 2d 00 34 00 35 00 37 00 32 00 2d 00 61 00 37 00 33 00 65 00 2d 00 62 00 62 00 33 00 65 00 36 00 31 00 63 00 66 00 64 00 63 00 31 00 36 00))}
		$typelibguid0up = {((39 45 39 32 41 38 38 33 2d 33 43 38 42 2d 34 35 37 32 2d 41 37 33 45 2d 42 42 33 45 36 31 43 46 44 43 31 36) | (39 00 45 00 39 00 32 00 41 00 38 00 38 00 33 00 2d 00 33 00 43 00 38 00 42 00 2d 00 34 00 35 00 37 00 32 00 2d 00 41 00 37 00 33 00 45 00 2d 00 42 00 42 00 33 00 45 00 36 00 31 00 43 00 46 00 44 00 43 00 31 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Internal_Monologue : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/eladshamir/Internal-Monologue"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "ce2773a2-b0b7-560e-ba21-3f018ddcacb3"

	strings:
		$typelibguid0lo = {((30 63 30 33 33 33 64 62 2d 38 66 30 30 2d 34 62 36 38 2d 62 31 64 62 2d 31 38 61 39 63 61 63 63 31 34 38 36) | (30 00 63 00 30 00 33 00 33 00 33 00 64 00 62 00 2d 00 38 00 66 00 30 00 30 00 2d 00 34 00 62 00 36 00 38 00 2d 00 62 00 31 00 64 00 62 00 2d 00 31 00 38 00 61 00 39 00 63 00 61 00 63 00 63 00 31 00 34 00 38 00 36 00))}
		$typelibguid0up = {((30 43 30 33 33 33 44 42 2d 38 46 30 30 2d 34 42 36 38 2d 42 31 44 42 2d 31 38 41 39 43 41 43 43 31 34 38 36) | (30 00 43 00 30 00 33 00 33 00 33 00 44 00 42 00 2d 00 38 00 46 00 30 00 30 00 2d 00 34 00 42 00 36 00 38 00 2d 00 42 00 31 00 44 00 42 00 2d 00 31 00 38 00 41 00 39 00 43 00 41 00 43 00 43 00 31 00 34 00 38 00 36 00))}
		$typelibguid1lo = {((38 34 37 30 31 61 63 65 2d 63 35 38 34 2d 34 38 38 36 2d 61 33 63 66 2d 37 36 63 35 37 66 36 65 38 30 31 61) | (38 00 34 00 37 00 30 00 31 00 61 00 63 00 65 00 2d 00 63 00 35 00 38 00 34 00 2d 00 34 00 38 00 38 00 36 00 2d 00 61 00 33 00 63 00 66 00 2d 00 37 00 36 00 63 00 35 00 37 00 66 00 36 00 65 00 38 00 30 00 31 00 61 00))}
		$typelibguid1up = {((38 34 37 30 31 41 43 45 2d 43 35 38 34 2d 34 38 38 36 2d 41 33 43 46 2d 37 36 43 35 37 46 36 45 38 30 31 41) | (38 00 34 00 37 00 30 00 31 00 41 00 43 00 45 00 2d 00 43 00 35 00 38 00 34 00 2d 00 34 00 38 00 38 00 36 00 2d 00 41 00 33 00 43 00 46 00 2d 00 37 00 36 00 43 00 35 00 37 00 46 00 36 00 45 00 38 00 30 00 31 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_GRAT2 : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/r3nhat/GRAT2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "e731d563-0d16-5f84-8127-624a71f8b646"

	strings:
		$typelibguid0lo = {((35 65 37 66 63 65 37 38 2d 31 39 37 37 2d 34 34 34 66 2d 61 31 38 65 2d 39 38 37 64 37 30 38 61 32 63 66 66) | (35 00 65 00 37 00 66 00 63 00 65 00 37 00 38 00 2d 00 31 00 39 00 37 00 37 00 2d 00 34 00 34 00 34 00 66 00 2d 00 61 00 31 00 38 00 65 00 2d 00 39 00 38 00 37 00 64 00 37 00 30 00 38 00 61 00 32 00 63 00 66 00 66 00))}
		$typelibguid0up = {((35 45 37 46 43 45 37 38 2d 31 39 37 37 2d 34 34 34 46 2d 41 31 38 45 2d 39 38 37 44 37 30 38 41 32 43 46 46) | (35 00 45 00 37 00 46 00 43 00 45 00 37 00 38 00 2d 00 31 00 39 00 37 00 37 00 2d 00 34 00 34 00 34 00 46 00 2d 00 41 00 31 00 38 00 45 00 2d 00 39 00 38 00 37 00 44 00 37 00 30 00 38 00 41 00 32 00 43 00 46 00 46 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_PowerShdll : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/p3nt4/PowerShdll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "3f582a47-078e-525f-9d02-4ee7a455a3b2"
		score = 60

	strings:
		$typelibguid0lo = {((33 36 65 62 66 39 61 61 2d 32 66 33 37 2d 34 66 31 64 2d 61 32 66 31 2d 66 32 61 34 35 64 65 65 61 66 32 31) | (33 00 36 00 65 00 62 00 66 00 39 00 61 00 61 00 2d 00 32 00 66 00 33 00 37 00 2d 00 34 00 66 00 31 00 64 00 2d 00 61 00 32 00 66 00 31 00 2d 00 66 00 32 00 61 00 34 00 35 00 64 00 65 00 65 00 61 00 66 00 32 00 31 00))}
		$typelibguid0up = {((33 36 45 42 46 39 41 41 2d 32 46 33 37 2d 34 46 31 44 2d 41 32 46 31 2d 46 32 41 34 35 44 45 45 41 46 32 31) | (33 00 36 00 45 00 42 00 46 00 39 00 41 00 41 00 2d 00 32 00 46 00 33 00 37 00 2d 00 34 00 46 00 31 00 44 00 2d 00 41 00 32 00 46 00 31 00 2d 00 46 00 32 00 41 00 34 00 35 00 44 00 45 00 45 00 41 00 46 00 32 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_CsharpAmsiBypass : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/WayneJLee/CsharpAmsiBypass"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "ca97004e-edc1-5b5a-ac67-e81ae24631aa"

	strings:
		$typelibguid0lo = {((34 61 62 33 62 39 35 64 2d 33 37 33 63 2d 34 31 39 37 2d 38 65 65 33 2d 66 65 30 66 61 36 36 63 61 31 32 32) | (34 00 61 00 62 00 33 00 62 00 39 00 35 00 64 00 2d 00 33 00 37 00 33 00 63 00 2d 00 34 00 31 00 39 00 37 00 2d 00 38 00 65 00 65 00 33 00 2d 00 66 00 65 00 30 00 66 00 61 00 36 00 36 00 63 00 61 00 31 00 32 00 32 00))}
		$typelibguid0up = {((34 41 42 33 42 39 35 44 2d 33 37 33 43 2d 34 31 39 37 2d 38 45 45 33 2d 46 45 30 46 41 36 36 43 41 31 32 32) | (34 00 41 00 42 00 33 00 42 00 39 00 35 00 44 00 2d 00 33 00 37 00 33 00 43 00 2d 00 34 00 31 00 39 00 37 00 2d 00 38 00 45 00 45 00 33 00 2d 00 46 00 45 00 30 00 46 00 41 00 36 00 36 00 43 00 41 00 31 00 32 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_HastySeries : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/obscuritylabs/HastySeries"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "0d35acf4-c763-593c-94e2-c499d3826375"

	strings:
		$typelibguid0lo = {((38 34 33 35 35 33 31 64 2d 36 37 35 63 2d 34 32 37 30 2d 38 35 62 66 2d 36 30 64 62 37 36 35 33 62 63 66 36) | (38 00 34 00 33 00 35 00 35 00 33 00 31 00 64 00 2d 00 36 00 37 00 35 00 63 00 2d 00 34 00 32 00 37 00 30 00 2d 00 38 00 35 00 62 00 66 00 2d 00 36 00 30 00 64 00 62 00 37 00 36 00 35 00 33 00 62 00 63 00 66 00 36 00))}
		$typelibguid0up = {((38 34 33 35 35 33 31 44 2d 36 37 35 43 2d 34 32 37 30 2d 38 35 42 46 2d 36 30 44 42 37 36 35 33 42 43 46 36) | (38 00 34 00 33 00 35 00 35 00 33 00 31 00 44 00 2d 00 36 00 37 00 35 00 43 00 2d 00 34 00 32 00 37 00 30 00 2d 00 38 00 35 00 42 00 46 00 2d 00 36 00 30 00 44 00 42 00 37 00 36 00 35 00 33 00 42 00 43 00 46 00 36 00))}
		$typelibguid1lo = {((34 37 64 62 39 38 39 66 2d 37 65 33 33 2d 34 65 36 62 2d 61 34 61 35 2d 63 33 39 32 62 34 32 39 32 36 34 62) | (34 00 37 00 64 00 62 00 39 00 38 00 39 00 66 00 2d 00 37 00 65 00 33 00 33 00 2d 00 34 00 65 00 36 00 62 00 2d 00 61 00 34 00 61 00 35 00 2d 00 63 00 33 00 39 00 32 00 62 00 34 00 32 00 39 00 32 00 36 00 34 00 62 00))}
		$typelibguid1up = {((34 37 44 42 39 38 39 46 2d 37 45 33 33 2d 34 45 36 42 2d 41 34 41 35 2d 43 33 39 32 42 34 32 39 32 36 34 42) | (34 00 37 00 44 00 42 00 39 00 38 00 39 00 46 00 2d 00 37 00 45 00 33 00 33 00 2d 00 34 00 45 00 36 00 42 00 2d 00 41 00 34 00 41 00 35 00 2d 00 43 00 33 00 39 00 32 00 42 00 34 00 32 00 39 00 32 00 36 00 34 00 42 00))}
		$typelibguid2lo = {((33 30 30 63 37 34 38 39 2d 61 30 35 66 2d 34 30 33 35 2d 38 38 32 36 2d 32 36 31 66 61 34 34 39 64 64 39 36) | (33 00 30 00 30 00 63 00 37 00 34 00 38 00 39 00 2d 00 61 00 30 00 35 00 66 00 2d 00 34 00 30 00 33 00 35 00 2d 00 38 00 38 00 32 00 36 00 2d 00 32 00 36 00 31 00 66 00 61 00 34 00 34 00 39 00 64 00 64 00 39 00 36 00))}
		$typelibguid2up = {((33 30 30 43 37 34 38 39 2d 41 30 35 46 2d 34 30 33 35 2d 38 38 32 36 2d 32 36 31 46 41 34 34 39 44 44 39 36) | (33 00 30 00 30 00 43 00 37 00 34 00 38 00 39 00 2d 00 41 00 30 00 35 00 46 00 2d 00 34 00 30 00 33 00 35 00 2d 00 38 00 38 00 32 00 36 00 2d 00 32 00 36 00 31 00 46 00 41 00 34 00 34 00 39 00 44 00 44 00 39 00 36 00))}
		$typelibguid3lo = {((34 31 62 66 38 37 38 31 2d 61 65 30 34 2d 34 64 38 30 2d 62 33 38 64 2d 37 30 37 35 38 34 62 66 37 39 36 62) | (34 00 31 00 62 00 66 00 38 00 37 00 38 00 31 00 2d 00 61 00 65 00 30 00 34 00 2d 00 34 00 64 00 38 00 30 00 2d 00 62 00 33 00 38 00 64 00 2d 00 37 00 30 00 37 00 35 00 38 00 34 00 62 00 66 00 37 00 39 00 36 00 62 00))}
		$typelibguid3up = {((34 31 42 46 38 37 38 31 2d 41 45 30 34 2d 34 44 38 30 2d 42 33 38 44 2d 37 30 37 35 38 34 42 46 37 39 36 42) | (34 00 31 00 42 00 46 00 38 00 37 00 38 00 31 00 2d 00 41 00 45 00 30 00 34 00 2d 00 34 00 44 00 38 00 30 00 2d 00 42 00 33 00 38 00 44 00 2d 00 37 00 30 00 37 00 35 00 38 00 34 00 42 00 46 00 37 00 39 00 36 00 42 00))}
		$typelibguid4lo = {((36 32 30 65 64 34 35 39 2d 31 38 64 65 2d 34 33 35 39 2d 62 66 62 30 2d 36 64 30 63 34 38 34 31 62 36 66 36) | (36 00 32 00 30 00 65 00 64 00 34 00 35 00 39 00 2d 00 31 00 38 00 64 00 65 00 2d 00 34 00 33 00 35 00 39 00 2d 00 62 00 66 00 62 00 30 00 2d 00 36 00 64 00 30 00 63 00 34 00 38 00 34 00 31 00 62 00 36 00 66 00 36 00))}
		$typelibguid4up = {((36 32 30 45 44 34 35 39 2d 31 38 44 45 2d 34 33 35 39 2d 42 46 42 30 2d 36 44 30 43 34 38 34 31 42 36 46 36) | (36 00 32 00 30 00 45 00 44 00 34 00 35 00 39 00 2d 00 31 00 38 00 44 00 45 00 2d 00 34 00 33 00 35 00 39 00 2d 00 42 00 46 00 42 00 30 00 2d 00 36 00 44 00 30 00 43 00 34 00 38 00 34 00 31 00 42 00 36 00 46 00 36 00))}
		$typelibguid5lo = {((39 31 65 37 63 64 66 65 2d 30 39 34 35 2d 34 35 61 37 2d 39 65 61 61 2d 30 39 33 33 61 66 65 33 38 31 66 32) | (39 00 31 00 65 00 37 00 63 00 64 00 66 00 65 00 2d 00 30 00 39 00 34 00 35 00 2d 00 34 00 35 00 61 00 37 00 2d 00 39 00 65 00 61 00 61 00 2d 00 30 00 39 00 33 00 33 00 61 00 66 00 65 00 33 00 38 00 31 00 66 00 32 00))}
		$typelibguid5up = {((39 31 45 37 43 44 46 45 2d 30 39 34 35 2d 34 35 41 37 2d 39 45 41 41 2d 30 39 33 33 41 46 45 33 38 31 46 32) | (39 00 31 00 45 00 37 00 43 00 44 00 46 00 45 00 2d 00 30 00 39 00 34 00 35 00 2d 00 34 00 35 00 41 00 37 00 2d 00 39 00 45 00 41 00 41 00 2d 00 30 00 39 00 33 00 33 00 41 00 46 00 45 00 33 00 38 00 31 00 46 00 32 00))}
		$typelibguid6lo = {((63 32 38 65 31 32 31 61 2d 36 30 63 61 2d 34 63 32 31 2d 61 66 34 62 2d 39 33 65 62 32 33 37 62 38 38 32 66) | (63 00 32 00 38 00 65 00 31 00 32 00 31 00 61 00 2d 00 36 00 30 00 63 00 61 00 2d 00 34 00 63 00 32 00 31 00 2d 00 61 00 66 00 34 00 62 00 2d 00 39 00 33 00 65 00 62 00 32 00 33 00 37 00 62 00 38 00 38 00 32 00 66 00))}
		$typelibguid6up = {((43 32 38 45 31 32 31 41 2d 36 30 43 41 2d 34 43 32 31 2d 41 46 34 42 2d 39 33 45 42 32 33 37 42 38 38 32 46) | (43 00 32 00 38 00 45 00 31 00 32 00 31 00 41 00 2d 00 36 00 30 00 43 00 41 00 2d 00 34 00 43 00 32 00 31 00 2d 00 41 00 46 00 34 00 42 00 2d 00 39 00 33 00 45 00 42 00 32 00 33 00 37 00 42 00 38 00 38 00 32 00 46 00))}
		$typelibguid7lo = {((36 39 38 66 61 63 37 61 2d 62 66 66 31 2d 34 63 32 34 2d 62 32 63 33 2d 31 37 33 61 36 61 61 65 31 35 62 66) | (36 00 39 00 38 00 66 00 61 00 63 00 37 00 61 00 2d 00 62 00 66 00 66 00 31 00 2d 00 34 00 63 00 32 00 34 00 2d 00 62 00 32 00 63 00 33 00 2d 00 31 00 37 00 33 00 61 00 36 00 61 00 61 00 65 00 31 00 35 00 62 00 66 00))}
		$typelibguid7up = {((36 39 38 46 41 43 37 41 2d 42 46 46 31 2d 34 43 32 34 2d 42 32 43 33 2d 31 37 33 41 36 41 41 45 31 35 42 46) | (36 00 39 00 38 00 46 00 41 00 43 00 37 00 41 00 2d 00 42 00 46 00 46 00 31 00 2d 00 34 00 43 00 32 00 34 00 2d 00 42 00 32 00 43 00 33 00 2d 00 31 00 37 00 33 00 41 00 36 00 41 00 41 00 45 00 31 00 35 00 42 00 46 00))}
		$typelibguid8lo = {((36 33 61 34 30 64 39 34 2d 35 33 31 38 2d 34 32 61 64 2d 61 35 37 33 2d 65 33 61 31 63 31 32 38 34 63 35 37) | (36 00 33 00 61 00 34 00 30 00 64 00 39 00 34 00 2d 00 35 00 33 00 31 00 38 00 2d 00 34 00 32 00 61 00 64 00 2d 00 61 00 35 00 37 00 33 00 2d 00 65 00 33 00 61 00 31 00 63 00 31 00 32 00 38 00 34 00 63 00 35 00 37 00))}
		$typelibguid8up = {((36 33 41 34 30 44 39 34 2d 35 33 31 38 2d 34 32 41 44 2d 41 35 37 33 2d 45 33 41 31 43 31 32 38 34 43 35 37) | (36 00 33 00 41 00 34 00 30 00 44 00 39 00 34 00 2d 00 35 00 33 00 31 00 38 00 2d 00 34 00 32 00 41 00 44 00 2d 00 41 00 35 00 37 00 33 00 2d 00 45 00 33 00 41 00 31 00 43 00 31 00 32 00 38 00 34 00 43 00 35 00 37 00))}
		$typelibguid9lo = {((35 36 62 38 33 31 31 62 2d 30 34 62 38 2d 34 65 35 37 2d 62 62 35 38 2d 64 36 32 61 64 63 30 64 32 65 36 38) | (35 00 36 00 62 00 38 00 33 00 31 00 31 00 62 00 2d 00 30 00 34 00 62 00 38 00 2d 00 34 00 65 00 35 00 37 00 2d 00 62 00 62 00 35 00 38 00 2d 00 64 00 36 00 32 00 61 00 64 00 63 00 30 00 64 00 32 00 65 00 36 00 38 00))}
		$typelibguid9up = {((35 36 42 38 33 31 31 42 2d 30 34 42 38 2d 34 45 35 37 2d 42 42 35 38 2d 44 36 32 41 44 43 30 44 32 45 36 38) | (35 00 36 00 42 00 38 00 33 00 31 00 31 00 42 00 2d 00 30 00 34 00 42 00 38 00 2d 00 34 00 45 00 35 00 37 00 2d 00 42 00 42 00 35 00 38 00 2d 00 44 00 36 00 32 00 41 00 44 00 43 00 30 00 44 00 32 00 45 00 36 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_DreamProtectorFree : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Paskowsky/DreamProtectorFree"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "9ebee989-3441-5a76-b243-08de978b541c"

	strings:
		$typelibguid0lo = {((66 37 65 38 61 39 30 32 2d 32 33 37 38 2d 34 32 36 61 2d 62 66 61 35 2d 36 62 31 34 63 34 62 34 30 61 61 33) | (66 00 37 00 65 00 38 00 61 00 39 00 30 00 32 00 2d 00 32 00 33 00 37 00 38 00 2d 00 34 00 32 00 36 00 61 00 2d 00 62 00 66 00 61 00 35 00 2d 00 36 00 62 00 31 00 34 00 63 00 34 00 62 00 34 00 30 00 61 00 61 00 33 00))}
		$typelibguid0up = {((46 37 45 38 41 39 30 32 2d 32 33 37 38 2d 34 32 36 41 2d 42 46 41 35 2d 36 42 31 34 43 34 42 34 30 41 41 33) | (46 00 37 00 45 00 38 00 41 00 39 00 30 00 32 00 2d 00 32 00 33 00 37 00 38 00 2d 00 34 00 32 00 36 00 41 00 2d 00 42 00 46 00 41 00 35 00 2d 00 36 00 42 00 31 00 34 00 43 00 34 00 42 00 34 00 30 00 41 00 41 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_RedSharp : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/padovah4ck/RedSharp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "2aa62d61-075c-5664-a7fc-2b9d84b954ed"

	strings:
		$typelibguid0lo = {((33 30 62 32 65 30 63 66 2d 33 34 64 64 2d 34 36 31 34 2d 61 35 63 61 2d 36 35 37 38 66 62 36 38 34 61 65 61) | (33 00 30 00 62 00 32 00 65 00 30 00 63 00 66 00 2d 00 33 00 34 00 64 00 64 00 2d 00 34 00 36 00 31 00 34 00 2d 00 61 00 35 00 63 00 61 00 2d 00 36 00 35 00 37 00 38 00 66 00 62 00 36 00 38 00 34 00 61 00 65 00 61 00))}
		$typelibguid0up = {((33 30 42 32 45 30 43 46 2d 33 34 44 44 2d 34 36 31 34 2d 41 35 43 41 2d 36 35 37 38 46 42 36 38 34 41 45 41) | (33 00 30 00 42 00 32 00 45 00 30 00 43 00 46 00 2d 00 33 00 34 00 44 00 44 00 2d 00 34 00 36 00 31 00 34 00 2d 00 41 00 35 00 43 00 41 00 2d 00 36 00 35 00 37 00 38 00 46 00 42 00 36 00 38 00 34 00 41 00 45 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_ESC : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NetSPI/ESC"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "a57c47e8-62bf-5425-9735-35a3e3a0c218"

	strings:
		$typelibguid0lo = {((30 36 32 36 30 63 65 35 2d 36 31 66 34 2d 34 62 38 31 2d 61 64 38 33 2d 37 64 30 31 63 33 62 33 37 39 32 31) | (30 00 36 00 32 00 36 00 30 00 63 00 65 00 35 00 2d 00 36 00 31 00 66 00 34 00 2d 00 34 00 62 00 38 00 31 00 2d 00 61 00 64 00 38 00 33 00 2d 00 37 00 64 00 30 00 31 00 63 00 33 00 62 00 33 00 37 00 39 00 32 00 31 00))}
		$typelibguid0up = {((30 36 32 36 30 43 45 35 2d 36 31 46 34 2d 34 42 38 31 2d 41 44 38 33 2d 37 44 30 31 43 33 42 33 37 39 32 31) | (30 00 36 00 32 00 36 00 30 00 43 00 45 00 35 00 2d 00 36 00 31 00 46 00 34 00 2d 00 34 00 42 00 38 00 31 00 2d 00 41 00 44 00 38 00 33 00 2d 00 37 00 44 00 30 00 31 00 43 00 33 00 42 00 33 00 37 00 39 00 32 00 31 00))}
		$typelibguid1lo = {((38 37 66 63 37 65 64 65 2d 34 64 61 65 2d 34 66 30 30 2d 61 63 37 37 2d 39 63 34 30 38 30 33 65 38 32 34 38) | (38 00 37 00 66 00 63 00 37 00 65 00 64 00 65 00 2d 00 34 00 64 00 61 00 65 00 2d 00 34 00 66 00 30 00 30 00 2d 00 61 00 63 00 37 00 37 00 2d 00 39 00 63 00 34 00 30 00 38 00 30 00 33 00 65 00 38 00 32 00 34 00 38 00))}
		$typelibguid1up = {((38 37 46 43 37 45 44 45 2d 34 44 41 45 2d 34 46 30 30 2d 41 43 37 37 2d 39 43 34 30 38 30 33 45 38 32 34 38) | (38 00 37 00 46 00 43 00 37 00 45 00 44 00 45 00 2d 00 34 00 44 00 41 00 45 00 2d 00 34 00 46 00 30 00 30 00 2d 00 41 00 43 00 37 00 37 00 2d 00 39 00 43 00 34 00 30 00 38 00 30 00 33 00 45 00 38 00 32 00 34 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Csharp_Loader : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Csharp-Loader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "bf0c3d93-cbea-54c7-b950-fd4e5a600d07"

	strings:
		$typelibguid0lo = {((35 66 64 37 66 39 66 63 2d 30 36 31 38 2d 34 64 64 65 2d 61 36 61 30 2d 39 66 61 65 66 65 39 36 63 38 61 31) | (35 00 66 00 64 00 37 00 66 00 39 00 66 00 63 00 2d 00 30 00 36 00 31 00 38 00 2d 00 34 00 64 00 64 00 65 00 2d 00 61 00 36 00 61 00 30 00 2d 00 39 00 66 00 61 00 65 00 66 00 65 00 39 00 36 00 63 00 38 00 61 00 31 00))}
		$typelibguid0up = {((35 46 44 37 46 39 46 43 2d 30 36 31 38 2d 34 44 44 45 2d 41 36 41 30 2d 39 46 41 45 46 45 39 36 43 38 41 31) | (35 00 46 00 44 00 37 00 46 00 39 00 46 00 43 00 2d 00 30 00 36 00 31 00 38 00 2d 00 34 00 44 00 44 00 45 00 2d 00 41 00 36 00 41 00 30 00 2d 00 39 00 46 00 41 00 45 00 46 00 45 00 39 00 36 00 43 00 38 00 41 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_bantam : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/gellin/bantam"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "0ed3f5e5-d954-51e2-b7fb-4c25ca3d9f10"

	strings:
		$typelibguid0lo = {((31 34 63 37 39 62 64 61 2d 32 63 65 36 2d 34 32 34 64 2d 62 64 34 39 2d 34 66 38 64 36 38 36 33 30 62 37 62) | (31 00 34 00 63 00 37 00 39 00 62 00 64 00 61 00 2d 00 32 00 63 00 65 00 36 00 2d 00 34 00 32 00 34 00 64 00 2d 00 62 00 64 00 34 00 39 00 2d 00 34 00 66 00 38 00 64 00 36 00 38 00 36 00 33 00 30 00 62 00 37 00 62 00))}
		$typelibguid0up = {((31 34 43 37 39 42 44 41 2d 32 43 45 36 2d 34 32 34 44 2d 42 44 34 39 2d 34 46 38 44 36 38 36 33 30 42 37 42) | (31 00 34 00 43 00 37 00 39 00 42 00 44 00 41 00 2d 00 32 00 43 00 45 00 36 00 2d 00 34 00 32 00 34 00 44 00 2d 00 42 00 44 00 34 00 39 00 2d 00 34 00 46 00 38 00 44 00 36 00 38 00 36 00 33 00 30 00 42 00 37 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpTask : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jnqpblc/SharpTask"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "2cdd1a15-c70c-5eea-b5a7-8b4a445b9323"

	strings:
		$typelibguid0lo = {((31 33 65 39 30 61 34 64 2d 62 66 37 61 2d 34 64 35 61 2d 39 39 37 39 2d 38 62 31 31 33 65 33 31 36 36 62 65) | (31 00 33 00 65 00 39 00 30 00 61 00 34 00 64 00 2d 00 62 00 66 00 37 00 61 00 2d 00 34 00 64 00 35 00 61 00 2d 00 39 00 39 00 37 00 39 00 2d 00 38 00 62 00 31 00 31 00 33 00 65 00 33 00 31 00 36 00 36 00 62 00 65 00))}
		$typelibguid0up = {((31 33 45 39 30 41 34 44 2d 42 46 37 41 2d 34 44 35 41 2d 39 39 37 39 2d 38 42 31 31 33 45 33 31 36 36 42 45) | (31 00 33 00 45 00 39 00 30 00 41 00 34 00 44 00 2d 00 42 00 46 00 37 00 41 00 2d 00 34 00 44 00 35 00 41 00 2d 00 39 00 39 00 37 00 39 00 2d 00 38 00 42 00 31 00 31 00 33 00 45 00 33 00 31 00 36 00 36 00 42 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_WindowsPlague : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/RITRedteam/WindowsPlague"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "89729c43-ae01-5c1f-af04-06d7a6c4e7fc"

	strings:
		$typelibguid0lo = {((63 64 66 38 62 30 32 34 2d 37 30 63 39 2d 34 31 33 61 2d 61 64 65 33 2d 38 34 36 61 34 33 38 34 35 65 39 39) | (63 00 64 00 66 00 38 00 62 00 30 00 32 00 34 00 2d 00 37 00 30 00 63 00 39 00 2d 00 34 00 31 00 33 00 61 00 2d 00 61 00 64 00 65 00 33 00 2d 00 38 00 34 00 36 00 61 00 34 00 33 00 38 00 34 00 35 00 65 00 39 00 39 00))}
		$typelibguid0up = {((43 44 46 38 42 30 32 34 2d 37 30 43 39 2d 34 31 33 41 2d 41 44 45 33 2d 38 34 36 41 34 33 38 34 35 45 39 39) | (43 00 44 00 46 00 38 00 42 00 30 00 32 00 34 00 2d 00 37 00 30 00 43 00 39 00 2d 00 34 00 31 00 33 00 41 00 2d 00 41 00 44 00 45 00 33 00 2d 00 38 00 34 00 36 00 41 00 34 00 33 00 38 00 34 00 35 00 45 00 39 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Misc_CSharp : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jnqpblc/Misc-CSharp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "d25fa706-2254-5a82-a961-f57a0daa447c"

	strings:
		$typelibguid0lo = {((64 31 34 32 31 62 61 33 2d 63 36 30 62 2d 34 32 61 30 2d 39 38 66 39 2d 39 32 62 61 34 65 36 35 33 66 33 64) | (64 00 31 00 34 00 32 00 31 00 62 00 61 00 33 00 2d 00 63 00 36 00 30 00 62 00 2d 00 34 00 32 00 61 00 30 00 2d 00 39 00 38 00 66 00 39 00 2d 00 39 00 32 00 62 00 61 00 34 00 65 00 36 00 35 00 33 00 66 00 33 00 64 00))}
		$typelibguid0up = {((44 31 34 32 31 42 41 33 2d 43 36 30 42 2d 34 32 41 30 2d 39 38 46 39 2d 39 32 42 41 34 45 36 35 33 46 33 44) | (44 00 31 00 34 00 32 00 31 00 42 00 41 00 33 00 2d 00 43 00 36 00 30 00 42 00 2d 00 34 00 32 00 41 00 30 00 2d 00 39 00 38 00 46 00 39 00 2d 00 39 00 32 00 42 00 41 00 34 00 45 00 36 00 35 00 33 00 46 00 33 00 44 00))}
		$typelibguid1lo = {((32 61 66 61 63 30 64 64 2d 66 34 36 66 2d 34 66 39 35 2d 38 61 39 33 2d 64 63 31 37 62 34 66 39 61 33 61 31) | (32 00 61 00 66 00 61 00 63 00 30 00 64 00 64 00 2d 00 66 00 34 00 36 00 66 00 2d 00 34 00 66 00 39 00 35 00 2d 00 38 00 61 00 39 00 33 00 2d 00 64 00 63 00 31 00 37 00 62 00 34 00 66 00 39 00 61 00 33 00 61 00 31 00))}
		$typelibguid1up = {((32 41 46 41 43 30 44 44 2d 46 34 36 46 2d 34 46 39 35 2d 38 41 39 33 2d 44 43 31 37 42 34 46 39 41 33 41 31) | (32 00 41 00 46 00 41 00 43 00 30 00 44 00 44 00 2d 00 46 00 34 00 36 00 46 00 2d 00 34 00 46 00 39 00 35 00 2d 00 38 00 41 00 39 00 33 00 2d 00 44 00 43 00 31 00 37 00 42 00 34 00 46 00 39 00 41 00 33 00 41 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpSpray : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jnqpblc/SharpSpray"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "e9312c96-be10-5942-a4da-1fe708cc6699"

	strings:
		$typelibguid0lo = {((35 31 63 36 65 30 31 36 2d 31 34 32 38 2d 34 34 31 64 2d 38 32 65 39 2d 62 62 30 65 62 35 39 39 62 62 63 38) | (35 00 31 00 63 00 36 00 65 00 30 00 31 00 36 00 2d 00 31 00 34 00 32 00 38 00 2d 00 34 00 34 00 31 00 64 00 2d 00 38 00 32 00 65 00 39 00 2d 00 62 00 62 00 30 00 65 00 62 00 35 00 39 00 39 00 62 00 62 00 63 00 38 00))}
		$typelibguid0up = {((35 31 43 36 45 30 31 36 2d 31 34 32 38 2d 34 34 31 44 2d 38 32 45 39 2d 42 42 30 45 42 35 39 39 42 42 43 38) | (35 00 31 00 43 00 36 00 45 00 30 00 31 00 36 00 2d 00 31 00 34 00 32 00 38 00 2d 00 34 00 34 00 31 00 44 00 2d 00 38 00 32 00 45 00 39 00 2d 00 42 00 42 00 30 00 45 00 42 00 35 00 39 00 39 00 42 00 42 00 43 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Obfuscator : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/3xpl01tc0d3r/Obfuscator"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "d9988b00-1f10-5421-8ffe-49849a5d5902"

	strings:
		$typelibguid0lo = {((38 66 65 35 62 38 31 31 2d 61 32 63 62 2d 34 31 37 66 2d 61 66 39 33 2d 36 61 33 63 66 36 36 35 30 61 66 31) | (38 00 66 00 65 00 35 00 62 00 38 00 31 00 31 00 2d 00 61 00 32 00 63 00 62 00 2d 00 34 00 31 00 37 00 66 00 2d 00 61 00 66 00 39 00 33 00 2d 00 36 00 61 00 33 00 63 00 66 00 36 00 36 00 35 00 30 00 61 00 66 00 31 00))}
		$typelibguid0up = {((38 46 45 35 42 38 31 31 2d 41 32 43 42 2d 34 31 37 46 2d 41 46 39 33 2d 36 41 33 43 46 36 36 35 30 41 46 31) | (38 00 46 00 45 00 35 00 42 00 38 00 31 00 31 00 2d 00 41 00 32 00 43 00 42 00 2d 00 34 00 31 00 37 00 46 00 2d 00 41 00 46 00 39 00 33 00 2d 00 36 00 41 00 33 00 43 00 46 00 36 00 36 00 35 00 30 00 41 00 46 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SafetyKatz : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/SafetyKatz"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "5f6d7432-0bb5-5782-98ec-2c2168f2fc1f"

	strings:
		$typelibguid0lo = {((38 33 34 37 65 38 31 62 2d 38 39 66 63 2d 34 32 61 39 2d 62 32 32 63 2d 66 35 39 61 36 61 35 37 32 64 65 63) | (38 00 33 00 34 00 37 00 65 00 38 00 31 00 62 00 2d 00 38 00 39 00 66 00 63 00 2d 00 34 00 32 00 61 00 39 00 2d 00 62 00 32 00 32 00 63 00 2d 00 66 00 35 00 39 00 61 00 36 00 61 00 35 00 37 00 32 00 64 00 65 00 63 00))}
		$typelibguid0up = {((38 33 34 37 45 38 31 42 2d 38 39 46 43 2d 34 32 41 39 2d 42 32 32 43 2d 46 35 39 41 36 41 35 37 32 44 45 43) | (38 00 33 00 34 00 37 00 45 00 38 00 31 00 42 00 2d 00 38 00 39 00 46 00 43 00 2d 00 34 00 32 00 41 00 39 00 2d 00 42 00 32 00 32 00 43 00 2d 00 46 00 35 00 39 00 41 00 36 00 41 00 35 00 37 00 32 00 44 00 45 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Dropless_Malware : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		score = 75
		reference = "https://github.com/NYAN-x-CAT/Dropless-Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "0da3b6d8-2002-590e-a8d5-f6c84acfb083"

	strings:
		$typelibguid0lo = {((32 33 62 37 33 39 66 37 2d 32 33 35 35 2d 34 39 31 65 2d 61 37 63 64 2d 61 38 34 38 35 64 33 39 64 36 64 36) | (32 00 33 00 62 00 37 00 33 00 39 00 66 00 37 00 2d 00 32 00 33 00 35 00 35 00 2d 00 34 00 39 00 31 00 65 00 2d 00 61 00 37 00 63 00 64 00 2d 00 61 00 38 00 34 00 38 00 35 00 64 00 33 00 39 00 64 00 36 00 64 00 36 00))}
		$typelibguid0up = {((32 33 42 37 33 39 46 37 2d 32 33 35 35 2d 34 39 31 45 2d 41 37 43 44 2d 41 38 34 38 35 44 33 39 44 36 44 36) | (32 00 33 00 42 00 37 00 33 00 39 00 46 00 37 00 2d 00 32 00 33 00 35 00 35 00 2d 00 34 00 39 00 31 00 45 00 2d 00 41 00 37 00 43 00 44 00 2d 00 41 00 38 00 34 00 38 00 35 00 44 00 33 00 39 00 44 00 36 00 44 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_UAC_SilentClean : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/EncodeGroup/UAC-SilentClean"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "2dde9632-10c5-5c91-8bd9-2fb80d6f0c49"

	strings:
		$typelibguid0lo = {((39 34 38 31 35 32 61 34 2d 61 34 61 31 2d 34 32 36 30 2d 61 32 32 34 2d 32 30 34 32 35 35 62 66 65 65 37 32) | (39 00 34 00 38 00 31 00 35 00 32 00 61 00 34 00 2d 00 61 00 34 00 61 00 31 00 2d 00 34 00 32 00 36 00 30 00 2d 00 61 00 32 00 32 00 34 00 2d 00 32 00 30 00 34 00 32 00 35 00 35 00 62 00 66 00 65 00 65 00 37 00 32 00))}
		$typelibguid0up = {((39 34 38 31 35 32 41 34 2d 41 34 41 31 2d 34 32 36 30 2d 41 32 32 34 2d 32 30 34 32 35 35 42 46 45 45 37 32) | (39 00 34 00 38 00 31 00 35 00 32 00 41 00 34 00 2d 00 41 00 34 00 41 00 31 00 2d 00 34 00 32 00 36 00 30 00 2d 00 41 00 32 00 32 00 34 00 2d 00 32 00 30 00 34 00 32 00 35 00 35 00 42 00 46 00 45 00 45 00 37 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_DesktopGrabber : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/DesktopGrabber"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "7db07291-d6d4-5527-a879-27f899dbd6fe"

	strings:
		$typelibguid0lo = {((65 36 61 61 30 63 64 35 2d 39 35 33 37 2d 34 37 61 30 2d 38 63 38 35 2d 31 66 62 65 32 38 34 61 34 33 38 30) | (65 00 36 00 61 00 61 00 30 00 63 00 64 00 35 00 2d 00 39 00 35 00 33 00 37 00 2d 00 34 00 37 00 61 00 30 00 2d 00 38 00 63 00 38 00 35 00 2d 00 31 00 66 00 62 00 65 00 32 00 38 00 34 00 61 00 34 00 33 00 38 00 30 00))}
		$typelibguid0up = {((45 36 41 41 30 43 44 35 2d 39 35 33 37 2d 34 37 41 30 2d 38 43 38 35 2d 31 46 42 45 32 38 34 41 34 33 38 30) | (45 00 36 00 41 00 41 00 30 00 43 00 44 00 35 00 2d 00 39 00 35 00 33 00 37 00 2d 00 34 00 37 00 41 00 30 00 2d 00 38 00 43 00 38 00 35 00 2d 00 31 00 46 00 42 00 45 00 32 00 38 00 34 00 41 00 34 00 33 00 38 00 30 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_wsManager : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/guillaC/wsManager"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "b8c330dc-74aa-5a33-8af6-17c9beb8be81"

	strings:
		$typelibguid0lo = {((39 34 38 30 38 30 39 65 2d 35 34 37 32 2d 34 34 66 33 2d 62 30 37 36 2d 64 63 64 66 37 33 37 39 65 37 36 36) | (39 00 34 00 38 00 30 00 38 00 30 00 39 00 65 00 2d 00 35 00 34 00 37 00 32 00 2d 00 34 00 34 00 66 00 33 00 2d 00 62 00 30 00 37 00 36 00 2d 00 64 00 63 00 64 00 66 00 37 00 33 00 37 00 39 00 65 00 37 00 36 00 36 00))}
		$typelibguid0up = {((39 34 38 30 38 30 39 45 2d 35 34 37 32 2d 34 34 46 33 2d 42 30 37 36 2d 44 43 44 46 37 33 37 39 45 37 36 36) | (39 00 34 00 38 00 30 00 38 00 30 00 39 00 45 00 2d 00 35 00 34 00 37 00 32 00 2d 00 34 00 34 00 46 00 33 00 2d 00 42 00 30 00 37 00 36 00 2d 00 44 00 43 00 44 00 46 00 37 00 33 00 37 00 39 00 45 00 37 00 36 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_UglyEXe : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/fashionproof/UglyEXe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "5833e6c5-f078-5eb5-9519-76710d7da0e1"

	strings:
		$typelibguid0lo = {((32 33 33 64 65 34 34 62 2d 34 65 63 31 2d 34 37 35 64 2d 61 37 64 36 2d 31 36 64 61 34 38 64 36 66 63 38 64) | (32 00 33 00 33 00 64 00 65 00 34 00 34 00 62 00 2d 00 34 00 65 00 63 00 31 00 2d 00 34 00 37 00 35 00 64 00 2d 00 61 00 37 00 64 00 36 00 2d 00 31 00 36 00 64 00 61 00 34 00 38 00 64 00 36 00 66 00 63 00 38 00 64 00))}
		$typelibguid0up = {((32 33 33 44 45 34 34 42 2d 34 45 43 31 2d 34 37 35 44 2d 41 37 44 36 2d 31 36 44 41 34 38 44 36 46 43 38 44) | (32 00 33 00 33 00 44 00 45 00 34 00 34 00 42 00 2d 00 34 00 45 00 43 00 31 00 2d 00 34 00 37 00 35 00 44 00 2d 00 41 00 37 00 44 00 36 00 2d 00 31 00 36 00 44 00 41 00 34 00 38 00 44 00 36 00 46 00 43 00 38 00 44 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpDump : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/SharpDump"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "b613092f-9006-5405-b07e-59737410ac1e"

	strings:
		$typelibguid0lo = {((37 39 63 39 62 62 61 33 2d 61 30 65 61 2d 34 33 31 63 2d 38 36 36 63 2d 37 37 30 30 34 38 30 32 64 38 61 30) | (37 00 39 00 63 00 39 00 62 00 62 00 61 00 33 00 2d 00 61 00 30 00 65 00 61 00 2d 00 34 00 33 00 31 00 63 00 2d 00 38 00 36 00 36 00 63 00 2d 00 37 00 37 00 30 00 30 00 34 00 38 00 30 00 32 00 64 00 38 00 61 00 30 00))}
		$typelibguid0up = {((37 39 43 39 42 42 41 33 2d 41 30 45 41 2d 34 33 31 43 2d 38 36 36 43 2d 37 37 30 30 34 38 30 32 44 38 41 30) | (37 00 39 00 43 00 39 00 42 00 42 00 41 00 33 00 2d 00 41 00 30 00 45 00 41 00 2d 00 34 00 33 00 31 00 43 00 2d 00 38 00 36 00 36 00 43 00 2d 00 37 00 37 00 30 00 30 00 34 00 38 00 30 00 32 00 44 00 38 00 41 00 30 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_EducationalRAT : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/securesean/EducationalRAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "b1d54bea-a6c4-5c57-9ee1-7438d503b01d"

	strings:
		$typelibguid0lo = {((38 61 31 38 66 62 63 66 2d 38 63 61 63 2d 34 38 32 64 2d 38 61 62 37 2d 30 38 61 34 34 66 30 65 32 37 38 65) | (38 00 61 00 31 00 38 00 66 00 62 00 63 00 66 00 2d 00 38 00 63 00 61 00 63 00 2d 00 34 00 38 00 32 00 64 00 2d 00 38 00 61 00 62 00 37 00 2d 00 30 00 38 00 61 00 34 00 34 00 66 00 30 00 65 00 32 00 37 00 38 00 65 00))}
		$typelibguid0up = {((38 41 31 38 46 42 43 46 2d 38 43 41 43 2d 34 38 32 44 2d 38 41 42 37 2d 30 38 41 34 34 46 30 45 32 37 38 45) | (38 00 41 00 31 00 38 00 46 00 42 00 43 00 46 00 2d 00 38 00 43 00 41 00 43 00 2d 00 34 00 38 00 32 00 44 00 2d 00 38 00 41 00 42 00 37 00 2d 00 30 00 38 00 41 00 34 00 34 00 46 00 30 00 45 00 32 00 37 00 38 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Stealth_Kid_RAT : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ctsecurity/Stealth-Kid-RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "f26e040a-dcc7-518f-89f2-3333f83fa14a"

	strings:
		$typelibguid0lo = {((62 66 34 33 63 64 33 33 2d 63 32 35 39 2d 34 37 31 31 2d 38 61 30 65 2d 31 61 35 63 36 63 31 33 38 31 31 64) | (62 00 66 00 34 00 33 00 63 00 64 00 33 00 33 00 2d 00 63 00 32 00 35 00 39 00 2d 00 34 00 37 00 31 00 31 00 2d 00 38 00 61 00 30 00 65 00 2d 00 31 00 61 00 35 00 63 00 36 00 63 00 31 00 33 00 38 00 31 00 31 00 64 00))}
		$typelibguid0up = {((42 46 34 33 43 44 33 33 2d 43 32 35 39 2d 34 37 31 31 2d 38 41 30 45 2d 31 41 35 43 36 43 31 33 38 31 31 44) | (42 00 46 00 34 00 33 00 43 00 44 00 33 00 33 00 2d 00 43 00 32 00 35 00 39 00 2d 00 34 00 37 00 31 00 31 00 2d 00 38 00 41 00 30 00 45 00 2d 00 31 00 41 00 35 00 43 00 36 00 43 00 31 00 33 00 38 00 31 00 31 00 44 00))}
		$typelibguid1lo = {((65 35 62 39 64 66 39 62 2d 61 39 65 34 2d 34 37 35 34 2d 38 37 33 31 2d 65 66 63 34 65 32 36 36 37 64 38 38) | (65 00 35 00 62 00 39 00 64 00 66 00 39 00 62 00 2d 00 61 00 39 00 65 00 34 00 2d 00 34 00 37 00 35 00 34 00 2d 00 38 00 37 00 33 00 31 00 2d 00 65 00 66 00 63 00 34 00 65 00 32 00 36 00 36 00 37 00 64 00 38 00 38 00))}
		$typelibguid1up = {((45 35 42 39 44 46 39 42 2d 41 39 45 34 2d 34 37 35 34 2d 38 37 33 31 2d 45 46 43 34 45 32 36 36 37 44 38 38) | (45 00 35 00 42 00 39 00 44 00 46 00 39 00 42 00 2d 00 41 00 39 00 45 00 34 00 2d 00 34 00 37 00 35 00 34 00 2d 00 38 00 37 00 33 00 31 00 2d 00 45 00 46 00 43 00 34 00 45 00 32 00 36 00 36 00 37 00 44 00 38 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpCradle : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/anthemtotheego/SharpCradle"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "e2123a73-2609-559d-a122-923ebf8fd668"

	strings:
		$typelibguid0lo = {((66 37 30 64 32 62 37 31 2d 34 61 61 65 2d 34 62 32 34 2d 39 64 61 65 2d 35 35 62 63 38 31 39 63 37 38 62 62) | (66 00 37 00 30 00 64 00 32 00 62 00 37 00 31 00 2d 00 34 00 61 00 61 00 65 00 2d 00 34 00 62 00 32 00 34 00 2d 00 39 00 64 00 61 00 65 00 2d 00 35 00 35 00 62 00 63 00 38 00 31 00 39 00 63 00 37 00 38 00 62 00 62 00))}
		$typelibguid0up = {((46 37 30 44 32 42 37 31 2d 34 41 41 45 2d 34 42 32 34 2d 39 44 41 45 2d 35 35 42 43 38 31 39 43 37 38 42 42) | (46 00 37 00 30 00 44 00 32 00 42 00 37 00 31 00 2d 00 34 00 41 00 41 00 45 00 2d 00 34 00 42 00 32 00 34 00 2d 00 39 00 44 00 41 00 45 00 2d 00 35 00 35 00 42 00 43 00 38 00 31 00 39 00 43 00 37 00 38 00 42 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_BypassUAC : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/cnsimo/BypassUAC"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "327f581e-1d8c-5d20-bdd7-a29810c619c9"

	strings:
		$typelibguid0lo = {((34 65 37 63 31 34 30 64 2d 62 63 63 34 2d 34 62 31 35 2d 38 63 31 31 2d 61 64 62 34 65 35 34 63 63 33 39 61) | (34 00 65 00 37 00 63 00 31 00 34 00 30 00 64 00 2d 00 62 00 63 00 63 00 34 00 2d 00 34 00 62 00 31 00 35 00 2d 00 38 00 63 00 31 00 31 00 2d 00 61 00 64 00 62 00 34 00 65 00 35 00 34 00 63 00 63 00 33 00 39 00 61 00))}
		$typelibguid0up = {((34 45 37 43 31 34 30 44 2d 42 43 43 34 2d 34 42 31 35 2d 38 43 31 31 2d 41 44 42 34 45 35 34 43 43 33 39 41) | (34 00 45 00 37 00 43 00 31 00 34 00 30 00 44 00 2d 00 42 00 43 00 43 00 34 00 2d 00 34 00 42 00 31 00 35 00 2d 00 38 00 43 00 31 00 31 00 2d 00 41 00 44 00 42 00 34 00 45 00 35 00 34 00 43 00 43 00 33 00 39 00 41 00))}
		$typelibguid1lo = {((63 65 63 35 35 33 61 37 2d 31 33 37 30 2d 34 62 62 63 2d 39 61 61 65 2d 62 32 66 35 64 62 64 65 33 32 62 30) | (63 00 65 00 63 00 35 00 35 00 33 00 61 00 37 00 2d 00 31 00 33 00 37 00 30 00 2d 00 34 00 62 00 62 00 63 00 2d 00 39 00 61 00 61 00 65 00 2d 00 62 00 32 00 66 00 35 00 64 00 62 00 64 00 65 00 33 00 32 00 62 00 30 00))}
		$typelibguid1up = {((43 45 43 35 35 33 41 37 2d 31 33 37 30 2d 34 42 42 43 2d 39 41 41 45 2d 42 32 46 35 44 42 44 45 33 32 42 30) | (43 00 45 00 43 00 35 00 35 00 33 00 41 00 37 00 2d 00 31 00 33 00 37 00 30 00 2d 00 34 00 42 00 42 00 43 00 2d 00 39 00 41 00 41 00 45 00 2d 00 42 00 32 00 46 00 35 00 44 00 42 00 44 00 45 00 33 00 32 00 42 00 30 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_hanzoInjection : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/P0cL4bs/hanzoInjection"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "c432bf68-49bf-57c7-bbfa-7bd2f3506c52"

	strings:
		$typelibguid0lo = {((33 32 65 32 32 65 32 35 2d 62 30 33 33 2d 34 64 39 38 2d 61 30 62 33 2d 33 64 32 63 33 38 35 30 66 30 36 63) | (33 00 32 00 65 00 32 00 32 00 65 00 32 00 35 00 2d 00 62 00 30 00 33 00 33 00 2d 00 34 00 64 00 39 00 38 00 2d 00 61 00 30 00 62 00 33 00 2d 00 33 00 64 00 32 00 63 00 33 00 38 00 35 00 30 00 66 00 30 00 36 00 63 00))}
		$typelibguid0up = {((33 32 45 32 32 45 32 35 2d 42 30 33 33 2d 34 44 39 38 2d 41 30 42 33 2d 33 44 32 43 33 38 35 30 46 30 36 43) | (33 00 32 00 45 00 32 00 32 00 45 00 32 00 35 00 2d 00 42 00 30 00 33 00 33 00 2d 00 34 00 44 00 39 00 38 00 2d 00 41 00 30 00 42 00 33 00 2d 00 33 00 44 00 32 00 43 00 33 00 38 00 35 00 30 00 46 00 30 00 36 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_clr_meterpreter : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/OJ/clr-meterpreter"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "1d8a9717-4d80-5fb1-9c57-9b5f6c5a18b0"

	strings:
		$typelibguid0lo = {((36 38 34 30 62 32 34 39 2d 31 61 30 65 2d 34 33 33 62 2d 62 65 37 39 2d 61 39 32 37 36 39 36 65 61 34 62 33) | (36 00 38 00 34 00 30 00 62 00 32 00 34 00 39 00 2d 00 31 00 61 00 30 00 65 00 2d 00 34 00 33 00 33 00 62 00 2d 00 62 00 65 00 37 00 39 00 2d 00 61 00 39 00 32 00 37 00 36 00 39 00 36 00 65 00 61 00 34 00 62 00 33 00))}
		$typelibguid0up = {((36 38 34 30 42 32 34 39 2d 31 41 30 45 2d 34 33 33 42 2d 42 45 37 39 2d 41 39 32 37 36 39 36 45 41 34 42 33) | (36 00 38 00 34 00 30 00 42 00 32 00 34 00 39 00 2d 00 31 00 41 00 30 00 45 00 2d 00 34 00 33 00 33 00 42 00 2d 00 42 00 45 00 37 00 39 00 2d 00 41 00 39 00 32 00 37 00 36 00 39 00 36 00 45 00 41 00 34 00 42 00 33 00))}
		$typelibguid1lo = {((36 37 63 30 39 64 33 37 2d 61 63 31 38 2d 34 66 31 35 2d 38 64 64 36 2d 62 35 64 61 37 32 31 63 30 64 66 36) | (36 00 37 00 63 00 30 00 39 00 64 00 33 00 37 00 2d 00 61 00 63 00 31 00 38 00 2d 00 34 00 66 00 31 00 35 00 2d 00 38 00 64 00 64 00 36 00 2d 00 62 00 35 00 64 00 61 00 37 00 32 00 31 00 63 00 30 00 64 00 66 00 36 00))}
		$typelibguid1up = {((36 37 43 30 39 44 33 37 2d 41 43 31 38 2d 34 46 31 35 2d 38 44 44 36 2d 42 35 44 41 37 32 31 43 30 44 46 36) | (36 00 37 00 43 00 30 00 39 00 44 00 33 00 37 00 2d 00 41 00 43 00 31 00 38 00 2d 00 34 00 46 00 31 00 35 00 2d 00 38 00 44 00 44 00 36 00 2d 00 42 00 35 00 44 00 41 00 37 00 32 00 31 00 43 00 30 00 44 00 46 00 36 00))}
		$typelibguid2lo = {((65 30 35 64 30 64 65 62 2d 64 37 32 34 2d 34 34 34 38 2d 38 63 34 63 2d 35 33 64 36 61 38 65 36 37 30 66 33) | (65 00 30 00 35 00 64 00 30 00 64 00 65 00 62 00 2d 00 64 00 37 00 32 00 34 00 2d 00 34 00 34 00 34 00 38 00 2d 00 38 00 63 00 34 00 63 00 2d 00 35 00 33 00 64 00 36 00 61 00 38 00 65 00 36 00 37 00 30 00 66 00 33 00))}
		$typelibguid2up = {((45 30 35 44 30 44 45 42 2d 44 37 32 34 2d 34 34 34 38 2d 38 43 34 43 2d 35 33 44 36 41 38 45 36 37 30 46 33) | (45 00 30 00 35 00 44 00 30 00 44 00 45 00 42 00 2d 00 44 00 37 00 32 00 34 00 2d 00 34 00 34 00 34 00 38 00 2d 00 38 00 43 00 34 00 43 00 2d 00 35 00 33 00 44 00 36 00 41 00 38 00 45 00 36 00 37 00 30 00 46 00 33 00))}
		$typelibguid3lo = {((63 33 63 63 37 32 62 66 2d 36 32 61 32 2d 34 30 33 34 2d 61 66 36 36 2d 65 36 36 64 61 37 33 65 34 32 35 64) | (63 00 33 00 63 00 63 00 37 00 32 00 62 00 66 00 2d 00 36 00 32 00 61 00 32 00 2d 00 34 00 30 00 33 00 34 00 2d 00 61 00 66 00 36 00 36 00 2d 00 65 00 36 00 36 00 64 00 61 00 37 00 33 00 65 00 34 00 32 00 35 00 64 00))}
		$typelibguid3up = {((43 33 43 43 37 32 42 46 2d 36 32 41 32 2d 34 30 33 34 2d 41 46 36 36 2d 45 36 36 44 41 37 33 45 34 32 35 44) | (43 00 33 00 43 00 43 00 37 00 32 00 42 00 46 00 2d 00 36 00 32 00 41 00 32 00 2d 00 34 00 30 00 33 00 34 00 2d 00 41 00 46 00 36 00 36 00 2d 00 45 00 36 00 36 00 44 00 41 00 37 00 33 00 45 00 34 00 32 00 35 00 44 00))}
		$typelibguid4lo = {((37 61 63 65 33 37 36 32 2d 64 38 65 31 2d 34 39 36 39 2d 61 35 61 30 2d 64 63 61 66 37 62 31 38 31 36 34 65) | (37 00 61 00 63 00 65 00 33 00 37 00 36 00 32 00 2d 00 64 00 38 00 65 00 31 00 2d 00 34 00 39 00 36 00 39 00 2d 00 61 00 35 00 61 00 30 00 2d 00 64 00 63 00 61 00 66 00 37 00 62 00 31 00 38 00 31 00 36 00 34 00 65 00))}
		$typelibguid4up = {((37 41 43 45 33 37 36 32 2d 44 38 45 31 2d 34 39 36 39 2d 41 35 41 30 2d 44 43 41 46 37 42 31 38 31 36 34 45) | (37 00 41 00 43 00 45 00 33 00 37 00 36 00 32 00 2d 00 44 00 38 00 45 00 31 00 2d 00 34 00 39 00 36 00 39 00 2d 00 41 00 35 00 41 00 30 00 2d 00 44 00 43 00 41 00 46 00 37 00 42 00 31 00 38 00 31 00 36 00 34 00 45 00))}
		$typelibguid5lo = {((33 32 39 36 65 34 61 33 2d 39 34 62 35 2d 34 32 33 32 2d 62 34 32 33 2d 34 34 66 34 63 37 34 32 31 63 62 33) | (33 00 32 00 39 00 36 00 65 00 34 00 61 00 33 00 2d 00 39 00 34 00 62 00 35 00 2d 00 34 00 32 00 33 00 32 00 2d 00 62 00 34 00 32 00 33 00 2d 00 34 00 34 00 66 00 34 00 63 00 37 00 34 00 32 00 31 00 63 00 62 00 33 00))}
		$typelibguid5up = {((33 32 39 36 45 34 41 33 2d 39 34 42 35 2d 34 32 33 32 2d 42 34 32 33 2d 34 34 46 34 43 37 34 32 31 43 42 33) | (33 00 32 00 39 00 36 00 45 00 34 00 41 00 33 00 2d 00 39 00 34 00 42 00 35 00 2d 00 34 00 32 00 33 00 32 00 2d 00 42 00 34 00 32 00 33 00 2d 00 34 00 34 00 46 00 34 00 43 00 37 00 34 00 32 00 31 00 43 00 42 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_BYTAGE : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/KNIF/BYTAGE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "4f87ca2c-3ac1-5733-893e-79665b80ffc3"

	strings:
		$typelibguid0lo = {((38 65 34 36 62 61 35 36 2d 65 38 37 37 2d 34 64 65 63 2d 62 65 31 65 2d 33 39 34 63 62 31 62 35 62 39 64 65) | (38 00 65 00 34 00 36 00 62 00 61 00 35 00 36 00 2d 00 65 00 38 00 37 00 37 00 2d 00 34 00 64 00 65 00 63 00 2d 00 62 00 65 00 31 00 65 00 2d 00 33 00 39 00 34 00 63 00 62 00 31 00 62 00 35 00 62 00 39 00 64 00 65 00))}
		$typelibguid0up = {((38 45 34 36 42 41 35 36 2d 45 38 37 37 2d 34 44 45 43 2d 42 45 31 45 2d 33 39 34 43 42 31 42 35 42 39 44 45) | (38 00 45 00 34 00 36 00 42 00 41 00 35 00 36 00 2d 00 45 00 38 00 37 00 37 00 2d 00 34 00 44 00 45 00 43 00 2d 00 42 00 45 00 31 00 45 00 2d 00 33 00 39 00 34 00 43 00 42 00 31 00 42 00 35 00 42 00 39 00 44 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_MultiOS_ReverseShell : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/belane/MultiOS_ReverseShell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "f54bcb1a-b0cd-5988-bf1d-4fa6c012d6b9"

	strings:
		$typelibguid0lo = {((64 66 30 64 64 37 61 31 2d 39 66 36 62 2d 34 62 30 66 2d 38 30 31 65 2d 65 31 37 65 37 33 62 30 38 30 31 64) | (64 00 66 00 30 00 64 00 64 00 37 00 61 00 31 00 2d 00 39 00 66 00 36 00 62 00 2d 00 34 00 62 00 30 00 66 00 2d 00 38 00 30 00 31 00 65 00 2d 00 65 00 31 00 37 00 65 00 37 00 33 00 62 00 30 00 38 00 30 00 31 00 64 00))}
		$typelibguid0up = {((44 46 30 44 44 37 41 31 2d 39 46 36 42 2d 34 42 30 46 2d 38 30 31 45 2d 45 31 37 45 37 33 42 30 38 30 31 44) | (44 00 46 00 30 00 44 00 44 00 37 00 41 00 31 00 2d 00 39 00 46 00 36 00 42 00 2d 00 34 00 42 00 30 00 46 00 2d 00 38 00 30 00 31 00 45 00 2d 00 45 00 31 00 37 00 45 00 37 00 33 00 42 00 30 00 38 00 30 00 31 00 44 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_HideFromAMSI : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0r13lc0ch4v1/HideFromAMSI"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "0fa1ce82-b662-5e18-a5da-8359c96cd6e9"

	strings:
		$typelibguid0lo = {((62 39 31 64 32 64 34 34 2d 37 39 34 63 2d 34 39 62 38 2d 38 61 37 35 2d 32 66 62 65 63 33 66 65 33 66 65 33) | (62 00 39 00 31 00 64 00 32 00 64 00 34 00 34 00 2d 00 37 00 39 00 34 00 63 00 2d 00 34 00 39 00 62 00 38 00 2d 00 38 00 61 00 37 00 35 00 2d 00 32 00 66 00 62 00 65 00 63 00 33 00 66 00 65 00 33 00 66 00 65 00 33 00))}
		$typelibguid0up = {((42 39 31 44 32 44 34 34 2d 37 39 34 43 2d 34 39 42 38 2d 38 41 37 35 2d 32 46 42 45 43 33 46 45 33 46 45 33) | (42 00 39 00 31 00 44 00 32 00 44 00 34 00 34 00 2d 00 37 00 39 00 34 00 43 00 2d 00 34 00 39 00 42 00 38 00 2d 00 38 00 41 00 37 00 35 00 2d 00 32 00 46 00 42 00 45 00 43 00 33 00 46 00 45 00 33 00 46 00 45 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_DotNetAVBypass_Master : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/lockfale/DotNetAVBypass-Master"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "4004271b-4fbe-58bb-9613-a077e76324b3"

	strings:
		$typelibguid0lo = {((34 38 35 34 63 38 64 63 2d 38 32 62 30 2d 34 31 36 32 2d 38 36 65 30 2d 61 35 62 62 63 62 63 31 30 32 34 30) | (34 00 38 00 35 00 34 00 63 00 38 00 64 00 63 00 2d 00 38 00 32 00 62 00 30 00 2d 00 34 00 31 00 36 00 32 00 2d 00 38 00 36 00 65 00 30 00 2d 00 61 00 35 00 62 00 62 00 63 00 62 00 63 00 31 00 30 00 32 00 34 00 30 00))}
		$typelibguid0up = {((34 38 35 34 43 38 44 43 2d 38 32 42 30 2d 34 31 36 32 2d 38 36 45 30 2d 41 35 42 42 43 42 43 31 30 32 34 30) | (34 00 38 00 35 00 34 00 43 00 38 00 44 00 43 00 2d 00 38 00 32 00 42 00 30 00 2d 00 34 00 31 00 36 00 32 00 2d 00 38 00 36 00 45 00 30 00 2d 00 41 00 35 00 42 00 42 00 43 00 42 00 43 00 31 00 30 00 32 00 34 00 30 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpDPAPI : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/SharpDPAPI"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "1394323f-b336-548f-925c-c276d439e9eb"

	strings:
		$typelibguid0lo = {((35 66 30 32 36 63 32 37 2d 66 38 65 36 2d 34 30 35 32 2d 62 32 33 31 2d 38 34 35 31 63 36 61 37 33 38 33 38) | (35 00 66 00 30 00 32 00 36 00 63 00 32 00 37 00 2d 00 66 00 38 00 65 00 36 00 2d 00 34 00 30 00 35 00 32 00 2d 00 62 00 32 00 33 00 31 00 2d 00 38 00 34 00 35 00 31 00 63 00 36 00 61 00 37 00 33 00 38 00 33 00 38 00))}
		$typelibguid0up = {((35 46 30 32 36 43 32 37 2d 46 38 45 36 2d 34 30 35 32 2d 42 32 33 31 2d 38 34 35 31 43 36 41 37 33 38 33 38) | (35 00 46 00 30 00 32 00 36 00 43 00 32 00 37 00 2d 00 46 00 38 00 45 00 36 00 2d 00 34 00 30 00 35 00 32 00 2d 00 42 00 32 00 33 00 31 00 2d 00 38 00 34 00 35 00 31 00 43 00 36 00 41 00 37 00 33 00 38 00 33 00 38 00))}
		$typelibguid1lo = {((32 66 30 30 61 30 35 62 2d 32 36 33 64 2d 34 66 63 63 2d 38 34 36 62 2d 64 61 38 32 62 64 36 38 34 36 30 33) | (32 00 66 00 30 00 30 00 61 00 30 00 35 00 62 00 2d 00 32 00 36 00 33 00 64 00 2d 00 34 00 66 00 63 00 63 00 2d 00 38 00 34 00 36 00 62 00 2d 00 64 00 61 00 38 00 32 00 62 00 64 00 36 00 38 00 34 00 36 00 30 00 33 00))}
		$typelibguid1up = {((32 46 30 30 41 30 35 42 2d 32 36 33 44 2d 34 46 43 43 2d 38 34 36 42 2d 44 41 38 32 42 44 36 38 34 36 30 33) | (32 00 46 00 30 00 30 00 41 00 30 00 35 00 42 00 2d 00 32 00 36 00 33 00 44 00 2d 00 34 00 46 00 43 00 43 00 2d 00 38 00 34 00 36 00 42 00 2d 00 44 00 41 00 38 00 32 00 42 00 44 00 36 00 38 00 34 00 36 00 30 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Telegra_Csharp_C2 : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/sf197/Telegra_Csharp_C2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "495a5f3e-cf05-5a66-b01c-8176ded88768"

	strings:
		$typelibguid0lo = {((31 64 37 39 66 61 62 63 2d 32 62 61 32 2d 34 36 30 34 2d 61 34 62 36 2d 30 34 35 30 32 37 33 34 30 63 38 35) | (31 00 64 00 37 00 39 00 66 00 61 00 62 00 63 00 2d 00 32 00 62 00 61 00 32 00 2d 00 34 00 36 00 30 00 34 00 2d 00 61 00 34 00 62 00 36 00 2d 00 30 00 34 00 35 00 30 00 32 00 37 00 33 00 34 00 30 00 63 00 38 00 35 00))}
		$typelibguid0up = {((31 44 37 39 46 41 42 43 2d 32 42 41 32 2d 34 36 30 34 2d 41 34 42 36 2d 30 34 35 30 32 37 33 34 30 43 38 35) | (31 00 44 00 37 00 39 00 46 00 41 00 42 00 43 00 2d 00 32 00 42 00 41 00 32 00 2d 00 34 00 36 00 30 00 34 00 2d 00 41 00 34 00 42 00 36 00 2d 00 30 00 34 00 35 00 30 00 32 00 37 00 33 00 34 00 30 00 43 00 38 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpCompile : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/SpiderLabs/SharpCompile"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "c5e053c4-1c90-581a-a6c3-087b252254b2"

	strings:
		$typelibguid0lo = {((36 33 66 38 31 62 37 33 2d 66 66 31 38 2d 34 61 33 36 2d 62 30 39 35 2d 66 64 63 62 34 37 37 36 64 61 34 63) | (36 00 33 00 66 00 38 00 31 00 62 00 37 00 33 00 2d 00 66 00 66 00 31 00 38 00 2d 00 34 00 61 00 33 00 36 00 2d 00 62 00 30 00 39 00 35 00 2d 00 66 00 64 00 63 00 62 00 34 00 37 00 37 00 36 00 64 00 61 00 34 00 63 00))}
		$typelibguid0up = {((36 33 46 38 31 42 37 33 2d 46 46 31 38 2d 34 41 33 36 2d 42 30 39 35 2d 46 44 43 42 34 37 37 36 44 41 34 43) | (36 00 33 00 46 00 38 00 31 00 42 00 37 00 33 00 2d 00 46 00 46 00 31 00 38 00 2d 00 34 00 41 00 33 00 36 00 2d 00 42 00 30 00 39 00 35 00 2d 00 46 00 44 00 43 00 42 00 34 00 37 00 37 00 36 00 44 00 41 00 34 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Carbuncle : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/checkymander/Carbuncle"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "4a87882e-570b-5b40-a8e3-47ebac01d257"

	strings:
		$typelibguid0lo = {((33 66 32 33 39 62 37 33 2d 38 38 61 65 2d 34 31 33 62 2d 62 38 63 38 2d 63 30 31 61 33 35 61 30 64 39 32 65) | (33 00 66 00 32 00 33 00 39 00 62 00 37 00 33 00 2d 00 38 00 38 00 61 00 65 00 2d 00 34 00 31 00 33 00 62 00 2d 00 62 00 38 00 63 00 38 00 2d 00 63 00 30 00 31 00 61 00 33 00 35 00 61 00 30 00 64 00 39 00 32 00 65 00))}
		$typelibguid0up = {((33 46 32 33 39 42 37 33 2d 38 38 41 45 2d 34 31 33 42 2d 42 38 43 38 2d 43 30 31 41 33 35 41 30 44 39 32 45) | (33 00 46 00 32 00 33 00 39 00 42 00 37 00 33 00 2d 00 38 00 38 00 41 00 45 00 2d 00 34 00 31 00 33 00 42 00 2d 00 42 00 38 00 43 00 38 00 2d 00 43 00 30 00 31 00 41 00 33 00 35 00 41 00 30 00 44 00 39 00 32 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_OSSFileTool : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/B1eed/OSSFileTool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "fa9aeae1-2aa5-51af-81e2-22a1b6fcda81"

	strings:
		$typelibguid0lo = {((32 30 37 61 63 61 35 64 2d 64 63 64 36 2d 34 31 66 62 2d 38 34 36 35 2d 35 38 62 33 39 65 66 63 64 65 38 62) | (32 00 30 00 37 00 61 00 63 00 61 00 35 00 64 00 2d 00 64 00 63 00 64 00 36 00 2d 00 34 00 31 00 66 00 62 00 2d 00 38 00 34 00 36 00 35 00 2d 00 35 00 38 00 62 00 33 00 39 00 65 00 66 00 63 00 64 00 65 00 38 00 62 00))}
		$typelibguid0up = {((32 30 37 41 43 41 35 44 2d 44 43 44 36 2d 34 31 46 42 2d 38 34 36 35 2d 35 38 42 33 39 45 46 43 44 45 38 42) | (32 00 30 00 37 00 41 00 43 00 41 00 35 00 44 00 2d 00 44 00 43 00 44 00 36 00 2d 00 34 00 31 00 46 00 42 00 2d 00 38 00 34 00 36 00 35 00 2d 00 35 00 38 00 42 00 33 00 39 00 45 00 46 00 43 00 44 00 45 00 38 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Rubeus : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/Rubeus"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "54638fe4-84b5-51a8-8c88-9c50ab09ff49"

	strings:
		$typelibguid0lo = {((36 35 38 63 38 62 37 66 2d 33 36 36 34 2d 34 61 39 35 2d 39 35 37 32 2d 61 33 65 35 38 37 31 64 66 63 30 36) | (36 00 35 00 38 00 63 00 38 00 62 00 37 00 66 00 2d 00 33 00 36 00 36 00 34 00 2d 00 34 00 61 00 39 00 35 00 2d 00 39 00 35 00 37 00 32 00 2d 00 61 00 33 00 65 00 35 00 38 00 37 00 31 00 64 00 66 00 63 00 30 00 36 00))}
		$typelibguid0up = {((36 35 38 43 38 42 37 46 2d 33 36 36 34 2d 34 41 39 35 2d 39 35 37 32 2d 41 33 45 35 38 37 31 44 46 43 30 36) | (36 00 35 00 38 00 43 00 38 00 42 00 37 00 46 00 2d 00 33 00 36 00 36 00 34 00 2d 00 34 00 41 00 39 00 35 00 2d 00 39 00 35 00 37 00 32 00 2d 00 41 00 33 00 45 00 35 00 38 00 37 00 31 00 44 00 46 00 43 00 30 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Simple_Loader : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/cribdragg3r/Simple-Loader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "4c26aaf9-187d-5990-b956-1bbf630411f0"

	strings:
		$typelibguid0lo = {((30 33 35 61 65 37 31 31 2d 63 30 65 39 2d 34 31 64 61 2d 61 39 61 32 2d 36 35 32 33 38 36 35 65 38 36 39 34) | (30 00 33 00 35 00 61 00 65 00 37 00 31 00 31 00 2d 00 63 00 30 00 65 00 39 00 2d 00 34 00 31 00 64 00 61 00 2d 00 61 00 39 00 61 00 32 00 2d 00 36 00 35 00 32 00 33 00 38 00 36 00 35 00 65 00 38 00 36 00 39 00 34 00))}
		$typelibguid0up = {((30 33 35 41 45 37 31 31 2d 43 30 45 39 2d 34 31 44 41 2d 41 39 41 32 2d 36 35 32 33 38 36 35 45 38 36 39 34) | (30 00 33 00 35 00 41 00 45 00 37 00 31 00 31 00 2d 00 43 00 30 00 45 00 39 00 2d 00 34 00 31 00 44 00 41 00 2d 00 41 00 39 00 41 00 32 00 2d 00 36 00 35 00 32 00 33 00 38 00 36 00 35 00 45 00 38 00 36 00 39 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Minidump : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/3xpl01tc0d3r/Minidump"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "51f64c64-f3fa-5543-83fc-5f0bf881ef03"

	strings:
		$typelibguid0lo = {((31 35 63 32 34 31 61 61 2d 65 37 33 63 2d 34 62 33 38 2d 39 34 38 39 2d 39 61 33 34 34 61 63 32 36 38 61 33) | (31 00 35 00 63 00 32 00 34 00 31 00 61 00 61 00 2d 00 65 00 37 00 33 00 63 00 2d 00 34 00 62 00 33 00 38 00 2d 00 39 00 34 00 38 00 39 00 2d 00 39 00 61 00 33 00 34 00 34 00 61 00 63 00 32 00 36 00 38 00 61 00 33 00))}
		$typelibguid0up = {((31 35 43 32 34 31 41 41 2d 45 37 33 43 2d 34 42 33 38 2d 39 34 38 39 2d 39 41 33 34 34 41 43 32 36 38 41 33) | (31 00 35 00 43 00 32 00 34 00 31 00 41 00 41 00 2d 00 45 00 37 00 33 00 43 00 2d 00 34 00 42 00 33 00 38 00 2d 00 39 00 34 00 38 00 39 00 2d 00 39 00 41 00 33 00 34 00 34 00 41 00 43 00 32 00 36 00 38 00 41 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpBypassUAC : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FatRodzianko/SharpBypassUAC"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "474d40aa-4bcc-58b5-a129-40bbd3a89e99"

	strings:
		$typelibguid0lo = {((30 64 35 38 38 63 38 36 2d 63 36 38 30 2d 34 62 30 64 2d 39 61 65 64 2d 34 31 38 66 31 62 62 39 34 32 35 35) | (30 00 64 00 35 00 38 00 38 00 63 00 38 00 36 00 2d 00 63 00 36 00 38 00 30 00 2d 00 34 00 62 00 30 00 64 00 2d 00 39 00 61 00 65 00 64 00 2d 00 34 00 31 00 38 00 66 00 31 00 62 00 62 00 39 00 34 00 32 00 35 00 35 00))}
		$typelibguid0up = {((30 44 35 38 38 43 38 36 2d 43 36 38 30 2d 34 42 30 44 2d 39 41 45 44 2d 34 31 38 46 31 42 42 39 34 32 35 35) | (30 00 44 00 35 00 38 00 38 00 43 00 38 00 36 00 2d 00 43 00 36 00 38 00 30 00 2d 00 34 00 42 00 30 00 44 00 2d 00 39 00 41 00 45 00 44 00 2d 00 34 00 31 00 38 00 46 00 31 00 42 00 42 00 39 00 34 00 32 00 35 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpPack : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Lexus89/SharpPack"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "633d074a-b8c2-5148-ad80-6226b99be818"

	strings:
		$typelibguid1lo = {((62 35 39 63 37 37 34 31 2d 64 35 32 32 2d 34 61 34 31 2d 62 66 34 64 2d 39 62 61 64 64 64 65 62 62 38 34 61) | (62 00 35 00 39 00 63 00 37 00 37 00 34 00 31 00 2d 00 64 00 35 00 32 00 32 00 2d 00 34 00 61 00 34 00 31 00 2d 00 62 00 66 00 34 00 64 00 2d 00 39 00 62 00 61 00 64 00 64 00 64 00 65 00 62 00 62 00 38 00 34 00 61 00))}
		$typelibguid1up = {((42 35 39 43 37 37 34 31 2d 44 35 32 32 2d 34 41 34 31 2d 42 46 34 44 2d 39 42 41 44 44 44 45 42 42 38 34 41) | (42 00 35 00 39 00 43 00 37 00 37 00 34 00 31 00 2d 00 44 00 35 00 32 00 32 00 2d 00 34 00 41 00 34 00 31 00 2d 00 42 00 46 00 34 00 44 00 2d 00 39 00 42 00 41 00 44 00 44 00 44 00 45 00 42 00 42 00 38 00 34 00 41 00))}
		$typelibguid2lo = {((66 64 36 62 64 66 37 61 2d 66 65 66 34 2d 34 62 32 38 2d 39 30 32 37 2d 35 62 66 37 35 30 66 30 38 30 34 38) | (66 00 64 00 36 00 62 00 64 00 66 00 37 00 61 00 2d 00 66 00 65 00 66 00 34 00 2d 00 34 00 62 00 32 00 38 00 2d 00 39 00 30 00 32 00 37 00 2d 00 35 00 62 00 66 00 37 00 35 00 30 00 66 00 30 00 38 00 30 00 34 00 38 00))}
		$typelibguid2up = {((46 44 36 42 44 46 37 41 2d 46 45 46 34 2d 34 42 32 38 2d 39 30 32 37 2d 35 42 46 37 35 30 46 30 38 30 34 38) | (46 00 44 00 36 00 42 00 44 00 46 00 37 00 41 00 2d 00 46 00 45 00 46 00 34 00 2d 00 34 00 42 00 32 00 38 00 2d 00 39 00 30 00 32 00 37 00 2d 00 35 00 42 00 46 00 37 00 35 00 30 00 46 00 30 00 38 00 30 00 34 00 38 00))}
		$typelibguid3lo = {((36 64 64 32 32 38 38 30 2d 64 61 63 35 2d 34 62 34 64 2d 39 63 39 31 2d 38 63 33 35 63 63 37 62 38 31 38 30) | (36 00 64 00 64 00 32 00 32 00 38 00 38 00 30 00 2d 00 64 00 61 00 63 00 35 00 2d 00 34 00 62 00 34 00 64 00 2d 00 39 00 63 00 39 00 31 00 2d 00 38 00 63 00 33 00 35 00 63 00 63 00 37 00 62 00 38 00 31 00 38 00 30 00))}
		$typelibguid3up = {((36 44 44 32 32 38 38 30 2d 44 41 43 35 2d 34 42 34 44 2d 39 43 39 31 2d 38 43 33 35 43 43 37 42 38 31 38 30) | (36 00 44 00 44 00 32 00 32 00 38 00 38 00 30 00 2d 00 44 00 41 00 43 00 35 00 2d 00 34 00 42 00 34 00 44 00 2d 00 39 00 43 00 39 00 31 00 2d 00 38 00 43 00 33 00 35 00 43 00 43 00 37 00 42 00 38 00 31 00 38 00 30 00))}
		$typelibguid5lo = {((66 33 30 33 37 35 38 37 2d 31 61 33 62 2d 34 31 66 31 2d 61 61 37 31 2d 62 30 32 36 65 66 64 62 32 61 38 32) | (66 00 33 00 30 00 33 00 37 00 35 00 38 00 37 00 2d 00 31 00 61 00 33 00 62 00 2d 00 34 00 31 00 66 00 31 00 2d 00 61 00 61 00 37 00 31 00 2d 00 62 00 30 00 32 00 36 00 65 00 66 00 64 00 62 00 32 00 61 00 38 00 32 00))}
		$typelibguid5up = {((46 33 30 33 37 35 38 37 2d 31 41 33 42 2d 34 31 46 31 2d 41 41 37 31 2d 42 30 32 36 45 46 44 42 32 41 38 32) | (46 00 33 00 30 00 33 00 37 00 35 00 38 00 37 00 2d 00 31 00 41 00 33 00 42 00 2d 00 34 00 31 00 46 00 31 00 2d 00 41 00 41 00 37 00 31 00 2d 00 42 00 30 00 32 00 36 00 45 00 46 00 44 00 42 00 32 00 41 00 38 00 32 00))}
		$typelibguid6lo = {((34 31 61 39 30 61 36 61 2d 66 39 65 64 2d 34 61 32 66 2d 38 34 34 38 2d 64 35 34 34 65 63 31 66 64 37 35 33) | (34 00 31 00 61 00 39 00 30 00 61 00 36 00 61 00 2d 00 66 00 39 00 65 00 64 00 2d 00 34 00 61 00 32 00 66 00 2d 00 38 00 34 00 34 00 38 00 2d 00 64 00 35 00 34 00 34 00 65 00 63 00 31 00 66 00 64 00 37 00 35 00 33 00))}
		$typelibguid6up = {((34 31 41 39 30 41 36 41 2d 46 39 45 44 2d 34 41 32 46 2d 38 34 34 38 2d 44 35 34 34 45 43 31 46 44 37 35 33) | (34 00 31 00 41 00 39 00 30 00 41 00 36 00 41 00 2d 00 46 00 39 00 45 00 44 00 2d 00 34 00 41 00 32 00 46 00 2d 00 38 00 34 00 34 00 38 00 2d 00 44 00 35 00 34 00 34 00 45 00 43 00 31 00 46 00 44 00 37 00 35 00 33 00))}
		$typelibguid7lo = {((33 37 38 37 34 33 35 62 2d 38 33 35 32 2d 34 62 64 38 2d 61 31 63 36 2d 65 35 61 31 62 37 33 39 32 31 66 34) | (33 00 37 00 38 00 37 00 34 00 33 00 35 00 62 00 2d 00 38 00 33 00 35 00 32 00 2d 00 34 00 62 00 64 00 38 00 2d 00 61 00 31 00 63 00 36 00 2d 00 65 00 35 00 61 00 31 00 62 00 37 00 33 00 39 00 32 00 31 00 66 00 34 00))}
		$typelibguid7up = {((33 37 38 37 34 33 35 42 2d 38 33 35 32 2d 34 42 44 38 2d 41 31 43 36 2d 45 35 41 31 42 37 33 39 32 31 46 34) | (33 00 37 00 38 00 37 00 34 00 33 00 35 00 42 00 2d 00 38 00 33 00 35 00 32 00 2d 00 34 00 42 00 44 00 38 00 2d 00 41 00 31 00 43 00 36 00 2d 00 45 00 35 00 41 00 31 00 42 00 37 00 33 00 39 00 32 00 31 00 46 00 34 00))}
		$typelibguid8lo = {((66 64 64 36 35 34 66 35 2d 35 63 35 34 2d 34 64 39 33 2d 62 66 38 65 2d 66 61 66 31 31 62 30 30 65 33 65 39) | (66 00 64 00 64 00 36 00 35 00 34 00 66 00 35 00 2d 00 35 00 63 00 35 00 34 00 2d 00 34 00 64 00 39 00 33 00 2d 00 62 00 66 00 38 00 65 00 2d 00 66 00 61 00 66 00 31 00 31 00 62 00 30 00 30 00 65 00 33 00 65 00 39 00))}
		$typelibguid8up = {((46 44 44 36 35 34 46 35 2d 35 43 35 34 2d 34 44 39 33 2d 42 46 38 45 2d 46 41 46 31 31 42 30 30 45 33 45 39) | (46 00 44 00 44 00 36 00 35 00 34 00 46 00 35 00 2d 00 35 00 43 00 35 00 34 00 2d 00 34 00 44 00 39 00 33 00 2d 00 42 00 46 00 38 00 45 00 2d 00 46 00 41 00 46 00 31 00 31 00 42 00 30 00 30 00 45 00 33 00 45 00 39 00))}
		$typelibguid9lo = {((61 65 63 33 32 31 35 35 2d 64 35 38 39 2d 34 31 35 30 2d 38 66 65 37 2d 32 39 30 30 64 66 34 35 35 34 63 38) | (61 00 65 00 63 00 33 00 32 00 31 00 35 00 35 00 2d 00 64 00 35 00 38 00 39 00 2d 00 34 00 31 00 35 00 30 00 2d 00 38 00 66 00 65 00 37 00 2d 00 32 00 39 00 30 00 30 00 64 00 66 00 34 00 35 00 35 00 34 00 63 00 38 00))}
		$typelibguid9up = {((41 45 43 33 32 31 35 35 2d 44 35 38 39 2d 34 31 35 30 2d 38 46 45 37 2d 32 39 30 30 44 46 34 35 35 34 43 38) | (41 00 45 00 43 00 33 00 32 00 31 00 35 00 35 00 2d 00 44 00 35 00 38 00 39 00 2d 00 34 00 31 00 35 00 30 00 2d 00 38 00 46 00 45 00 37 00 2d 00 32 00 39 00 30 00 30 00 44 00 46 00 34 00 35 00 35 00 34 00 43 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Salsa_tools : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Hackplayers/Salsa-tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "50db578e-6ddb-54d1-a978-e3630a3548c3"

	strings:
		$typelibguid0lo = {((32 37 36 30 30 34 62 62 2d 35 32 30 30 2d 34 33 38 31 2d 38 34 33 63 2d 39 33 34 65 34 63 33 38 35 62 36 36) | (32 00 37 00 36 00 30 00 30 00 34 00 62 00 62 00 2d 00 35 00 32 00 30 00 30 00 2d 00 34 00 33 00 38 00 31 00 2d 00 38 00 34 00 33 00 63 00 2d 00 39 00 33 00 34 00 65 00 34 00 63 00 33 00 38 00 35 00 62 00 36 00 36 00))}
		$typelibguid0up = {((32 37 36 30 30 34 42 42 2d 35 32 30 30 2d 34 33 38 31 2d 38 34 33 43 2d 39 33 34 45 34 43 33 38 35 42 36 36) | (32 00 37 00 36 00 30 00 30 00 34 00 42 00 42 00 2d 00 35 00 32 00 30 00 30 00 2d 00 34 00 33 00 38 00 31 00 2d 00 38 00 34 00 33 00 43 00 2d 00 39 00 33 00 34 00 45 00 34 00 43 00 33 00 38 00 35 00 42 00 36 00 36 00))}
		$typelibguid1lo = {((63 66 63 62 66 37 62 36 2d 31 63 36 39 2d 34 62 31 66 2d 38 36 35 31 2d 36 62 64 62 34 62 35 35 66 36 62 39) | (63 00 66 00 63 00 62 00 66 00 37 00 62 00 36 00 2d 00 31 00 63 00 36 00 39 00 2d 00 34 00 62 00 31 00 66 00 2d 00 38 00 36 00 35 00 31 00 2d 00 36 00 62 00 64 00 62 00 34 00 62 00 35 00 35 00 66 00 36 00 62 00 39 00))}
		$typelibguid1up = {((43 46 43 42 46 37 42 36 2d 31 43 36 39 2d 34 42 31 46 2d 38 36 35 31 2d 36 42 44 42 34 42 35 35 46 36 42 39) | (43 00 46 00 43 00 42 00 46 00 37 00 42 00 36 00 2d 00 31 00 43 00 36 00 39 00 2d 00 34 00 42 00 31 00 46 00 2d 00 38 00 36 00 35 00 31 00 2d 00 36 00 42 00 44 00 42 00 34 00 42 00 35 00 35 00 46 00 36 00 42 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_WindowsDefender_Payload_Downloader : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/notkohlrexo/WindowsDefender-Payload-Downloader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "6e494a91-c05e-5a2e-8aa9-77600f3bdd47"

	strings:
		$typelibguid0lo = {((32 66 38 62 34 64 32 36 2d 37 36 32 30 2d 34 65 31 31 2d 62 32 39 36 2d 62 63 34 36 65 62 61 33 61 64 66 63) | (32 00 66 00 38 00 62 00 34 00 64 00 32 00 36 00 2d 00 37 00 36 00 32 00 30 00 2d 00 34 00 65 00 31 00 31 00 2d 00 62 00 32 00 39 00 36 00 2d 00 62 00 63 00 34 00 36 00 65 00 62 00 61 00 33 00 61 00 64 00 66 00 63 00))}
		$typelibguid0up = {((32 46 38 42 34 44 32 36 2d 37 36 32 30 2d 34 45 31 31 2d 42 32 39 36 2d 42 43 34 36 45 42 41 33 41 44 46 43) | (32 00 46 00 38 00 42 00 34 00 44 00 32 00 36 00 2d 00 37 00 36 00 32 00 30 00 2d 00 34 00 45 00 31 00 31 00 2d 00 42 00 32 00 39 00 36 00 2d 00 42 00 43 00 34 00 36 00 45 00 42 00 41 00 33 00 41 00 44 00 46 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Privilege_Escalation : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Mrakovic-ORG/Privilege_Escalation"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "28615807-6637-57fc-ba56-efc64b041b80"

	strings:
		$typelibguid0lo = {((65 64 35 34 62 39 30 34 2d 35 36 34 35 2d 34 38 33 30 2d 38 65 36 38 2d 35 32 66 64 39 65 63 62 62 32 65 62) | (65 00 64 00 35 00 34 00 62 00 39 00 30 00 34 00 2d 00 35 00 36 00 34 00 35 00 2d 00 34 00 38 00 33 00 30 00 2d 00 38 00 65 00 36 00 38 00 2d 00 35 00 32 00 66 00 64 00 39 00 65 00 63 00 62 00 62 00 32 00 65 00 62 00))}
		$typelibguid0up = {((45 44 35 34 42 39 30 34 2d 35 36 34 35 2d 34 38 33 30 2d 38 45 36 38 2d 35 32 46 44 39 45 43 42 42 32 45 42) | (45 00 44 00 35 00 34 00 42 00 39 00 30 00 34 00 2d 00 35 00 36 00 34 00 35 00 2d 00 34 00 38 00 33 00 30 00 2d 00 38 00 45 00 36 00 38 00 2d 00 35 00 32 00 46 00 44 00 39 00 45 00 43 00 42 00 42 00 32 00 45 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Marauder : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/maraudershell/Marauder"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "f2783477-2853-5dcd-95f5-9f1e07a4a6e8"

	strings:
		$typelibguid0lo = {((66 66 66 30 61 39 61 33 2d 64 66 64 34 2d 34 30 32 62 2d 61 32 35 31 2d 36 30 34 36 64 37 36 35 61 64 37 38) | (66 00 66 00 66 00 30 00 61 00 39 00 61 00 33 00 2d 00 64 00 66 00 64 00 34 00 2d 00 34 00 30 00 32 00 62 00 2d 00 61 00 32 00 35 00 31 00 2d 00 36 00 30 00 34 00 36 00 64 00 37 00 36 00 35 00 61 00 64 00 37 00 38 00))}
		$typelibguid0up = {((46 46 46 30 41 39 41 33 2d 44 46 44 34 2d 34 30 32 42 2d 41 32 35 31 2d 36 30 34 36 44 37 36 35 41 44 37 38) | (46 00 46 00 46 00 30 00 41 00 39 00 41 00 33 00 2d 00 44 00 46 00 44 00 34 00 2d 00 34 00 30 00 32 00 42 00 2d 00 41 00 32 00 35 00 31 00 2d 00 36 00 30 00 34 00 36 00 44 00 37 00 36 00 35 00 41 00 44 00 37 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_AV_Evasion_Tool : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/1y0n/AV_Evasion_Tool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "d4257465-38a0-56b9-8402-b92e21b96cb0"

	strings:
		$typelibguid0lo = {((31 39 33 37 65 65 31 36 2d 35 37 64 37 2d 34 61 35 66 2d 38 38 66 34 2d 30 32 34 32 34 34 66 31 39 64 63 36) | (31 00 39 00 33 00 37 00 65 00 65 00 31 00 36 00 2d 00 35 00 37 00 64 00 37 00 2d 00 34 00 61 00 35 00 66 00 2d 00 38 00 38 00 66 00 34 00 2d 00 30 00 32 00 34 00 32 00 34 00 34 00 66 00 31 00 39 00 64 00 63 00 36 00))}
		$typelibguid0up = {((31 39 33 37 45 45 31 36 2d 35 37 44 37 2d 34 41 35 46 2d 38 38 46 34 2d 30 32 34 32 34 34 46 31 39 44 43 36) | (31 00 39 00 33 00 37 00 45 00 45 00 31 00 36 00 2d 00 35 00 37 00 44 00 37 00 2d 00 34 00 41 00 35 00 46 00 2d 00 38 00 38 00 46 00 34 00 2d 00 30 00 32 00 34 00 32 00 34 00 34 00 46 00 31 00 39 00 44 00 43 00 36 00))}
		$typelibguid1lo = {((37 38 39 38 36 31 37 64 2d 30 38 64 32 2d 34 32 39 37 2d 61 64 66 65 2d 35 65 64 64 35 63 31 62 38 32 38 62) | (37 00 38 00 39 00 38 00 36 00 31 00 37 00 64 00 2d 00 30 00 38 00 64 00 32 00 2d 00 34 00 32 00 39 00 37 00 2d 00 61 00 64 00 66 00 65 00 2d 00 35 00 65 00 64 00 64 00 35 00 63 00 31 00 62 00 38 00 32 00 38 00 62 00))}
		$typelibguid1up = {((37 38 39 38 36 31 37 44 2d 30 38 44 32 2d 34 32 39 37 2d 41 44 46 45 2d 35 45 44 44 35 43 31 42 38 32 38 42) | (37 00 38 00 39 00 38 00 36 00 31 00 37 00 44 00 2d 00 30 00 38 00 44 00 32 00 2d 00 34 00 32 00 39 00 37 00 2d 00 41 00 44 00 46 00 45 00 2d 00 35 00 45 00 44 00 44 00 35 00 43 00 31 00 42 00 38 00 32 00 38 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Fenrir : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/nccgroup/Fenrir"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "cfc6312d-5997-5261-b771-c7f3f30bf86c"

	strings:
		$typelibguid0lo = {((61 65 63 65 63 31 39 35 2d 66 31 34 33 2d 34 64 30 32 2d 62 39 34 36 2d 64 66 30 65 31 34 33 33 62 64 32 65) | (61 00 65 00 63 00 65 00 63 00 31 00 39 00 35 00 2d 00 66 00 31 00 34 00 33 00 2d 00 34 00 64 00 30 00 32 00 2d 00 62 00 39 00 34 00 36 00 2d 00 64 00 66 00 30 00 65 00 31 00 34 00 33 00 33 00 62 00 64 00 32 00 65 00))}
		$typelibguid0up = {((41 45 43 45 43 31 39 35 2d 46 31 34 33 2d 34 44 30 32 2d 42 39 34 36 2d 44 46 30 45 31 34 33 33 42 44 32 45) | (41 00 45 00 43 00 45 00 43 00 31 00 39 00 35 00 2d 00 46 00 31 00 34 00 33 00 2d 00 34 00 44 00 30 00 32 00 2d 00 42 00 39 00 34 00 36 00 2d 00 44 00 46 00 30 00 45 00 31 00 34 00 33 00 33 00 42 00 44 00 32 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_StormKitty : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/LimerBoy/StormKitty"
		score = 70
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "09d66661-5b67-5846-9bea-ec682afb62cf"

	strings:
		$typelibguid0lo = {((61 31 36 61 62 62 62 34 2d 39 38 35 62 2d 34 64 62 32 2d 61 38 30 63 2d 32 31 32 36 38 62 32 36 63 37 33 64) | (61 00 31 00 36 00 61 00 62 00 62 00 62 00 34 00 2d 00 39 00 38 00 35 00 62 00 2d 00 34 00 64 00 62 00 32 00 2d 00 61 00 38 00 30 00 63 00 2d 00 32 00 31 00 32 00 36 00 38 00 62 00 32 00 36 00 63 00 37 00 33 00 64 00))}
		$typelibguid0up = {((41 31 36 41 42 42 42 34 2d 39 38 35 42 2d 34 44 42 32 2d 41 38 30 43 2d 32 31 32 36 38 42 32 36 43 37 33 44) | (41 00 31 00 36 00 41 00 42 00 42 00 42 00 34 00 2d 00 39 00 38 00 35 00 42 00 2d 00 34 00 44 00 42 00 32 00 2d 00 41 00 38 00 30 00 43 00 2d 00 32 00 31 00 32 00 36 00 38 00 42 00 32 00 36 00 43 00 37 00 33 00 44 00))}
		$typelibguid1lo = {((39 38 30 37 35 33 33 31 2d 31 66 38 36 2d 34 38 63 38 2d 61 65 32 39 2d 32 39 64 61 33 39 61 38 66 39 38 62) | (39 00 38 00 30 00 37 00 35 00 33 00 33 00 31 00 2d 00 31 00 66 00 38 00 36 00 2d 00 34 00 38 00 63 00 38 00 2d 00 61 00 65 00 32 00 39 00 2d 00 32 00 39 00 64 00 61 00 33 00 39 00 61 00 38 00 66 00 39 00 38 00 62 00))}
		$typelibguid1up = {((39 38 30 37 35 33 33 31 2d 31 46 38 36 2d 34 38 43 38 2d 41 45 32 39 2d 32 39 44 41 33 39 41 38 46 39 38 42) | (39 00 38 00 30 00 37 00 35 00 33 00 33 00 31 00 2d 00 31 00 46 00 38 00 36 00 2d 00 34 00 38 00 43 00 38 00 2d 00 41 00 45 00 32 00 39 00 2d 00 32 00 39 00 44 00 41 00 33 00 39 00 41 00 38 00 46 00 39 00 38 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Crypter_Runtime_AV_s_bypass : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/netreverse/Crypter-Runtime-AV-s-bypass"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "726cd57b-d88a-5854-b2e1-76d9bd71a155"

	strings:
		$typelibguid0lo = {((63 32 35 65 33 39 61 39 2d 38 32 31 35 2d 34 33 61 61 2d 39 36 61 33 2d 64 61 30 65 39 35 31 32 65 63 31 38) | (63 00 32 00 35 00 65 00 33 00 39 00 61 00 39 00 2d 00 38 00 32 00 31 00 35 00 2d 00 34 00 33 00 61 00 61 00 2d 00 39 00 36 00 61 00 33 00 2d 00 64 00 61 00 30 00 65 00 39 00 35 00 31 00 32 00 65 00 63 00 31 00 38 00))}
		$typelibguid0up = {((43 32 35 45 33 39 41 39 2d 38 32 31 35 2d 34 33 41 41 2d 39 36 41 33 2d 44 41 30 45 39 35 31 32 45 43 31 38) | (43 00 32 00 35 00 45 00 33 00 39 00 41 00 39 00 2d 00 38 00 32 00 31 00 35 00 2d 00 34 00 33 00 41 00 41 00 2d 00 39 00 36 00 41 00 33 00 2d 00 44 00 41 00 30 00 45 00 39 00 35 00 31 00 32 00 45 00 43 00 31 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_RunAsUser : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/atthacks/RunAsUser"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "ead7819a-1397-5953-888f-2176e4041375"

	strings:
		$typelibguid0lo = {((39 64 66 66 32 38 32 63 2d 39 33 62 39 2d 34 30 36 33 2d 62 66 38 61 2d 62 36 37 39 38 33 37 31 64 33 35 61) | (39 00 64 00 66 00 66 00 32 00 38 00 32 00 63 00 2d 00 39 00 33 00 62 00 39 00 2d 00 34 00 30 00 36 00 33 00 2d 00 62 00 66 00 38 00 61 00 2d 00 62 00 36 00 37 00 39 00 38 00 33 00 37 00 31 00 64 00 33 00 35 00 61 00))}
		$typelibguid0up = {((39 44 46 46 32 38 32 43 2d 39 33 42 39 2d 34 30 36 33 2d 42 46 38 41 2d 42 36 37 39 38 33 37 31 44 33 35 41) | (39 00 44 00 46 00 46 00 32 00 38 00 32 00 43 00 2d 00 39 00 33 00 42 00 39 00 2d 00 34 00 30 00 36 00 33 00 2d 00 42 00 46 00 38 00 41 00 2d 00 42 00 36 00 37 00 39 00 38 00 33 00 37 00 31 00 44 00 33 00 35 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_HWIDbypass : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/yunseok/HWIDbypass"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "62b0541b-6eec-546e-8445-85d25bb0d784"

	strings:
		$typelibguid0lo = {((34 37 65 30 38 37 39 31 2d 64 31 32 34 2d 34 37 34 36 2d 62 63 35 30 2d 32 34 62 64 31 65 65 37 31 39 61 36) | (34 00 37 00 65 00 30 00 38 00 37 00 39 00 31 00 2d 00 64 00 31 00 32 00 34 00 2d 00 34 00 37 00 34 00 36 00 2d 00 62 00 63 00 35 00 30 00 2d 00 32 00 34 00 62 00 64 00 31 00 65 00 65 00 37 00 31 00 39 00 61 00 36 00))}
		$typelibguid0up = {((34 37 45 30 38 37 39 31 2d 44 31 32 34 2d 34 37 34 36 2d 42 43 35 30 2d 32 34 42 44 31 45 45 37 31 39 41 36) | (34 00 37 00 45 00 30 00 38 00 37 00 39 00 31 00 2d 00 44 00 31 00 32 00 34 00 2d 00 34 00 37 00 34 00 36 00 2d 00 42 00 43 00 35 00 30 00 2d 00 32 00 34 00 42 00 44 00 31 00 45 00 45 00 37 00 31 00 39 00 41 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_XORedReflectiveDLL : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/r3nhat/XORedReflectiveDLL"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "9b584bfb-98ef-50ee-b546-780c4b210a1b"

	strings:
		$typelibguid0lo = {((63 30 65 34 39 33 39 32 2d 30 34 65 33 2d 34 61 62 62 2d 62 39 33 31 2d 35 32 30 32 65 30 65 62 34 63 37 33) | (63 00 30 00 65 00 34 00 39 00 33 00 39 00 32 00 2d 00 30 00 34 00 65 00 33 00 2d 00 34 00 61 00 62 00 62 00 2d 00 62 00 39 00 33 00 31 00 2d 00 35 00 32 00 30 00 32 00 65 00 30 00 65 00 62 00 34 00 63 00 37 00 33 00))}
		$typelibguid0up = {((43 30 45 34 39 33 39 32 2d 30 34 45 33 2d 34 41 42 42 2d 42 39 33 31 2d 35 32 30 32 45 30 45 42 34 43 37 33) | (43 00 30 00 45 00 34 00 39 00 33 00 39 00 32 00 2d 00 30 00 34 00 45 00 33 00 2d 00 34 00 41 00 42 00 42 00 2d 00 42 00 39 00 33 00 31 00 2d 00 35 00 32 00 30 00 32 00 45 00 30 00 45 00 42 00 34 00 43 00 37 00 33 00))}
		$typelibguid1lo = {((33 30 65 65 66 37 64 36 2d 63 65 65 38 2d 34 39 30 62 2d 38 32 39 66 2d 30 38 32 30 34 31 62 63 33 31 34 31) | (33 00 30 00 65 00 65 00 66 00 37 00 64 00 36 00 2d 00 63 00 65 00 65 00 38 00 2d 00 34 00 39 00 30 00 62 00 2d 00 38 00 32 00 39 00 66 00 2d 00 30 00 38 00 32 00 30 00 34 00 31 00 62 00 63 00 33 00 31 00 34 00 31 00))}
		$typelibguid1up = {((33 30 45 45 46 37 44 36 2d 43 45 45 38 2d 34 39 30 42 2d 38 32 39 46 2d 30 38 32 30 34 31 42 43 33 31 34 31) | (33 00 30 00 45 00 45 00 46 00 37 00 44 00 36 00 2d 00 43 00 45 00 45 00 38 00 2d 00 34 00 39 00 30 00 42 00 2d 00 38 00 32 00 39 00 46 00 2d 00 30 00 38 00 32 00 30 00 34 00 31 00 42 00 43 00 33 00 31 00 34 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Sharp_Suite : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FuzzySecurity/Sharp-Suite"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		modified = "2023-04-06"
		id = "ab3cf358-a41d-584d-baaf-5e8f7232ca85"

	strings:
		$typelibguid0lo = {((31 39 36 35 37 62 65 34 2d 35 31 63 61 2d 34 61 38 35 2d 38 61 62 31 2d 66 36 36 36 36 30 30 38 62 31 66 33) | (31 00 39 00 36 00 35 00 37 00 62 00 65 00 34 00 2d 00 35 00 31 00 63 00 61 00 2d 00 34 00 61 00 38 00 35 00 2d 00 38 00 61 00 62 00 31 00 2d 00 66 00 36 00 36 00 36 00 36 00 30 00 30 00 38 00 62 00 31 00 66 00 33 00))}
		$typelibguid0up = {((31 39 36 35 37 42 45 34 2d 35 31 43 41 2d 34 41 38 35 2d 38 41 42 31 2d 46 36 36 36 36 30 30 38 42 31 46 33) | (31 00 39 00 36 00 35 00 37 00 42 00 45 00 34 00 2d 00 35 00 31 00 43 00 41 00 2d 00 34 00 41 00 38 00 35 00 2d 00 38 00 41 00 42 00 31 00 2d 00 46 00 36 00 36 00 36 00 36 00 30 00 30 00 38 00 42 00 31 00 46 00 33 00))}
		$typelibguid1lo = {((30 61 33 38 32 64 39 61 2d 38 39 37 66 2d 34 33 31 61 2d 38 31 63 32 2d 61 34 65 30 38 33 39 32 63 35 38 37) | (30 00 61 00 33 00 38 00 32 00 64 00 39 00 61 00 2d 00 38 00 39 00 37 00 66 00 2d 00 34 00 33 00 31 00 61 00 2d 00 38 00 31 00 63 00 32 00 2d 00 61 00 34 00 65 00 30 00 38 00 33 00 39 00 32 00 63 00 35 00 38 00 37 00))}
		$typelibguid1up = {((30 41 33 38 32 44 39 41 2d 38 39 37 46 2d 34 33 31 41 2d 38 31 43 32 2d 41 34 45 30 38 33 39 32 43 35 38 37) | (30 00 41 00 33 00 38 00 32 00 44 00 39 00 41 00 2d 00 38 00 39 00 37 00 46 00 2d 00 34 00 33 00 31 00 41 00 2d 00 38 00 31 00 43 00 32 00 2d 00 41 00 34 00 45 00 30 00 38 00 33 00 39 00 32 00 43 00 35 00 38 00 37 00))}
		$typelibguid2lo = {((34 36 37 65 65 32 61 39 2d 32 66 30 31 2d 34 61 37 31 2d 39 36 34 37 2d 32 61 32 64 39 63 33 31 65 36 30 38) | (34 00 36 00 37 00 65 00 65 00 32 00 61 00 39 00 2d 00 32 00 66 00 30 00 31 00 2d 00 34 00 61 00 37 00 31 00 2d 00 39 00 36 00 34 00 37 00 2d 00 32 00 61 00 32 00 64 00 39 00 63 00 33 00 31 00 65 00 36 00 30 00 38 00))}
		$typelibguid2up = {((34 36 37 45 45 32 41 39 2d 32 46 30 31 2d 34 41 37 31 2d 39 36 34 37 2d 32 41 32 44 39 43 33 31 45 36 30 38) | (34 00 36 00 37 00 45 00 45 00 32 00 41 00 39 00 2d 00 32 00 46 00 30 00 31 00 2d 00 34 00 41 00 37 00 31 00 2d 00 39 00 36 00 34 00 37 00 2d 00 32 00 41 00 32 00 44 00 39 00 43 00 33 00 31 00 45 00 36 00 30 00 38 00))}
		$typelibguid3lo = {((65 61 63 61 61 32 62 38 2d 34 33 65 35 2d 34 38 38 38 2d 38 32 36 64 2d 32 66 36 39 30 32 65 31 36 35 34 36) | (65 00 61 00 63 00 61 00 61 00 32 00 62 00 38 00 2d 00 34 00 33 00 65 00 35 00 2d 00 34 00 38 00 38 00 38 00 2d 00 38 00 32 00 36 00 64 00 2d 00 32 00 66 00 36 00 39 00 30 00 32 00 65 00 31 00 36 00 35 00 34 00 36 00))}
		$typelibguid3up = {((45 41 43 41 41 32 42 38 2d 34 33 45 35 2d 34 38 38 38 2d 38 32 36 44 2d 32 46 36 39 30 32 45 31 36 35 34 36) | (45 00 41 00 43 00 41 00 41 00 32 00 42 00 38 00 2d 00 34 00 33 00 45 00 35 00 2d 00 34 00 38 00 38 00 38 00 2d 00 38 00 32 00 36 00 44 00 2d 00 32 00 46 00 36 00 39 00 30 00 32 00 45 00 31 00 36 00 35 00 34 00 36 00))}
		$typelibguid4lo = {((36 32 39 66 38 36 65 36 2d 34 34 66 65 2d 34 63 39 63 2d 62 30 34 33 2d 31 63 39 62 36 34 62 65 36 64 35 61) | (36 00 32 00 39 00 66 00 38 00 36 00 65 00 36 00 2d 00 34 00 34 00 66 00 65 00 2d 00 34 00 63 00 39 00 63 00 2d 00 62 00 30 00 34 00 33 00 2d 00 31 00 63 00 39 00 62 00 36 00 34 00 62 00 65 00 36 00 64 00 35 00 61 00))}
		$typelibguid4up = {((36 32 39 46 38 36 45 36 2d 34 34 46 45 2d 34 43 39 43 2d 42 30 34 33 2d 31 43 39 42 36 34 42 45 36 44 35 41) | (36 00 32 00 39 00 46 00 38 00 36 00 45 00 36 00 2d 00 34 00 34 00 46 00 45 00 2d 00 34 00 43 00 39 00 43 00 2d 00 42 00 30 00 34 00 33 00 2d 00 31 00 43 00 39 00 42 00 36 00 34 00 42 00 45 00 36 00 44 00 35 00 41 00))}
		$typelibguid5lo = {((65 63 66 32 66 66 65 34 2d 31 37 34 34 2d 34 37 34 35 2d 38 36 39 33 2d 35 37 39 30 64 36 36 62 62 31 62 38) | (65 00 63 00 66 00 32 00 66 00 66 00 65 00 34 00 2d 00 31 00 37 00 34 00 34 00 2d 00 34 00 37 00 34 00 35 00 2d 00 38 00 36 00 39 00 33 00 2d 00 35 00 37 00 39 00 30 00 64 00 36 00 36 00 62 00 62 00 31 00 62 00 38 00))}
		$typelibguid5up = {((45 43 46 32 46 46 45 34 2d 31 37 34 34 2d 34 37 34 35 2d 38 36 39 33 2d 35 37 39 30 44 36 36 42 42 31 42 38) | (45 00 43 00 46 00 32 00 46 00 46 00 45 00 34 00 2d 00 31 00 37 00 34 00 34 00 2d 00 34 00 37 00 34 00 35 00 2d 00 38 00 36 00 39 00 33 00 2d 00 35 00 37 00 39 00 30 00 44 00 36 00 36 00 42 00 42 00 31 00 42 00 38 00))}
		$typelibguid6lo = {((30 61 36 32 31 66 34 63 2d 38 30 38 32 2d 34 63 33 30 2d 62 31 33 31 2d 62 61 32 63 39 38 64 62 30 35 33 33) | (30 00 61 00 36 00 32 00 31 00 66 00 34 00 63 00 2d 00 38 00 30 00 38 00 32 00 2d 00 34 00 63 00 33 00 30 00 2d 00 62 00 31 00 33 00 31 00 2d 00 62 00 61 00 32 00 63 00 39 00 38 00 64 00 62 00 30 00 35 00 33 00 33 00))}
		$typelibguid6up = {((30 41 36 32 31 46 34 43 2d 38 30 38 32 2d 34 43 33 30 2d 42 31 33 31 2d 42 41 32 43 39 38 44 42 30 35 33 33) | (30 00 41 00 36 00 32 00 31 00 46 00 34 00 43 00 2d 00 38 00 30 00 38 00 32 00 2d 00 34 00 43 00 33 00 30 00 2d 00 42 00 31 00 33 00 31 00 2d 00 42 00 41 00 32 00 43 00 39 00 38 00 44 00 42 00 30 00 35 00 33 00 33 00))}
		$typelibguid7lo = {((37 32 30 31 39 64 66 65 2d 36 30 38 65 2d 34 61 62 32 2d 61 38 66 31 2d 36 36 63 39 35 63 34 32 35 36 32 30) | (37 00 32 00 30 00 31 00 39 00 64 00 66 00 65 00 2d 00 36 00 30 00 38 00 65 00 2d 00 34 00 61 00 62 00 32 00 2d 00 61 00 38 00 66 00 31 00 2d 00 36 00 36 00 63 00 39 00 35 00 63 00 34 00 32 00 35 00 36 00 32 00 30 00))}
		$typelibguid7up = {((37 32 30 31 39 44 46 45 2d 36 30 38 45 2d 34 41 42 32 2d 41 38 46 31 2d 36 36 43 39 35 43 34 32 35 36 32 30) | (37 00 32 00 30 00 31 00 39 00 44 00 46 00 45 00 2d 00 36 00 30 00 38 00 45 00 2d 00 34 00 41 00 42 00 32 00 2d 00 41 00 38 00 46 00 31 00 2d 00 36 00 36 00 43 00 39 00 35 00 43 00 34 00 32 00 35 00 36 00 32 00 30 00))}
		$typelibguid8lo = {((66 30 64 32 38 38 30 39 2d 62 37 31 32 2d 34 33 38 30 2d 39 61 35 39 2d 34 30 37 62 37 62 32 62 61 64 64 35) | (66 00 30 00 64 00 32 00 38 00 38 00 30 00 39 00 2d 00 62 00 37 00 31 00 32 00 2d 00 34 00 33 00 38 00 30 00 2d 00 39 00 61 00 35 00 39 00 2d 00 34 00 30 00 37 00 62 00 37 00 62 00 32 00 62 00 61 00 64 00 64 00 35 00))}
		$typelibguid8up = {((46 30 44 32 38 38 30 39 2d 42 37 31 32 2d 34 33 38 30 2d 39 41 35 39 2d 34 30 37 42 37 42 32 42 41 44 44 35) | (46 00 30 00 44 00 32 00 38 00 38 00 30 00 39 00 2d 00 42 00 37 00 31 00 32 00 2d 00 34 00 33 00 38 00 30 00 2d 00 39 00 41 00 35 00 39 00 2d 00 34 00 30 00 37 00 42 00 37 00 42 00 32 00 42 00 41 00 44 00 44 00 35 00))}
		$typelibguid9lo = {((39 35 36 61 35 61 34 64 2d 32 30 30 37 2d 34 38 35 37 2d 39 32 35 39 2d 35 31 63 64 30 66 62 35 33 31 32 61) | (39 00 35 00 36 00 61 00 35 00 61 00 34 00 64 00 2d 00 32 00 30 00 30 00 37 00 2d 00 34 00 38 00 35 00 37 00 2d 00 39 00 32 00 35 00 39 00 2d 00 35 00 31 00 63 00 64 00 30 00 66 00 62 00 35 00 33 00 31 00 32 00 61 00))}
		$typelibguid9up = {((39 35 36 41 35 41 34 44 2d 32 30 30 37 2d 34 38 35 37 2d 39 32 35 39 2d 35 31 43 44 30 46 42 35 33 31 32 41) | (39 00 35 00 36 00 41 00 35 00 41 00 34 00 44 00 2d 00 32 00 30 00 30 00 37 00 2d 00 34 00 38 00 35 00 37 00 2d 00 39 00 32 00 35 00 39 00 2d 00 35 00 31 00 43 00 44 00 30 00 46 00 42 00 35 00 33 00 31 00 32 00 41 00))}
		$typelibguid10lo = {((61 33 62 37 63 36 39 37 2d 34 62 62 36 2d 34 35 35 64 2d 39 66 64 61 2d 34 61 62 35 34 61 65 34 63 38 64 32) | (61 00 33 00 62 00 37 00 63 00 36 00 39 00 37 00 2d 00 34 00 62 00 62 00 36 00 2d 00 34 00 35 00 35 00 64 00 2d 00 39 00 66 00 64 00 61 00 2d 00 34 00 61 00 62 00 35 00 34 00 61 00 65 00 34 00 63 00 38 00 64 00 32 00))}
		$typelibguid10up = {((41 33 42 37 43 36 39 37 2d 34 42 42 36 2d 34 35 35 44 2d 39 46 44 41 2d 34 41 42 35 34 41 45 34 43 38 44 32) | (41 00 33 00 42 00 37 00 43 00 36 00 39 00 37 00 2d 00 34 00 42 00 42 00 36 00 2d 00 34 00 35 00 35 00 44 00 2d 00 39 00 46 00 44 00 41 00 2d 00 34 00 41 00 42 00 35 00 34 00 41 00 45 00 34 00 43 00 38 00 44 00 32 00))}
		$typelibguid11lo = {((61 35 66 38 38 33 63 65 2d 31 66 39 36 2d 34 34 35 36 2d 62 62 33 35 2d 34 30 32 32 39 31 39 31 34 32 30 63) | (61 00 35 00 66 00 38 00 38 00 33 00 63 00 65 00 2d 00 31 00 66 00 39 00 36 00 2d 00 34 00 34 00 35 00 36 00 2d 00 62 00 62 00 33 00 35 00 2d 00 34 00 30 00 32 00 32 00 39 00 31 00 39 00 31 00 34 00 32 00 30 00 63 00))}
		$typelibguid11up = {((41 35 46 38 38 33 43 45 2d 31 46 39 36 2d 34 34 35 36 2d 42 42 33 35 2d 34 30 32 32 39 31 39 31 34 32 30 43) | (41 00 35 00 46 00 38 00 38 00 33 00 43 00 45 00 2d 00 31 00 46 00 39 00 36 00 2d 00 34 00 34 00 35 00 36 00 2d 00 42 00 42 00 33 00 35 00 2d 00 34 00 30 00 32 00 32 00 39 00 31 00 39 00 31 00 34 00 32 00 30 00 43 00))}
		$typelibguid12lo = {((32 38 39 37 38 31 30 33 2d 64 39 30 64 2d 34 36 31 38 2d 62 32 32 65 2d 32 32 32 37 32 37 66 34 30 33 31 33) | (32 00 38 00 39 00 37 00 38 00 31 00 30 00 33 00 2d 00 64 00 39 00 30 00 64 00 2d 00 34 00 36 00 31 00 38 00 2d 00 62 00 32 00 32 00 65 00 2d 00 32 00 32 00 32 00 37 00 32 00 37 00 66 00 34 00 30 00 33 00 31 00 33 00))}
		$typelibguid12up = {((32 38 39 37 38 31 30 33 2d 44 39 30 44 2d 34 36 31 38 2d 42 32 32 45 2d 32 32 32 37 32 37 46 34 30 33 31 33) | (32 00 38 00 39 00 37 00 38 00 31 00 30 00 33 00 2d 00 44 00 39 00 30 00 44 00 2d 00 34 00 36 00 31 00 38 00 2d 00 42 00 32 00 32 00 45 00 2d 00 32 00 32 00 32 00 37 00 32 00 37 00 46 00 34 00 30 00 33 00 31 00 33 00))}
		$typelibguid13lo = {((30 63 37 30 63 38 33 39 2d 39 35 36 35 2d 34 38 38 31 2d 38 65 61 31 2d 34 30 38 63 31 65 62 65 33 38 63 65) | (30 00 63 00 37 00 30 00 63 00 38 00 33 00 39 00 2d 00 39 00 35 00 36 00 35 00 2d 00 34 00 38 00 38 00 31 00 2d 00 38 00 65 00 61 00 31 00 2d 00 34 00 30 00 38 00 63 00 31 00 65 00 62 00 65 00 33 00 38 00 63 00 65 00))}
		$typelibguid13up = {((30 43 37 30 43 38 33 39 2d 39 35 36 35 2d 34 38 38 31 2d 38 45 41 31 2d 34 30 38 43 31 45 42 45 33 38 43 45) | (30 00 43 00 37 00 30 00 43 00 38 00 33 00 39 00 2d 00 39 00 35 00 36 00 35 00 2d 00 34 00 38 00 38 00 31 00 2d 00 38 00 45 00 41 00 31 00 2d 00 34 00 30 00 38 00 43 00 31 00 45 00 42 00 45 00 33 00 38 00 43 00 45 00))}
		$typelibguid14lo = {((66 61 31 64 39 61 33 36 2d 34 31 35 61 2d 34 38 35 35 2d 38 63 30 31 2d 35 34 62 36 65 39 66 63 36 39 36 35) | (66 00 61 00 31 00 64 00 39 00 61 00 33 00 36 00 2d 00 34 00 31 00 35 00 61 00 2d 00 34 00 38 00 35 00 35 00 2d 00 38 00 63 00 30 00 31 00 2d 00 35 00 34 00 62 00 36 00 65 00 39 00 66 00 63 00 36 00 39 00 36 00 35 00))}
		$typelibguid14up = {((46 41 31 44 39 41 33 36 2d 34 31 35 41 2d 34 38 35 35 2d 38 43 30 31 2d 35 34 42 36 45 39 46 43 36 39 36 35) | (46 00 41 00 31 00 44 00 39 00 41 00 33 00 36 00 2d 00 34 00 31 00 35 00 41 00 2d 00 34 00 38 00 35 00 35 00 2d 00 38 00 43 00 30 00 31 00 2d 00 35 00 34 00 42 00 36 00 45 00 39 00 46 00 43 00 36 00 39 00 36 00 35 00))}
		$typelibguid15lo = {((32 35 32 36 37 36 66 38 2d 38 61 31 39 2d 34 36 36 34 2d 62 66 62 38 2d 35 61 39 34 37 65 34 38 63 33 32 61) | (32 00 35 00 32 00 36 00 37 00 36 00 66 00 38 00 2d 00 38 00 61 00 31 00 39 00 2d 00 34 00 36 00 36 00 34 00 2d 00 62 00 66 00 62 00 38 00 2d 00 35 00 61 00 39 00 34 00 37 00 65 00 34 00 38 00 63 00 33 00 32 00 61 00))}
		$typelibguid15up = {((32 35 32 36 37 36 46 38 2d 38 41 31 39 2d 34 36 36 34 2d 42 46 42 38 2d 35 41 39 34 37 45 34 38 43 33 32 41) | (32 00 35 00 32 00 36 00 37 00 36 00 46 00 38 00 2d 00 38 00 41 00 31 00 39 00 2d 00 34 00 36 00 36 00 34 00 2d 00 42 00 46 00 42 00 38 00 2d 00 35 00 41 00 39 00 34 00 37 00 45 00 34 00 38 00 43 00 33 00 32 00 41 00))}
		$typelibguid16lo = {((34 34 37 65 64 65 66 63 2d 62 34 32 39 2d 34 32 62 63 2d 62 33 62 63 2d 36 33 61 39 61 66 31 39 64 62 64 36) | (34 00 34 00 37 00 65 00 64 00 65 00 66 00 63 00 2d 00 62 00 34 00 32 00 39 00 2d 00 34 00 32 00 62 00 63 00 2d 00 62 00 33 00 62 00 63 00 2d 00 36 00 33 00 61 00 39 00 61 00 66 00 31 00 39 00 64 00 62 00 64 00 36 00))}
		$typelibguid16up = {((34 34 37 45 44 45 46 43 2d 42 34 32 39 2d 34 32 42 43 2d 42 33 42 43 2d 36 33 41 39 41 46 31 39 44 42 44 36) | (34 00 34 00 37 00 45 00 44 00 45 00 46 00 43 00 2d 00 42 00 34 00 32 00 39 00 2d 00 34 00 32 00 42 00 43 00 2d 00 42 00 33 00 42 00 43 00 2d 00 36 00 33 00 41 00 39 00 41 00 46 00 31 00 39 00 44 00 42 00 44 00 36 00))}
		$typelibguid17lo = {((30 34 64 30 62 33 61 36 2d 65 61 61 62 2d 34 31 33 64 2d 62 39 65 32 2d 35 31 32 66 61 38 65 62 64 30 32 66) | (30 00 34 00 64 00 30 00 62 00 33 00 61 00 36 00 2d 00 65 00 61 00 61 00 62 00 2d 00 34 00 31 00 33 00 64 00 2d 00 62 00 39 00 65 00 32 00 2d 00 35 00 31 00 32 00 66 00 61 00 38 00 65 00 62 00 64 00 30 00 32 00 66 00))}
		$typelibguid17up = {((30 34 44 30 42 33 41 36 2d 45 41 41 42 2d 34 31 33 44 2d 42 39 45 32 2d 35 31 32 46 41 38 45 42 44 30 32 46) | (30 00 34 00 44 00 30 00 42 00 33 00 41 00 36 00 2d 00 45 00 41 00 41 00 42 00 2d 00 34 00 31 00 33 00 44 00 2d 00 42 00 39 00 45 00 32 00 2d 00 35 00 31 00 32 00 46 00 41 00 38 00 45 00 42 00 44 00 30 00 32 00 46 00))}
		$typelibguid18lo = {((35 36 31 31 32 33 36 65 2d 32 35 35 37 2d 34 35 62 38 2d 62 65 32 39 2d 35 64 31 66 30 37 34 64 31 39 39 65) | (35 00 36 00 31 00 31 00 32 00 33 00 36 00 65 00 2d 00 32 00 35 00 35 00 37 00 2d 00 34 00 35 00 62 00 38 00 2d 00 62 00 65 00 32 00 39 00 2d 00 35 00 64 00 31 00 66 00 30 00 37 00 34 00 64 00 31 00 39 00 39 00 65 00))}
		$typelibguid18up = {((35 36 31 31 32 33 36 45 2d 32 35 35 37 2d 34 35 42 38 2d 42 45 32 39 2d 35 44 31 46 30 37 34 44 31 39 39 45) | (35 00 36 00 31 00 31 00 32 00 33 00 36 00 45 00 2d 00 32 00 35 00 35 00 37 00 2d 00 34 00 35 00 42 00 38 00 2d 00 42 00 45 00 32 00 39 00 2d 00 35 00 44 00 31 00 46 00 30 00 37 00 34 00 44 00 31 00 39 00 39 00 45 00))}
		$typelibguid19lo = {((35 33 66 36 32 32 65 62 2d 30 63 61 33 2d 34 65 39 62 2d 39 64 63 38 2d 33 30 63 38 33 32 64 66 31 63 37 62) | (35 00 33 00 66 00 36 00 32 00 32 00 65 00 62 00 2d 00 30 00 63 00 61 00 33 00 2d 00 34 00 65 00 39 00 62 00 2d 00 39 00 64 00 63 00 38 00 2d 00 33 00 30 00 63 00 38 00 33 00 32 00 64 00 66 00 31 00 63 00 37 00 62 00))}
		$typelibguid19up = {((35 33 46 36 32 32 45 42 2d 30 43 41 33 2d 34 45 39 42 2d 39 44 43 38 2d 33 30 43 38 33 32 44 46 31 43 37 42) | (35 00 33 00 46 00 36 00 32 00 32 00 45 00 42 00 2d 00 30 00 43 00 41 00 33 00 2d 00 34 00 45 00 39 00 42 00 2d 00 39 00 44 00 43 00 38 00 2d 00 33 00 30 00 43 00 38 00 33 00 32 00 44 00 46 00 31 00 43 00 37 00 42 00))}
		$typelibguid20lo = {((34 31 34 31 38 37 64 62 2d 35 66 65 62 2d 34 33 65 35 2d 61 33 38 33 2d 63 61 61 34 38 62 35 33 39 35 66 31) | (34 00 31 00 34 00 31 00 38 00 37 00 64 00 62 00 2d 00 35 00 66 00 65 00 62 00 2d 00 34 00 33 00 65 00 35 00 2d 00 61 00 33 00 38 00 33 00 2d 00 63 00 61 00 61 00 34 00 38 00 62 00 35 00 33 00 39 00 35 00 66 00 31 00))}
		$typelibguid20up = {((34 31 34 31 38 37 44 42 2d 35 46 45 42 2d 34 33 45 35 2d 41 33 38 33 2d 43 41 41 34 38 42 35 33 39 35 46 31) | (34 00 31 00 34 00 31 00 38 00 37 00 44 00 42 00 2d 00 35 00 46 00 45 00 42 00 2d 00 34 00 33 00 45 00 35 00 2d 00 41 00 33 00 38 00 33 00 2d 00 43 00 41 00 41 00 34 00 38 00 42 00 35 00 33 00 39 00 35 00 46 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_rat_shell : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/stphivos/rat-shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "8f206175-f7e4-5543-8059-24f102fcd4b9"

	strings:
		$typelibguid0lo = {((37 61 31 35 66 38 66 36 2d 36 63 65 32 2d 34 63 61 34 2d 39 31 39 64 2d 32 30 35 36 62 37 30 63 63 37 36 61) | (37 00 61 00 31 00 35 00 66 00 38 00 66 00 36 00 2d 00 36 00 63 00 65 00 32 00 2d 00 34 00 63 00 61 00 34 00 2d 00 39 00 31 00 39 00 64 00 2d 00 32 00 30 00 35 00 36 00 62 00 37 00 30 00 63 00 63 00 37 00 36 00 61 00))}
		$typelibguid0up = {((37 41 31 35 46 38 46 36 2d 36 43 45 32 2d 34 43 41 34 2d 39 31 39 44 2d 32 30 35 36 42 37 30 43 43 37 36 41) | (37 00 41 00 31 00 35 00 46 00 38 00 46 00 36 00 2d 00 36 00 43 00 45 00 32 00 2d 00 34 00 43 00 41 00 34 00 2d 00 39 00 31 00 39 00 44 00 2d 00 32 00 30 00 35 00 36 00 42 00 37 00 30 00 43 00 43 00 37 00 36 00 41 00))}
		$typelibguid1lo = {((31 36 35 39 64 36 35 64 2d 39 33 61 38 2d 34 62 61 65 2d 39 37 64 35 2d 36 36 64 37 33 38 66 63 36 66 36 63) | (31 00 36 00 35 00 39 00 64 00 36 00 35 00 64 00 2d 00 39 00 33 00 61 00 38 00 2d 00 34 00 62 00 61 00 65 00 2d 00 39 00 37 00 64 00 35 00 2d 00 36 00 36 00 64 00 37 00 33 00 38 00 66 00 63 00 36 00 66 00 36 00 63 00))}
		$typelibguid1up = {((31 36 35 39 44 36 35 44 2d 39 33 41 38 2d 34 42 41 45 2d 39 37 44 35 2d 36 36 44 37 33 38 46 43 36 46 36 43) | (31 00 36 00 35 00 39 00 44 00 36 00 35 00 44 00 2d 00 39 00 33 00 41 00 38 00 2d 00 34 00 42 00 41 00 45 00 2d 00 39 00 37 00 44 00 35 00 2d 00 36 00 36 00 44 00 37 00 33 00 38 00 46 00 43 00 36 00 46 00 36 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_dotnet_gargoyle : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/countercept/dotnet-gargoyle"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "5efd0c83-cb65-5bda-b55e-4a89db5f337c"

	strings:
		$typelibguid0lo = {((37 36 34 33 35 66 37 39 2d 66 38 61 66 2d 34 64 37 34 2d 38 64 66 35 2d 64 35 39 38 61 35 35 31 62 38 39 35) | (37 00 36 00 34 00 33 00 35 00 66 00 37 00 39 00 2d 00 66 00 38 00 61 00 66 00 2d 00 34 00 64 00 37 00 34 00 2d 00 38 00 64 00 66 00 35 00 2d 00 64 00 35 00 39 00 38 00 61 00 35 00 35 00 31 00 62 00 38 00 39 00 35 00))}
		$typelibguid0up = {((37 36 34 33 35 46 37 39 2d 46 38 41 46 2d 34 44 37 34 2d 38 44 46 35 2d 44 35 39 38 41 35 35 31 42 38 39 35) | (37 00 36 00 34 00 33 00 35 00 46 00 37 00 39 00 2d 00 46 00 38 00 41 00 46 00 2d 00 34 00 44 00 37 00 34 00 2d 00 38 00 44 00 46 00 35 00 2d 00 44 00 35 00 39 00 38 00 41 00 35 00 35 00 31 00 42 00 38 00 39 00 35 00))}
		$typelibguid1lo = {((35 61 33 66 63 38 34 30 2d 35 34 33 32 2d 34 39 32 35 2d 62 35 62 63 2d 61 62 63 35 33 36 34 32 39 63 62 35) | (35 00 61 00 33 00 66 00 63 00 38 00 34 00 30 00 2d 00 35 00 34 00 33 00 32 00 2d 00 34 00 39 00 32 00 35 00 2d 00 62 00 35 00 62 00 63 00 2d 00 61 00 62 00 63 00 35 00 33 00 36 00 34 00 32 00 39 00 63 00 62 00 35 00))}
		$typelibguid1up = {((35 41 33 46 43 38 34 30 2d 35 34 33 32 2d 34 39 32 35 2d 42 35 42 43 2d 41 42 43 35 33 36 34 32 39 43 42 35) | (35 00 41 00 33 00 46 00 43 00 38 00 34 00 30 00 2d 00 35 00 34 00 33 00 32 00 2d 00 34 00 39 00 32 00 35 00 2d 00 42 00 35 00 42 00 43 00 2d 00 41 00 42 00 43 00 35 00 33 00 36 00 34 00 32 00 39 00 43 00 42 00 35 00))}
		$typelibguid2lo = {((36 66 30 62 62 62 32 61 2d 65 32 30 30 2d 34 64 37 36 2d 62 38 66 61 2d 66 39 33 63 38 30 31 61 63 32 32 30) | (36 00 66 00 30 00 62 00 62 00 62 00 32 00 61 00 2d 00 65 00 32 00 30 00 30 00 2d 00 34 00 64 00 37 00 36 00 2d 00 62 00 38 00 66 00 61 00 2d 00 66 00 39 00 33 00 63 00 38 00 30 00 31 00 61 00 63 00 32 00 32 00 30 00))}
		$typelibguid2up = {((36 46 30 42 42 42 32 41 2d 45 32 30 30 2d 34 44 37 36 2d 42 38 46 41 2d 46 39 33 43 38 30 31 41 43 32 32 30) | (36 00 46 00 30 00 42 00 42 00 42 00 32 00 41 00 2d 00 45 00 32 00 30 00 30 00 2d 00 34 00 44 00 37 00 36 00 2d 00 42 00 38 00 46 00 41 00 2d 00 46 00 39 00 33 00 43 00 38 00 30 00 31 00 41 00 43 00 32 00 32 00 30 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_aresskit : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/BlackVikingPro/aresskit"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "8265cd84-c8e7-5654-9d3a-774dab52d938"

	strings:
		$typelibguid0lo = {((38 64 63 61 30 65 34 32 2d 66 37 36 37 2d 34 31 31 64 2d 39 37 30 34 2d 61 65 30 62 61 34 61 34 34 61 65 38) | (38 00 64 00 63 00 61 00 30 00 65 00 34 00 32 00 2d 00 66 00 37 00 36 00 37 00 2d 00 34 00 31 00 31 00 64 00 2d 00 39 00 37 00 30 00 34 00 2d 00 61 00 65 00 30 00 62 00 61 00 34 00 61 00 34 00 34 00 61 00 65 00 38 00))}
		$typelibguid0up = {((38 44 43 41 30 45 34 32 2d 46 37 36 37 2d 34 31 31 44 2d 39 37 30 34 2d 41 45 30 42 41 34 41 34 34 41 45 38) | (38 00 44 00 43 00 41 00 30 00 45 00 34 00 32 00 2d 00 46 00 37 00 36 00 37 00 2d 00 34 00 31 00 31 00 44 00 2d 00 39 00 37 00 30 00 34 00 2d 00 41 00 45 00 30 00 42 00 41 00 34 00 41 00 34 00 34 00 41 00 45 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_DLL_Injector : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tmthrgd/DLL-Injector"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "301e70f4-89ed-539c-b7f3-9fc6ae1393b3"

	strings:
		$typelibguid0lo = {((34 35 38 31 61 34 34 39 2d 37 64 32 30 2d 34 63 35 39 2d 38 64 61 32 2d 37 66 64 38 33 30 66 31 66 64 35 65) | (34 00 35 00 38 00 31 00 61 00 34 00 34 00 39 00 2d 00 37 00 64 00 32 00 30 00 2d 00 34 00 63 00 35 00 39 00 2d 00 38 00 64 00 61 00 32 00 2d 00 37 00 66 00 64 00 38 00 33 00 30 00 66 00 31 00 66 00 64 00 35 00 65 00))}
		$typelibguid0up = {((34 35 38 31 41 34 34 39 2d 37 44 32 30 2d 34 43 35 39 2d 38 44 41 32 2d 37 46 44 38 33 30 46 31 46 44 35 45) | (34 00 35 00 38 00 31 00 41 00 34 00 34 00 39 00 2d 00 37 00 44 00 32 00 30 00 2d 00 34 00 43 00 35 00 39 00 2d 00 38 00 44 00 41 00 32 00 2d 00 37 00 46 00 44 00 38 00 33 00 30 00 46 00 31 00 46 00 44 00 35 00 45 00))}
		$typelibguid1lo = {((30 35 66 34 62 32 33 38 2d 32 35 63 65 2d 34 30 64 63 2d 61 38 39 30 2d 64 35 62 62 62 38 36 34 32 65 65 34) | (30 00 35 00 66 00 34 00 62 00 32 00 33 00 38 00 2d 00 32 00 35 00 63 00 65 00 2d 00 34 00 30 00 64 00 63 00 2d 00 61 00 38 00 39 00 30 00 2d 00 64 00 35 00 62 00 62 00 62 00 38 00 36 00 34 00 32 00 65 00 65 00 34 00))}
		$typelibguid1up = {((30 35 46 34 42 32 33 38 2d 32 35 43 45 2d 34 30 44 43 2d 41 38 39 30 2d 44 35 42 42 42 38 36 34 32 45 45 34) | (30 00 35 00 46 00 34 00 42 00 32 00 33 00 38 00 2d 00 32 00 35 00 43 00 45 00 2d 00 34 00 30 00 44 00 43 00 2d 00 41 00 38 00 39 00 30 00 2d 00 44 00 35 00 42 00 42 00 42 00 38 00 36 00 34 00 32 00 45 00 45 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_TruffleSnout : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/dsnezhkov/TruffleSnout"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "8135d39e-6a9e-567d-840f-8d8c6338cce1"

	strings:
		$typelibguid0lo = {((33 33 38 34 32 64 37 37 2d 62 63 65 33 2d 34 65 65 38 2d 39 65 65 32 2d 39 37 36 39 38 39 38 62 62 34 32 39) | (33 00 33 00 38 00 34 00 32 00 64 00 37 00 37 00 2d 00 62 00 63 00 65 00 33 00 2d 00 34 00 65 00 65 00 38 00 2d 00 39 00 65 00 65 00 32 00 2d 00 39 00 37 00 36 00 39 00 38 00 39 00 38 00 62 00 62 00 34 00 32 00 39 00))}
		$typelibguid0up = {((33 33 38 34 32 44 37 37 2d 42 43 45 33 2d 34 45 45 38 2d 39 45 45 32 2d 39 37 36 39 38 39 38 42 42 34 32 39) | (33 00 33 00 38 00 34 00 32 00 44 00 37 00 37 00 2d 00 42 00 43 00 45 00 33 00 2d 00 34 00 45 00 45 00 38 00 2d 00 39 00 45 00 45 00 32 00 2d 00 39 00 37 00 36 00 39 00 38 00 39 00 38 00 42 00 42 00 34 00 32 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Anti_Analysis : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Anti-Analysis"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "bd527841-065e-57e9-b70e-c9d232072f1b"

	strings:
		$typelibguid0lo = {((33 30 39 32 63 38 64 66 2d 65 39 65 34 2d 34 62 37 35 2d 62 37 38 65 2d 66 38 31 61 30 30 35 38 61 36 33 35) | (33 00 30 00 39 00 32 00 63 00 38 00 64 00 66 00 2d 00 65 00 39 00 65 00 34 00 2d 00 34 00 62 00 37 00 35 00 2d 00 62 00 37 00 38 00 65 00 2d 00 66 00 38 00 31 00 61 00 30 00 30 00 35 00 38 00 61 00 36 00 33 00 35 00))}
		$typelibguid0up = {((33 30 39 32 43 38 44 46 2d 45 39 45 34 2d 34 42 37 35 2d 42 37 38 45 2d 46 38 31 41 30 30 35 38 41 36 33 35) | (33 00 30 00 39 00 32 00 43 00 38 00 44 00 46 00 2d 00 45 00 39 00 45 00 34 00 2d 00 34 00 42 00 37 00 35 00 2d 00 42 00 37 00 38 00 45 00 2d 00 46 00 38 00 31 00 41 00 30 00 30 00 35 00 38 00 41 00 36 00 33 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_BackNet : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/valsov/BackNet"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "91824d18-f46b-5b95-b650-4d710d711cf9"

	strings:
		$typelibguid0lo = {((39 66 64 61 65 31 32 32 2d 63 64 31 65 2d 34 36 37 64 2d 61 36 66 61 2d 61 39 38 63 32 36 65 37 36 33 34 38) | (39 00 66 00 64 00 61 00 65 00 31 00 32 00 32 00 2d 00 63 00 64 00 31 00 65 00 2d 00 34 00 36 00 37 00 64 00 2d 00 61 00 36 00 66 00 61 00 2d 00 61 00 39 00 38 00 63 00 32 00 36 00 65 00 37 00 36 00 33 00 34 00 38 00))}
		$typelibguid0up = {((39 46 44 41 45 31 32 32 2d 43 44 31 45 2d 34 36 37 44 2d 41 36 46 41 2d 41 39 38 43 32 36 45 37 36 33 34 38) | (39 00 46 00 44 00 41 00 45 00 31 00 32 00 32 00 2d 00 43 00 44 00 31 00 45 00 2d 00 34 00 36 00 37 00 44 00 2d 00 41 00 36 00 46 00 41 00 2d 00 41 00 39 00 38 00 43 00 32 00 36 00 45 00 37 00 36 00 33 00 34 00 38 00))}
		$typelibguid1lo = {((32 34 33 63 32 37 39 65 2d 33 33 61 36 2d 34 36 61 31 2d 62 65 61 62 2d 32 38 36 34 63 63 37 61 34 39 39 66) | (32 00 34 00 33 00 63 00 32 00 37 00 39 00 65 00 2d 00 33 00 33 00 61 00 36 00 2d 00 34 00 36 00 61 00 31 00 2d 00 62 00 65 00 61 00 62 00 2d 00 32 00 38 00 36 00 34 00 63 00 63 00 37 00 61 00 34 00 39 00 39 00 66 00))}
		$typelibguid1up = {((32 34 33 43 32 37 39 45 2d 33 33 41 36 2d 34 36 41 31 2d 42 45 41 42 2d 32 38 36 34 43 43 37 41 34 39 39 46) | (32 00 34 00 33 00 43 00 32 00 37 00 39 00 45 00 2d 00 33 00 33 00 41 00 36 00 2d 00 34 00 36 00 41 00 31 00 2d 00 42 00 45 00 41 00 42 00 2d 00 32 00 38 00 36 00 34 00 43 00 43 00 37 00 41 00 34 00 39 00 39 00 46 00))}
		$typelibguid2lo = {((61 37 33 30 31 33 38 34 2d 37 33 35 34 2d 34 37 66 64 2d 61 34 63 35 2d 36 35 62 37 34 65 30 62 62 62 34 36) | (61 00 37 00 33 00 30 00 31 00 33 00 38 00 34 00 2d 00 37 00 33 00 35 00 34 00 2d 00 34 00 37 00 66 00 64 00 2d 00 61 00 34 00 63 00 35 00 2d 00 36 00 35 00 62 00 37 00 34 00 65 00 30 00 62 00 62 00 62 00 34 00 36 00))}
		$typelibguid2up = {((41 37 33 30 31 33 38 34 2d 37 33 35 34 2d 34 37 46 44 2d 41 34 43 35 2d 36 35 42 37 34 45 30 42 42 42 34 36) | (41 00 37 00 33 00 30 00 31 00 33 00 38 00 34 00 2d 00 37 00 33 00 35 00 34 00 2d 00 34 00 37 00 46 00 44 00 2d 00 41 00 34 00 43 00 35 00 2d 00 36 00 35 00 42 00 37 00 34 00 45 00 30 00 42 00 42 00 42 00 34 00 36 00))}
		$typelibguid3lo = {((39 38 32 64 63 35 62 36 2d 31 31 32 33 2d 34 32 38 61 2d 38 33 64 64 2d 64 32 31 32 34 39 30 63 38 35 39 66) | (39 00 38 00 32 00 64 00 63 00 35 00 62 00 36 00 2d 00 31 00 31 00 32 00 33 00 2d 00 34 00 32 00 38 00 61 00 2d 00 38 00 33 00 64 00 64 00 2d 00 64 00 32 00 31 00 32 00 34 00 39 00 30 00 63 00 38 00 35 00 39 00 66 00))}
		$typelibguid3up = {((39 38 32 44 43 35 42 36 2d 31 31 32 33 2d 34 32 38 41 2d 38 33 44 44 2d 44 32 31 32 34 39 30 43 38 35 39 46) | (39 00 38 00 32 00 44 00 43 00 35 00 42 00 36 00 2d 00 31 00 31 00 32 00 33 00 2d 00 34 00 32 00 38 00 41 00 2d 00 38 00 33 00 44 00 44 00 2d 00 44 00 32 00 31 00 32 00 34 00 39 00 30 00 43 00 38 00 35 00 39 00 46 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_AllTheThings : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/johnjohnsp1/AllTheThings"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "c35160cb-ad31-5195-a7c6-0af91a58737d"

	strings:
		$typelibguid0lo = {((30 35 34 37 66 66 34 30 2d 35 32 35 35 2d 34 32 61 32 2d 62 65 62 37 2d 32 66 66 30 64 62 66 37 64 33 62 61) | (30 00 35 00 34 00 37 00 66 00 66 00 34 00 30 00 2d 00 35 00 32 00 35 00 35 00 2d 00 34 00 32 00 61 00 32 00 2d 00 62 00 65 00 62 00 37 00 2d 00 32 00 66 00 66 00 30 00 64 00 62 00 66 00 37 00 64 00 33 00 62 00 61 00))}
		$typelibguid0up = {((30 35 34 37 46 46 34 30 2d 35 32 35 35 2d 34 32 41 32 2d 42 45 42 37 2d 32 46 46 30 44 42 46 37 44 33 42 41) | (30 00 35 00 34 00 37 00 46 00 46 00 34 00 30 00 2d 00 35 00 32 00 35 00 35 00 2d 00 34 00 32 00 41 00 32 00 2d 00 42 00 45 00 42 00 37 00 2d 00 32 00 46 00 46 00 30 00 44 00 42 00 46 00 37 00 44 00 33 00 42 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_AddReferenceDotRedTeam : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ceramicskate0/AddReferenceDotRedTeam"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "59299a72-9b7a-5108-81c2-d8f6d2e99b20"

	strings:
		$typelibguid0lo = {((37 33 63 37 39 64 37 65 2d 31 37 64 34 2d 34 36 63 39 2d 62 65 35 61 2d 65 63 65 66 36 35 62 39 32 34 65 34) | (37 00 33 00 63 00 37 00 39 00 64 00 37 00 65 00 2d 00 31 00 37 00 64 00 34 00 2d 00 34 00 36 00 63 00 39 00 2d 00 62 00 65 00 35 00 61 00 2d 00 65 00 63 00 65 00 66 00 36 00 35 00 62 00 39 00 32 00 34 00 65 00 34 00))}
		$typelibguid0up = {((37 33 43 37 39 44 37 45 2d 31 37 44 34 2d 34 36 43 39 2d 42 45 35 41 2d 45 43 45 46 36 35 42 39 32 34 45 34) | (37 00 33 00 43 00 37 00 39 00 44 00 37 00 45 00 2d 00 31 00 37 00 44 00 34 00 2d 00 34 00 36 00 43 00 39 00 2d 00 42 00 45 00 35 00 41 00 2d 00 45 00 43 00 45 00 46 00 36 00 35 00 42 00 39 00 32 00 34 00 45 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Lime_Crypter : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Lime-Crypter"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "484c7a15-7ab2-57d3-848c-0fddff753d52"

	strings:
		$typelibguid0lo = {((66 39 33 63 39 39 65 64 2d 32 38 63 39 2d 34 38 63 35 2d 62 62 39 30 2d 64 64 39 38 66 31 38 32 38 35 61 36) | (66 00 39 00 33 00 63 00 39 00 39 00 65 00 64 00 2d 00 32 00 38 00 63 00 39 00 2d 00 34 00 38 00 63 00 35 00 2d 00 62 00 62 00 39 00 30 00 2d 00 64 00 64 00 39 00 38 00 66 00 31 00 38 00 32 00 38 00 35 00 61 00 36 00))}
		$typelibguid0up = {((46 39 33 43 39 39 45 44 2d 32 38 43 39 2d 34 38 43 35 2d 42 42 39 30 2d 44 44 39 38 46 31 38 32 38 35 41 36) | (46 00 39 00 33 00 43 00 39 00 39 00 45 00 44 00 2d 00 32 00 38 00 43 00 39 00 2d 00 34 00 38 00 43 00 35 00 2d 00 42 00 42 00 39 00 30 00 2d 00 44 00 44 00 39 00 38 00 46 00 31 00 38 00 32 00 38 00 35 00 41 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

import "pe"

rule HKTL_NET_GUID_BrowserGhost : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/QAX-A-Team/BrowserGhost"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		modified = "2023-04-06"
		id = "adcc5d12-c393-5708-ae0b-a85f2187c881"

	strings:
		$typelibguid0lo = {((32 31 33 33 63 36 33 34 2d 34 31 33 39 2d 34 36 36 65 2d 38 39 38 33 2d 39 61 32 33 65 63 39 39 65 30 31 62) | (32 00 31 00 33 00 33 00 63 00 36 00 33 00 34 00 2d 00 34 00 31 00 33 00 39 00 2d 00 34 00 36 00 36 00 65 00 2d 00 38 00 39 00 38 00 33 00 2d 00 39 00 61 00 32 00 33 00 65 00 63 00 39 00 39 00 65 00 30 00 31 00 62 00))}
		$typelibguid0up = {((32 31 33 33 43 36 33 34 2d 34 31 33 39 2d 34 36 36 45 2d 38 39 38 33 2d 39 41 32 33 45 43 39 39 45 30 31 42) | (32 00 31 00 33 00 33 00 43 00 36 00 33 00 34 00 2d 00 34 00 31 00 33 00 39 00 2d 00 34 00 36 00 36 00 45 00 2d 00 38 00 39 00 38 00 33 00 2d 00 39 00 41 00 32 00 33 00 45 00 43 00 39 00 39 00 45 00 30 00 31 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them and not pe.is_dll ( )
}

rule HKTL_NET_GUID_SharpShot : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tothi/SharpShot"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "9d59cd53-53b1-57db-b391-eee4dd6feec0"

	strings:
		$typelibguid0lo = {((30 35 37 61 65 66 37 35 2d 38 36 31 62 2d 34 65 34 62 2d 61 33 37 32 2d 63 66 62 64 38 33 32 32 63 38 65 31) | (30 00 35 00 37 00 61 00 65 00 66 00 37 00 35 00 2d 00 38 00 36 00 31 00 62 00 2d 00 34 00 65 00 34 00 62 00 2d 00 61 00 33 00 37 00 32 00 2d 00 63 00 66 00 62 00 64 00 38 00 33 00 32 00 32 00 63 00 38 00 65 00 31 00))}
		$typelibguid0up = {((30 35 37 41 45 46 37 35 2d 38 36 31 42 2d 34 45 34 42 2d 41 33 37 32 2d 43 46 42 44 38 33 32 32 43 38 45 31) | (30 00 35 00 37 00 41 00 45 00 46 00 37 00 35 00 2d 00 38 00 36 00 31 00 42 00 2d 00 34 00 45 00 34 00 42 00 2d 00 41 00 33 00 37 00 32 00 2d 00 43 00 46 00 42 00 44 00 38 00 33 00 32 00 32 00 43 00 38 00 45 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Offensive__NET : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mrjamiebowman/Offensive-.NET"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "b98495fb-0338-5042-a7ce-d117204eb91e"

	strings:
		$typelibguid0lo = {((31 31 66 65 35 66 61 65 2d 62 37 63 31 2d 34 38 34 61 2d 62 31 36 32 2d 64 35 35 37 38 61 38 30 32 63 39 63) | (31 00 31 00 66 00 65 00 35 00 66 00 61 00 65 00 2d 00 62 00 37 00 63 00 31 00 2d 00 34 00 38 00 34 00 61 00 2d 00 62 00 31 00 36 00 32 00 2d 00 64 00 35 00 35 00 37 00 38 00 61 00 38 00 30 00 32 00 63 00 39 00 63 00))}
		$typelibguid0up = {((31 31 46 45 35 46 41 45 2d 42 37 43 31 2d 34 38 34 41 2d 42 31 36 32 2d 44 35 35 37 38 41 38 30 32 43 39 43) | (31 00 31 00 46 00 45 00 35 00 46 00 41 00 45 00 2d 00 42 00 37 00 43 00 31 00 2d 00 34 00 38 00 34 00 41 00 2d 00 42 00 31 00 36 00 32 00 2d 00 44 00 35 00 35 00 37 00 38 00 41 00 38 00 30 00 32 00 43 00 39 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_RuralBishop : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rasta-mouse/RuralBishop"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "8fd89465-1ecc-5eda-b2ab-273172ad945d"

	strings:
		$typelibguid0lo = {((66 65 34 34 31 34 64 39 2d 31 64 37 65 2d 34 65 65 62 2d 62 37 38 31 2d 64 32 37 38 66 65 37 61 35 36 31 39) | (66 00 65 00 34 00 34 00 31 00 34 00 64 00 39 00 2d 00 31 00 64 00 37 00 65 00 2d 00 34 00 65 00 65 00 62 00 2d 00 62 00 37 00 38 00 31 00 2d 00 64 00 32 00 37 00 38 00 66 00 65 00 37 00 61 00 35 00 36 00 31 00 39 00))}
		$typelibguid0up = {((46 45 34 34 31 34 44 39 2d 31 44 37 45 2d 34 45 45 42 2d 42 37 38 31 2d 44 32 37 38 46 45 37 41 35 36 31 39) | (46 00 45 00 34 00 34 00 31 00 34 00 44 00 39 00 2d 00 31 00 44 00 37 00 45 00 2d 00 34 00 45 00 45 00 42 00 2d 00 42 00 37 00 38 00 31 00 2d 00 44 00 32 00 37 00 38 00 46 00 45 00 37 00 41 00 35 00 36 00 31 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_DeviceGuardBypasses : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tyranid/DeviceGuardBypasses"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "3790faac-b5be-5999-b35f-71a2ef02b6ed"

	strings:
		$typelibguid0lo = {((66 33 31 38 34 36 36 64 2d 64 33 31 30 2d 34 39 61 64 2d 61 39 36 37 2d 36 37 65 66 62 62 61 32 39 38 39 38) | (66 00 33 00 31 00 38 00 34 00 36 00 36 00 64 00 2d 00 64 00 33 00 31 00 30 00 2d 00 34 00 39 00 61 00 64 00 2d 00 61 00 39 00 36 00 37 00 2d 00 36 00 37 00 65 00 66 00 62 00 62 00 61 00 32 00 39 00 38 00 39 00 38 00))}
		$typelibguid0up = {((46 33 31 38 34 36 36 44 2d 44 33 31 30 2d 34 39 41 44 2d 41 39 36 37 2d 36 37 45 46 42 42 41 32 39 38 39 38) | (46 00 33 00 31 00 38 00 34 00 36 00 36 00 44 00 2d 00 44 00 33 00 31 00 30 00 2d 00 34 00 39 00 41 00 44 00 2d 00 41 00 39 00 36 00 37 00 2d 00 36 00 37 00 45 00 46 00 42 00 42 00 41 00 32 00 39 00 38 00 39 00 38 00))}
		$typelibguid1lo = {((33 37 30 35 38 30 30 66 2d 31 34 32 34 2d 34 36 35 62 2d 39 33 37 64 2d 35 38 36 65 33 61 36 32 32 61 34 66) | (33 00 37 00 30 00 35 00 38 00 30 00 30 00 66 00 2d 00 31 00 34 00 32 00 34 00 2d 00 34 00 36 00 35 00 62 00 2d 00 39 00 33 00 37 00 64 00 2d 00 35 00 38 00 36 00 65 00 33 00 61 00 36 00 32 00 32 00 61 00 34 00 66 00))}
		$typelibguid1up = {((33 37 30 35 38 30 30 46 2d 31 34 32 34 2d 34 36 35 42 2d 39 33 37 44 2d 35 38 36 45 33 41 36 32 32 41 34 46) | (33 00 37 00 30 00 35 00 38 00 30 00 30 00 46 00 2d 00 31 00 34 00 32 00 34 00 2d 00 34 00 36 00 35 00 42 00 2d 00 39 00 33 00 37 00 44 00 2d 00 35 00 38 00 36 00 45 00 33 00 41 00 36 00 32 00 32 00 41 00 34 00 46 00))}
		$typelibguid2lo = {((32 35 36 36 30 37 63 32 2d 34 31 32 36 2d 34 32 37 32 2d 61 32 66 61 2d 61 31 66 66 63 30 61 37 33 34 66 30) | (32 00 35 00 36 00 36 00 30 00 37 00 63 00 32 00 2d 00 34 00 31 00 32 00 36 00 2d 00 34 00 32 00 37 00 32 00 2d 00 61 00 32 00 66 00 61 00 2d 00 61 00 31 00 66 00 66 00 63 00 30 00 61 00 37 00 33 00 34 00 66 00 30 00))}
		$typelibguid2up = {((32 35 36 36 30 37 43 32 2d 34 31 32 36 2d 34 32 37 32 2d 41 32 46 41 2d 41 31 46 46 43 30 41 37 33 34 46 30) | (32 00 35 00 36 00 36 00 30 00 37 00 43 00 32 00 2d 00 34 00 31 00 32 00 36 00 2d 00 34 00 32 00 37 00 32 00 2d 00 41 00 32 00 46 00 41 00 2d 00 41 00 31 00 46 00 46 00 43 00 30 00 41 00 37 00 33 00 34 00 46 00 30 00))}
		$typelibguid3lo = {((34 65 36 63 65 65 61 31 2d 66 32 36 36 2d 34 30 31 63 2d 62 38 33 32 2d 66 39 31 34 33 32 64 34 36 66 34 32) | (34 00 65 00 36 00 63 00 65 00 65 00 61 00 31 00 2d 00 66 00 32 00 36 00 36 00 2d 00 34 00 30 00 31 00 63 00 2d 00 62 00 38 00 33 00 32 00 2d 00 66 00 39 00 31 00 34 00 33 00 32 00 64 00 34 00 36 00 66 00 34 00 32 00))}
		$typelibguid3up = {((34 45 36 43 45 45 41 31 2d 46 32 36 36 2d 34 30 31 43 2d 42 38 33 32 2d 46 39 31 34 33 32 44 34 36 46 34 32) | (34 00 45 00 36 00 43 00 45 00 45 00 41 00 31 00 2d 00 46 00 32 00 36 00 36 00 2d 00 34 00 30 00 31 00 43 00 2d 00 42 00 38 00 33 00 32 00 2d 00 46 00 39 00 31 00 34 00 33 00 32 00 44 00 34 00 36 00 46 00 34 00 32 00))}
		$typelibguid4lo = {((31 65 36 65 39 62 30 33 2d 64 64 35 66 2d 34 30 34 37 2d 62 33 38 36 2d 61 66 37 61 37 39 30 34 66 38 38 34) | (31 00 65 00 36 00 65 00 39 00 62 00 30 00 33 00 2d 00 64 00 64 00 35 00 66 00 2d 00 34 00 30 00 34 00 37 00 2d 00 62 00 33 00 38 00 36 00 2d 00 61 00 66 00 37 00 61 00 37 00 39 00 30 00 34 00 66 00 38 00 38 00 34 00))}
		$typelibguid4up = {((31 45 36 45 39 42 30 33 2d 44 44 35 46 2d 34 30 34 37 2d 42 33 38 36 2d 41 46 37 41 37 39 30 34 46 38 38 34) | (31 00 45 00 36 00 45 00 39 00 42 00 30 00 33 00 2d 00 44 00 44 00 35 00 46 00 2d 00 34 00 30 00 34 00 37 00 2d 00 42 00 33 00 38 00 36 00 2d 00 41 00 46 00 37 00 41 00 37 00 39 00 30 00 34 00 46 00 38 00 38 00 34 00))}
		$typelibguid5lo = {((64 38 35 65 33 36 30 31 2d 30 34 32 31 2d 34 65 66 61 2d 61 34 37 39 2d 66 33 33 37 30 63 30 34 39 38 66 64) | (64 00 38 00 35 00 65 00 33 00 36 00 30 00 31 00 2d 00 30 00 34 00 32 00 31 00 2d 00 34 00 65 00 66 00 61 00 2d 00 61 00 34 00 37 00 39 00 2d 00 66 00 33 00 33 00 37 00 30 00 63 00 30 00 34 00 39 00 38 00 66 00 64 00))}
		$typelibguid5up = {((44 38 35 45 33 36 30 31 2d 30 34 32 31 2d 34 45 46 41 2d 41 34 37 39 2d 46 33 33 37 30 43 30 34 39 38 46 44) | (44 00 38 00 35 00 45 00 33 00 36 00 30 00 31 00 2d 00 30 00 34 00 32 00 31 00 2d 00 34 00 45 00 46 00 41 00 2d 00 41 00 34 00 37 00 39 00 2d 00 46 00 33 00 33 00 37 00 30 00 43 00 30 00 34 00 39 00 38 00 46 00 44 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_AMSI_Handler : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/two06/AMSI_Handler"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "40768acf-fa9e-531a-83fd-187814ddc2d4"

	strings:
		$typelibguid0lo = {((64 38 32 39 34 32 36 63 2d 39 38 36 63 2d 34 30 61 34 2d 38 65 65 32 2d 35 38 64 31 34 65 30 39 30 65 66 32) | (64 00 38 00 32 00 39 00 34 00 32 00 36 00 63 00 2d 00 39 00 38 00 36 00 63 00 2d 00 34 00 30 00 61 00 34 00 2d 00 38 00 65 00 65 00 32 00 2d 00 35 00 38 00 64 00 31 00 34 00 65 00 30 00 39 00 30 00 65 00 66 00 32 00))}
		$typelibguid0up = {((44 38 32 39 34 32 36 43 2d 39 38 36 43 2d 34 30 41 34 2d 38 45 45 32 2d 35 38 44 31 34 45 30 39 30 45 46 32) | (44 00 38 00 32 00 39 00 34 00 32 00 36 00 43 00 2d 00 39 00 38 00 36 00 43 00 2d 00 34 00 30 00 41 00 34 00 2d 00 38 00 45 00 45 00 32 00 2d 00 35 00 38 00 44 00 31 00 34 00 45 00 30 00 39 00 30 00 45 00 46 00 32 00))}
		$typelibguid1lo = {((38 36 36 35 32 34 31 38 2d 35 36 30 35 2d 34 33 66 64 2d 39 38 62 35 2d 38 35 39 38 32 38 62 30 37 32 62 65) | (38 00 36 00 36 00 35 00 32 00 34 00 31 00 38 00 2d 00 35 00 36 00 30 00 35 00 2d 00 34 00 33 00 66 00 64 00 2d 00 39 00 38 00 62 00 35 00 2d 00 38 00 35 00 39 00 38 00 32 00 38 00 62 00 30 00 37 00 32 00 62 00 65 00))}
		$typelibguid1up = {((38 36 36 35 32 34 31 38 2d 35 36 30 35 2d 34 33 46 44 2d 39 38 42 35 2d 38 35 39 38 32 38 42 30 37 32 42 45) | (38 00 36 00 36 00 35 00 32 00 34 00 31 00 38 00 2d 00 35 00 36 00 30 00 35 00 2d 00 34 00 33 00 46 00 44 00 2d 00 39 00 38 00 42 00 35 00 2d 00 38 00 35 00 39 00 38 00 32 00 38 00 42 00 30 00 37 00 32 00 42 00 45 00))}
		$typelibguid2lo = {((31 30 34 33 36 34 39 66 2d 31 38 65 31 2d 34 31 63 34 2d 61 65 38 64 2d 61 63 34 64 39 61 38 36 63 32 66 63) | (31 00 30 00 34 00 33 00 36 00 34 00 39 00 66 00 2d 00 31 00 38 00 65 00 31 00 2d 00 34 00 31 00 63 00 34 00 2d 00 61 00 65 00 38 00 64 00 2d 00 61 00 63 00 34 00 64 00 39 00 61 00 38 00 36 00 63 00 32 00 66 00 63 00))}
		$typelibguid2up = {((31 30 34 33 36 34 39 46 2d 31 38 45 31 2d 34 31 43 34 2d 41 45 38 44 2d 41 43 34 44 39 41 38 36 43 32 46 43) | (31 00 30 00 34 00 33 00 36 00 34 00 39 00 46 00 2d 00 31 00 38 00 45 00 31 00 2d 00 34 00 31 00 43 00 34 00 2d 00 41 00 45 00 38 00 44 00 2d 00 41 00 43 00 34 00 44 00 39 00 41 00 38 00 36 00 43 00 32 00 46 00 43 00))}
		$typelibguid3lo = {((31 64 39 32 30 62 30 33 2d 63 35 33 37 2d 34 36 35 39 2d 39 61 38 63 2d 30 39 66 62 31 64 36 31 35 65 39 38) | (31 00 64 00 39 00 32 00 30 00 62 00 30 00 33 00 2d 00 63 00 35 00 33 00 37 00 2d 00 34 00 36 00 35 00 39 00 2d 00 39 00 61 00 38 00 63 00 2d 00 30 00 39 00 66 00 62 00 31 00 64 00 36 00 31 00 35 00 65 00 39 00 38 00))}
		$typelibguid3up = {((31 44 39 32 30 42 30 33 2d 43 35 33 37 2d 34 36 35 39 2d 39 41 38 43 2d 30 39 46 42 31 44 36 31 35 45 39 38) | (31 00 44 00 39 00 32 00 30 00 42 00 30 00 33 00 2d 00 43 00 35 00 33 00 37 00 2d 00 34 00 36 00 35 00 39 00 2d 00 39 00 41 00 38 00 43 00 2d 00 30 00 39 00 46 00 42 00 31 00 44 00 36 00 31 00 35 00 45 00 39 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_RAT_TelegramSpyBot : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/SebastianEPH/RAT.TelegramSpyBot"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "57d22201-a051-5040-927c-30da3fc684fd"

	strings:
		$typelibguid0lo = {((38 36 35 33 66 61 38 38 2d 39 36 35 35 2d 34 34 30 65 2d 62 35 33 34 2d 32 36 63 33 63 37 36 30 61 30 64 33) | (38 00 36 00 35 00 33 00 66 00 61 00 38 00 38 00 2d 00 39 00 36 00 35 00 35 00 2d 00 34 00 34 00 30 00 65 00 2d 00 62 00 35 00 33 00 34 00 2d 00 32 00 36 00 63 00 33 00 63 00 37 00 36 00 30 00 61 00 30 00 64 00 33 00))}
		$typelibguid0up = {((38 36 35 33 46 41 38 38 2d 39 36 35 35 2d 34 34 30 45 2d 42 35 33 34 2d 32 36 43 33 43 37 36 30 41 30 44 33) | (38 00 36 00 35 00 33 00 46 00 41 00 38 00 38 00 2d 00 39 00 36 00 35 00 35 00 2d 00 34 00 34 00 30 00 45 00 2d 00 42 00 35 00 33 00 34 00 2d 00 32 00 36 00 43 00 33 00 43 00 37 00 36 00 30 00 41 00 30 00 44 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_TheHackToolBoxTeek : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/teeknofil/TheHackToolBoxTeek"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "ad8cf2c8-f70e-5f46-92fa-46e1fa5e683c"

	strings:
		$typelibguid0lo = {((32 61 61 38 63 32 35 34 2d 62 33 62 33 2d 34 36 39 63 2d 62 30 63 39 2d 64 63 62 65 31 64 64 31 30 31 63 30) | (32 00 61 00 61 00 38 00 63 00 32 00 35 00 34 00 2d 00 62 00 33 00 62 00 33 00 2d 00 34 00 36 00 39 00 63 00 2d 00 62 00 30 00 63 00 39 00 2d 00 64 00 63 00 62 00 65 00 31 00 64 00 64 00 31 00 30 00 31 00 63 00 30 00))}
		$typelibguid0up = {((32 41 41 38 43 32 35 34 2d 42 33 42 33 2d 34 36 39 43 2d 42 30 43 39 2d 44 43 42 45 31 44 44 31 30 31 43 30) | (32 00 41 00 41 00 38 00 43 00 32 00 35 00 34 00 2d 00 42 00 33 00 42 00 33 00 2d 00 34 00 36 00 39 00 43 00 2d 00 42 00 30 00 43 00 39 00 2d 00 44 00 43 00 42 00 45 00 31 00 44 00 44 00 31 00 30 00 31 00 43 00 30 00))}
		$typelibguid1lo = {((61 66 65 66 66 35 30 35 2d 31 34 63 31 2d 34 65 63 66 2d 62 37 31 34 2d 61 62 61 63 34 66 62 64 34 38 65 37) | (61 00 66 00 65 00 66 00 66 00 35 00 30 00 35 00 2d 00 31 00 34 00 63 00 31 00 2d 00 34 00 65 00 63 00 66 00 2d 00 62 00 37 00 31 00 34 00 2d 00 61 00 62 00 61 00 63 00 34 00 66 00 62 00 64 00 34 00 38 00 65 00 37 00))}
		$typelibguid1up = {((41 46 45 46 46 35 30 35 2d 31 34 43 31 2d 34 45 43 46 2d 42 37 31 34 2d 41 42 41 43 34 46 42 44 34 38 45 37) | (41 00 46 00 45 00 46 00 46 00 35 00 30 00 35 00 2d 00 31 00 34 00 43 00 31 00 2d 00 34 00 45 00 43 00 46 00 2d 00 42 00 37 00 31 00 34 00 2d 00 41 00 42 00 41 00 43 00 34 00 46 00 42 00 44 00 34 00 38 00 45 00 37 00))}
		$typelibguid2lo = {((34 63 66 34 32 31 36 37 2d 61 35 63 66 2d 34 62 32 64 2d 38 35 62 34 2d 38 65 37 36 34 63 30 38 64 36 62 33) | (34 00 63 00 66 00 34 00 32 00 31 00 36 00 37 00 2d 00 61 00 35 00 63 00 66 00 2d 00 34 00 62 00 32 00 64 00 2d 00 38 00 35 00 62 00 34 00 2d 00 38 00 65 00 37 00 36 00 34 00 63 00 30 00 38 00 64 00 36 00 62 00 33 00))}
		$typelibguid2up = {((34 43 46 34 32 31 36 37 2d 41 35 43 46 2d 34 42 32 44 2d 38 35 42 34 2d 38 45 37 36 34 43 30 38 44 36 42 33) | (34 00 43 00 46 00 34 00 32 00 31 00 36 00 37 00 2d 00 41 00 35 00 43 00 46 00 2d 00 34 00 42 00 32 00 44 00 2d 00 38 00 35 00 42 00 34 00 2d 00 38 00 45 00 37 00 36 00 34 00 43 00 30 00 38 00 44 00 36 00 42 00 33 00))}
		$typelibguid3lo = {((31 31 38 61 39 30 62 37 2d 35 39 38 61 2d 34 63 66 63 2d 38 35 39 65 2d 38 30 31 33 63 38 62 39 33 33 39 63) | (31 00 31 00 38 00 61 00 39 00 30 00 62 00 37 00 2d 00 35 00 39 00 38 00 61 00 2d 00 34 00 63 00 66 00 63 00 2d 00 38 00 35 00 39 00 65 00 2d 00 38 00 30 00 31 00 33 00 63 00 38 00 62 00 39 00 33 00 33 00 39 00 63 00))}
		$typelibguid3up = {((31 31 38 41 39 30 42 37 2d 35 39 38 41 2d 34 43 46 43 2d 38 35 39 45 2d 38 30 31 33 43 38 42 39 33 33 39 43) | (31 00 31 00 38 00 41 00 39 00 30 00 42 00 37 00 2d 00 35 00 39 00 38 00 41 00 2d 00 34 00 43 00 46 00 43 00 2d 00 38 00 35 00 39 00 45 00 2d 00 38 00 30 00 31 00 33 00 43 00 38 00 42 00 39 00 33 00 33 00 39 00 43 00))}
		$typelibguid4lo = {((33 30 37 35 64 64 39 61 2d 34 32 38 33 2d 34 64 33 38 2d 61 32 35 65 2d 39 66 39 38 34 35 65 35 61 64 63 62) | (33 00 30 00 37 00 35 00 64 00 64 00 39 00 61 00 2d 00 34 00 32 00 38 00 33 00 2d 00 34 00 64 00 33 00 38 00 2d 00 61 00 32 00 35 00 65 00 2d 00 39 00 66 00 39 00 38 00 34 00 35 00 65 00 35 00 61 00 64 00 63 00 62 00))}
		$typelibguid4up = {((33 30 37 35 44 44 39 41 2d 34 32 38 33 2d 34 44 33 38 2d 41 32 35 45 2d 39 46 39 38 34 35 45 35 41 44 43 42) | (33 00 30 00 37 00 35 00 44 00 44 00 39 00 41 00 2d 00 34 00 32 00 38 00 33 00 2d 00 34 00 44 00 33 00 38 00 2d 00 41 00 32 00 35 00 45 00 2d 00 39 00 46 00 39 00 38 00 34 00 35 00 45 00 35 00 41 00 44 00 43 00 42 00))}
		$typelibguid5lo = {((32 39 35 36 35 35 65 38 2d 32 33 34 38 2d 34 37 30 30 2d 39 65 62 63 2d 61 61 35 37 64 66 35 34 38 38 37 65) | (32 00 39 00 35 00 36 00 35 00 35 00 65 00 38 00 2d 00 32 00 33 00 34 00 38 00 2d 00 34 00 37 00 30 00 30 00 2d 00 39 00 65 00 62 00 63 00 2d 00 61 00 61 00 35 00 37 00 64 00 66 00 35 00 34 00 38 00 38 00 37 00 65 00))}
		$typelibguid5up = {((32 39 35 36 35 35 45 38 2d 32 33 34 38 2d 34 37 30 30 2d 39 45 42 43 2d 41 41 35 37 44 46 35 34 38 38 37 45) | (32 00 39 00 35 00 36 00 35 00 35 00 45 00 38 00 2d 00 32 00 33 00 34 00 38 00 2d 00 34 00 37 00 30 00 30 00 2d 00 39 00 45 00 42 00 43 00 2d 00 41 00 41 00 35 00 37 00 44 00 46 00 35 00 34 00 38 00 38 00 37 00 45 00))}
		$typelibguid6lo = {((37 34 65 66 65 36 30 31 2d 39 61 39 33 2d 34 36 63 33 2d 39 33 32 65 2d 62 38 30 61 62 36 35 37 30 65 34 32) | (37 00 34 00 65 00 66 00 65 00 36 00 30 00 31 00 2d 00 39 00 61 00 39 00 33 00 2d 00 34 00 36 00 63 00 33 00 2d 00 39 00 33 00 32 00 65 00 2d 00 62 00 38 00 30 00 61 00 62 00 36 00 35 00 37 00 30 00 65 00 34 00 32 00))}
		$typelibguid6up = {((37 34 45 46 45 36 30 31 2d 39 41 39 33 2d 34 36 43 33 2d 39 33 32 45 2d 42 38 30 41 42 36 35 37 30 45 34 32) | (37 00 34 00 45 00 46 00 45 00 36 00 30 00 31 00 2d 00 39 00 41 00 39 00 33 00 2d 00 34 00 36 00 43 00 33 00 2d 00 39 00 33 00 32 00 45 00 2d 00 42 00 38 00 30 00 41 00 42 00 36 00 35 00 37 00 30 00 45 00 34 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_USBTrojan : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mashed-potatoes/USBTrojan"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "d25c9033-13e8-5fc9-8561-f8862cca39b8"

	strings:
		$typelibguid0lo = {((34 65 65 65 39 30 30 65 2d 61 64 63 35 2d 34 36 61 37 2d 38 64 37 64 2d 38 37 33 66 64 36 61 65 61 38 33 65) | (34 00 65 00 65 00 65 00 39 00 30 00 30 00 65 00 2d 00 61 00 64 00 63 00 35 00 2d 00 34 00 36 00 61 00 37 00 2d 00 38 00 64 00 37 00 64 00 2d 00 38 00 37 00 33 00 66 00 64 00 36 00 61 00 65 00 61 00 38 00 33 00 65 00))}
		$typelibguid0up = {((34 45 45 45 39 30 30 45 2d 41 44 43 35 2d 34 36 41 37 2d 38 44 37 44 2d 38 37 33 46 44 36 41 45 41 38 33 45) | (34 00 45 00 45 00 45 00 39 00 30 00 30 00 45 00 2d 00 41 00 44 00 43 00 35 00 2d 00 34 00 36 00 41 00 37 00 2d 00 38 00 44 00 37 00 44 00 2d 00 38 00 37 00 33 00 46 00 44 00 36 00 41 00 45 00 41 00 38 00 33 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_IIS_backdoor : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/WBGlIl/IIS_backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "44264dd9-f8e9-5a60-847f-94378e07a327"

	strings:
		$typelibguid0lo = {((33 66 64 61 34 61 61 39 2d 36 66 63 31 2d 34 37 33 66 2d 39 30 34 38 2d 37 65 64 63 30 35 38 63 34 66 36 35) | (33 00 66 00 64 00 61 00 34 00 61 00 61 00 39 00 2d 00 36 00 66 00 63 00 31 00 2d 00 34 00 37 00 33 00 66 00 2d 00 39 00 30 00 34 00 38 00 2d 00 37 00 65 00 64 00 63 00 30 00 35 00 38 00 63 00 34 00 66 00 36 00 35 00))}
		$typelibguid0up = {((33 46 44 41 34 41 41 39 2d 36 46 43 31 2d 34 37 33 46 2d 39 30 34 38 2d 37 45 44 43 30 35 38 43 34 46 36 35) | (33 00 46 00 44 00 41 00 34 00 41 00 41 00 39 00 2d 00 36 00 46 00 43 00 31 00 2d 00 34 00 37 00 33 00 46 00 2d 00 39 00 30 00 34 00 38 00 2d 00 37 00 45 00 44 00 43 00 30 00 35 00 38 00 43 00 34 00 46 00 36 00 35 00))}
		$typelibguid1lo = {((37 33 63 61 34 31 35 39 2d 35 64 31 33 2d 34 61 32 37 2d 38 39 36 35 2d 64 35 30 63 34 31 61 62 32 30 33 63) | (37 00 33 00 63 00 61 00 34 00 31 00 35 00 39 00 2d 00 35 00 64 00 31 00 33 00 2d 00 34 00 61 00 32 00 37 00 2d 00 38 00 39 00 36 00 35 00 2d 00 64 00 35 00 30 00 63 00 34 00 31 00 61 00 62 00 32 00 30 00 33 00 63 00))}
		$typelibguid1up = {((37 33 43 41 34 31 35 39 2d 35 44 31 33 2d 34 41 32 37 2d 38 39 36 35 2d 44 35 30 43 34 31 41 42 32 30 33 43) | (37 00 33 00 43 00 41 00 34 00 31 00 35 00 39 00 2d 00 35 00 44 00 31 00 33 00 2d 00 34 00 41 00 32 00 37 00 2d 00 38 00 39 00 36 00 35 00 2d 00 44 00 35 00 30 00 43 00 34 00 31 00 41 00 42 00 32 00 30 00 33 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_ShellGen : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jasondrawdy/ShellGen"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "538a4f12-5020-5c76-9208-363f435ed9a9"

	strings:
		$typelibguid0lo = {((63 36 38 39 34 38 38 32 2d 64 32 39 64 2d 34 61 65 31 2d 61 65 62 37 2d 37 64 30 61 39 62 39 31 35 30 31 33) | (63 00 36 00 38 00 39 00 34 00 38 00 38 00 32 00 2d 00 64 00 32 00 39 00 64 00 2d 00 34 00 61 00 65 00 31 00 2d 00 61 00 65 00 62 00 37 00 2d 00 37 00 64 00 30 00 61 00 39 00 62 00 39 00 31 00 35 00 30 00 31 00 33 00))}
		$typelibguid0up = {((43 36 38 39 34 38 38 32 2d 44 32 39 44 2d 34 41 45 31 2d 41 45 42 37 2d 37 44 30 41 39 42 39 31 35 30 31 33) | (43 00 36 00 38 00 39 00 34 00 38 00 38 00 32 00 2d 00 44 00 32 00 39 00 44 00 2d 00 34 00 41 00 45 00 31 00 2d 00 41 00 45 00 42 00 37 00 2d 00 37 00 44 00 30 00 41 00 39 00 42 00 39 00 31 00 35 00 30 00 31 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Mass_RAT : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Mass-RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "90b742da-6fd7-5c72-96cf-7a37a3e5d808"

	strings:
		$typelibguid0lo = {((36 63 34 33 61 37 35 33 2d 39 35 36 35 2d 34 38 62 32 2d 61 33 37 32 2d 34 32 31 30 62 62 31 65 30 64 37 35) | (36 00 63 00 34 00 33 00 61 00 37 00 35 00 33 00 2d 00 39 00 35 00 36 00 35 00 2d 00 34 00 38 00 62 00 32 00 2d 00 61 00 33 00 37 00 32 00 2d 00 34 00 32 00 31 00 30 00 62 00 62 00 31 00 65 00 30 00 64 00 37 00 35 00))}
		$typelibguid0up = {((36 43 34 33 41 37 35 33 2d 39 35 36 35 2d 34 38 42 32 2d 41 33 37 32 2d 34 32 31 30 42 42 31 45 30 44 37 35) | (36 00 43 00 34 00 33 00 41 00 37 00 35 00 33 00 2d 00 39 00 35 00 36 00 35 00 2d 00 34 00 38 00 42 00 32 00 2d 00 41 00 33 00 37 00 32 00 2d 00 34 00 32 00 31 00 30 00 42 00 42 00 31 00 45 00 30 00 44 00 37 00 35 00))}
		$typelibguid1lo = {((39 32 62 61 32 61 37 65 2d 63 31 39 38 2d 34 64 34 33 2d 39 32 39 65 2d 31 63 66 65 35 34 62 36 34 64 39 35) | (39 00 32 00 62 00 61 00 32 00 61 00 37 00 65 00 2d 00 63 00 31 00 39 00 38 00 2d 00 34 00 64 00 34 00 33 00 2d 00 39 00 32 00 39 00 65 00 2d 00 31 00 63 00 66 00 65 00 35 00 34 00 62 00 36 00 34 00 64 00 39 00 35 00))}
		$typelibguid1up = {((39 32 42 41 32 41 37 45 2d 43 31 39 38 2d 34 44 34 33 2d 39 32 39 45 2d 31 43 46 45 35 34 42 36 34 44 39 35) | (39 00 32 00 42 00 41 00 32 00 41 00 37 00 45 00 2d 00 43 00 31 00 39 00 38 00 2d 00 34 00 44 00 34 00 33 00 2d 00 39 00 32 00 39 00 45 00 2d 00 31 00 43 00 46 00 45 00 35 00 34 00 42 00 36 00 34 00 44 00 39 00 35 00))}
		$typelibguid2lo = {((34 63 62 39 62 62 65 65 2d 66 62 39 32 2d 34 34 66 61 2d 61 34 32 37 2d 62 37 32 34 35 62 65 66 63 32 66 33) | (34 00 63 00 62 00 39 00 62 00 62 00 65 00 65 00 2d 00 66 00 62 00 39 00 32 00 2d 00 34 00 34 00 66 00 61 00 2d 00 61 00 34 00 32 00 37 00 2d 00 62 00 37 00 32 00 34 00 35 00 62 00 65 00 66 00 63 00 32 00 66 00 33 00))}
		$typelibguid2up = {((34 43 42 39 42 42 45 45 2d 46 42 39 32 2d 34 34 46 41 2d 41 34 32 37 2d 42 37 32 34 35 42 45 46 43 32 46 33) | (34 00 43 00 42 00 39 00 42 00 42 00 45 00 45 00 2d 00 46 00 42 00 39 00 32 00 2d 00 34 00 34 00 46 00 41 00 2d 00 41 00 34 00 32 00 37 00 2d 00 42 00 37 00 32 00 34 00 35 00 42 00 45 00 46 00 43 00 32 00 46 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Browser_ExternalC2 : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mdsecactivebreach/Browser-ExternalC2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "8c309522-90e7-5f5a-b456-3a472756d397"

	strings:
		$typelibguid0lo = {((31 30 61 37 33 30 63 64 2d 39 35 31 37 2d 34 32 64 35 2d 62 33 65 33 2d 61 32 33 38 33 35 31 35 63 63 61 39) | (31 00 30 00 61 00 37 00 33 00 30 00 63 00 64 00 2d 00 39 00 35 00 31 00 37 00 2d 00 34 00 32 00 64 00 35 00 2d 00 62 00 33 00 65 00 33 00 2d 00 61 00 32 00 33 00 38 00 33 00 35 00 31 00 35 00 63 00 63 00 61 00 39 00))}
		$typelibguid0up = {((31 30 41 37 33 30 43 44 2d 39 35 31 37 2d 34 32 44 35 2d 42 33 45 33 2d 41 32 33 38 33 35 31 35 43 43 41 39) | (31 00 30 00 41 00 37 00 33 00 30 00 43 00 44 00 2d 00 39 00 35 00 31 00 37 00 2d 00 34 00 32 00 44 00 35 00 2d 00 42 00 33 00 45 00 33 00 2d 00 41 00 32 00 33 00 38 00 33 00 35 00 31 00 35 00 43 00 43 00 41 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_OffensivePowerShellTasking : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/leechristensen/OffensivePowerShellTasking"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "d221e24d-a2ef-51e2-95bf-4b91b438d9cf"

	strings:
		$typelibguid0lo = {((64 34 33 32 63 33 33 32 2d 33 62 34 38 2d 34 64 30 36 2d 62 65 64 62 2d 34 36 32 65 32 36 34 65 36 36 38 38) | (64 00 34 00 33 00 32 00 63 00 33 00 33 00 32 00 2d 00 33 00 62 00 34 00 38 00 2d 00 34 00 64 00 30 00 36 00 2d 00 62 00 65 00 64 00 62 00 2d 00 34 00 36 00 32 00 65 00 32 00 36 00 34 00 65 00 36 00 36 00 38 00 38 00))}
		$typelibguid0up = {((44 34 33 32 43 33 33 32 2d 33 42 34 38 2d 34 44 30 36 2d 42 45 44 42 2d 34 36 32 45 32 36 34 45 36 36 38 38) | (44 00 34 00 33 00 32 00 43 00 33 00 33 00 32 00 2d 00 33 00 42 00 34 00 38 00 2d 00 34 00 44 00 30 00 36 00 2d 00 42 00 45 00 44 00 42 00 2d 00 34 00 36 00 32 00 45 00 32 00 36 00 34 00 45 00 36 00 36 00 38 00 38 00))}
		$typelibguid1lo = {((35 37 39 36 32 37 36 66 2d 31 63 37 61 2d 34 64 37 62 2d 61 30 38 39 2d 35 35 30 61 38 63 31 39 64 30 65 38) | (35 00 37 00 39 00 36 00 32 00 37 00 36 00 66 00 2d 00 31 00 63 00 37 00 61 00 2d 00 34 00 64 00 37 00 62 00 2d 00 61 00 30 00 38 00 39 00 2d 00 35 00 35 00 30 00 61 00 38 00 63 00 31 00 39 00 64 00 30 00 65 00 38 00))}
		$typelibguid1up = {((35 37 39 36 32 37 36 46 2d 31 43 37 41 2d 34 44 37 42 2d 41 30 38 39 2d 35 35 30 41 38 43 31 39 44 30 45 38) | (35 00 37 00 39 00 36 00 32 00 37 00 36 00 46 00 2d 00 31 00 43 00 37 00 41 00 2d 00 34 00 44 00 37 00 42 00 2d 00 41 00 30 00 38 00 39 00 2d 00 35 00 35 00 30 00 41 00 38 00 43 00 31 00 39 00 44 00 30 00 45 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_DoHC2 : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/SpiderLabs/DoHC2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "0bb38f10-ca5c-5c18-97c9-540b6367d150"

	strings:
		$typelibguid0lo = {((39 38 37 37 61 39 34 38 2d 32 31 34 32 2d 34 30 39 34 2d 39 38 64 65 2d 65 30 66 62 62 31 62 63 34 30 36 32) | (39 00 38 00 37 00 37 00 61 00 39 00 34 00 38 00 2d 00 32 00 31 00 34 00 32 00 2d 00 34 00 30 00 39 00 34 00 2d 00 39 00 38 00 64 00 65 00 2d 00 65 00 30 00 66 00 62 00 62 00 31 00 62 00 63 00 34 00 30 00 36 00 32 00))}
		$typelibguid0up = {((39 38 37 37 41 39 34 38 2d 32 31 34 32 2d 34 30 39 34 2d 39 38 44 45 2d 45 30 46 42 42 31 42 43 34 30 36 32) | (39 00 38 00 37 00 37 00 41 00 39 00 34 00 38 00 2d 00 32 00 31 00 34 00 32 00 2d 00 34 00 30 00 39 00 34 00 2d 00 39 00 38 00 44 00 45 00 2d 00 45 00 30 00 46 00 42 00 42 00 31 00 42 00 43 00 34 00 30 00 36 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SyscallPOC : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/SolomonSklash/SyscallPOC"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "1ed5e226-0dcd-5397-b5e8-41f8a14981a1"

	strings:
		$typelibguid0lo = {((31 65 35 34 36 33 37 62 2d 63 38 38 37 2d 34 32 61 39 2d 61 66 36 61 2d 62 34 62 64 34 65 32 38 63 64 61 39) | (31 00 65 00 35 00 34 00 36 00 33 00 37 00 62 00 2d 00 63 00 38 00 38 00 37 00 2d 00 34 00 32 00 61 00 39 00 2d 00 61 00 66 00 36 00 61 00 2d 00 62 00 34 00 62 00 64 00 34 00 65 00 32 00 38 00 63 00 64 00 61 00 39 00))}
		$typelibguid0up = {((31 45 35 34 36 33 37 42 2d 43 38 38 37 2d 34 32 41 39 2d 41 46 36 41 2d 42 34 42 44 34 45 32 38 43 44 41 39) | (31 00 45 00 35 00 34 00 36 00 33 00 37 00 42 00 2d 00 43 00 38 00 38 00 37 00 2d 00 34 00 32 00 41 00 39 00 2d 00 41 00 46 00 36 00 41 00 2d 00 42 00 34 00 42 00 44 00 34 00 45 00 32 00 38 00 43 00 44 00 41 00 39 00))}
		$typelibguid1lo = {((31 39 38 64 35 35 39 39 2d 64 39 66 63 2d 34 61 37 34 2d 38 37 66 34 2d 35 30 37 37 33 31 38 32 33 32 61 64) | (31 00 39 00 38 00 64 00 35 00 35 00 39 00 39 00 2d 00 64 00 39 00 66 00 63 00 2d 00 34 00 61 00 37 00 34 00 2d 00 38 00 37 00 66 00 34 00 2d 00 35 00 30 00 37 00 37 00 33 00 31 00 38 00 32 00 33 00 32 00 61 00 64 00))}
		$typelibguid1up = {((31 39 38 44 35 35 39 39 2d 44 39 46 43 2d 34 41 37 34 2d 38 37 46 34 2d 35 30 37 37 33 31 38 32 33 32 41 44) | (31 00 39 00 38 00 44 00 35 00 35 00 39 00 39 00 2d 00 44 00 39 00 46 00 43 00 2d 00 34 00 41 00 37 00 34 00 2d 00 38 00 37 00 46 00 34 00 2d 00 35 00 30 00 37 00 37 00 33 00 31 00 38 00 32 00 33 00 32 00 41 00 44 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Pen_Test_Tools : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/awillard1/Pen-Test-Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "00fb98a9-e615-5fb6-a555-4326b93e2c24"

	strings:
		$typelibguid0lo = {((39 32 32 65 37 66 64 63 2d 33 33 62 66 2d 34 38 64 65 2d 62 63 32 36 2d 61 38 31 66 38 35 34 36 32 31 31 35) | (39 00 32 00 32 00 65 00 37 00 66 00 64 00 63 00 2d 00 33 00 33 00 62 00 66 00 2d 00 34 00 38 00 64 00 65 00 2d 00 62 00 63 00 32 00 36 00 2d 00 61 00 38 00 31 00 66 00 38 00 35 00 34 00 36 00 32 00 31 00 31 00 35 00))}
		$typelibguid0up = {((39 32 32 45 37 46 44 43 2d 33 33 42 46 2d 34 38 44 45 2d 42 43 32 36 2d 41 38 31 46 38 35 34 36 32 31 31 35) | (39 00 32 00 32 00 45 00 37 00 46 00 44 00 43 00 2d 00 33 00 33 00 42 00 46 00 2d 00 34 00 38 00 44 00 45 00 2d 00 42 00 43 00 32 00 36 00 2d 00 41 00 38 00 31 00 46 00 38 00 35 00 34 00 36 00 32 00 31 00 31 00 35 00))}
		$typelibguid1lo = {((61 64 35 32 30 35 64 64 2d 31 37 34 64 2d 34 33 33 32 2d 39 36 64 39 2d 39 38 62 30 37 36 64 36 66 64 38 32) | (61 00 64 00 35 00 32 00 30 00 35 00 64 00 64 00 2d 00 31 00 37 00 34 00 64 00 2d 00 34 00 33 00 33 00 32 00 2d 00 39 00 36 00 64 00 39 00 2d 00 39 00 38 00 62 00 30 00 37 00 36 00 64 00 36 00 66 00 64 00 38 00 32 00))}
		$typelibguid1up = {((41 44 35 32 30 35 44 44 2d 31 37 34 44 2d 34 33 33 32 2d 39 36 44 39 2d 39 38 42 30 37 36 44 36 46 44 38 32) | (41 00 44 00 35 00 32 00 30 00 35 00 44 00 44 00 2d 00 31 00 37 00 34 00 44 00 2d 00 34 00 33 00 33 00 32 00 2d 00 39 00 36 00 44 00 39 00 2d 00 39 00 38 00 42 00 30 00 37 00 36 00 44 00 36 00 46 00 44 00 38 00 32 00))}
		$typelibguid2lo = {((62 36 37 65 37 35 35 30 2d 66 30 30 65 2d 34 38 62 33 2d 61 62 39 62 2d 34 33 33 32 62 31 32 35 34 61 38 36) | (62 00 36 00 37 00 65 00 37 00 35 00 35 00 30 00 2d 00 66 00 30 00 30 00 65 00 2d 00 34 00 38 00 62 00 33 00 2d 00 61 00 62 00 39 00 62 00 2d 00 34 00 33 00 33 00 32 00 62 00 31 00 32 00 35 00 34 00 61 00 38 00 36 00))}
		$typelibguid2up = {((42 36 37 45 37 35 35 30 2d 46 30 30 45 2d 34 38 42 33 2d 41 42 39 42 2d 34 33 33 32 42 31 32 35 34 41 38 36) | (42 00 36 00 37 00 45 00 37 00 35 00 35 00 30 00 2d 00 46 00 30 00 30 00 45 00 2d 00 34 00 38 00 42 00 33 00 2d 00 41 00 42 00 39 00 42 00 2d 00 34 00 33 00 33 00 32 00 42 00 31 00 32 00 35 00 34 00 41 00 38 00 36 00))}
		$typelibguid3lo = {((35 65 39 35 31 32 30 65 2d 62 30 30 32 2d 34 34 39 35 2d 39 30 61 31 2d 63 64 33 61 61 62 32 61 32 34 64 64) | (35 00 65 00 39 00 35 00 31 00 32 00 30 00 65 00 2d 00 62 00 30 00 30 00 32 00 2d 00 34 00 34 00 39 00 35 00 2d 00 39 00 30 00 61 00 31 00 2d 00 63 00 64 00 33 00 61 00 61 00 62 00 32 00 61 00 32 00 34 00 64 00 64 00))}
		$typelibguid3up = {((35 45 39 35 31 32 30 45 2d 42 30 30 32 2d 34 34 39 35 2d 39 30 41 31 2d 43 44 33 41 41 42 32 41 32 34 44 44) | (35 00 45 00 39 00 35 00 31 00 32 00 30 00 45 00 2d 00 42 00 30 00 30 00 32 00 2d 00 34 00 34 00 39 00 35 00 2d 00 39 00 30 00 41 00 31 00 2d 00 43 00 44 00 33 00 41 00 41 00 42 00 32 00 41 00 32 00 34 00 44 00 44 00))}
		$typelibguid4lo = {((32 39 35 30 31 37 66 32 2d 64 63 33 31 2d 34 61 38 37 2d 38 36 33 64 2d 30 62 39 39 35 36 63 32 62 35 35 61) | (32 00 39 00 35 00 30 00 31 00 37 00 66 00 32 00 2d 00 64 00 63 00 33 00 31 00 2d 00 34 00 61 00 38 00 37 00 2d 00 38 00 36 00 33 00 64 00 2d 00 30 00 62 00 39 00 39 00 35 00 36 00 63 00 32 00 62 00 35 00 35 00 61 00))}
		$typelibguid4up = {((32 39 35 30 31 37 46 32 2d 44 43 33 31 2d 34 41 38 37 2d 38 36 33 44 2d 30 42 39 39 35 36 43 32 42 35 35 41) | (32 00 39 00 35 00 30 00 31 00 37 00 46 00 32 00 2d 00 44 00 43 00 33 00 31 00 2d 00 34 00 41 00 38 00 37 00 2d 00 38 00 36 00 33 00 44 00 2d 00 30 00 42 00 39 00 39 00 35 00 36 00 43 00 32 00 42 00 35 00 35 00 41 00))}
		$typelibguid5lo = {((61 62 62 61 61 32 66 37 2d 31 34 35 32 2d 34 33 61 36 2d 62 39 38 65 2d 31 30 62 32 63 38 63 32 62 61 34 36) | (61 00 62 00 62 00 61 00 61 00 32 00 66 00 37 00 2d 00 31 00 34 00 35 00 32 00 2d 00 34 00 33 00 61 00 36 00 2d 00 62 00 39 00 38 00 65 00 2d 00 31 00 30 00 62 00 32 00 63 00 38 00 63 00 32 00 62 00 61 00 34 00 36 00))}
		$typelibguid5up = {((41 42 42 41 41 32 46 37 2d 31 34 35 32 2d 34 33 41 36 2d 42 39 38 45 2d 31 30 42 32 43 38 43 32 42 41 34 36) | (41 00 42 00 42 00 41 00 41 00 32 00 46 00 37 00 2d 00 31 00 34 00 35 00 32 00 2d 00 34 00 33 00 41 00 36 00 2d 00 42 00 39 00 38 00 45 00 2d 00 31 00 30 00 42 00 32 00 43 00 38 00 43 00 32 00 42 00 41 00 34 00 36 00))}
		$typelibguid6lo = {((61 34 30 34 33 64 34 63 2d 31 36 37 62 2d 34 33 32 36 2d 38 62 65 34 2d 30 31 38 30 38 39 36 35 30 33 38 32) | (61 00 34 00 30 00 34 00 33 00 64 00 34 00 63 00 2d 00 31 00 36 00 37 00 62 00 2d 00 34 00 33 00 32 00 36 00 2d 00 38 00 62 00 65 00 34 00 2d 00 30 00 31 00 38 00 30 00 38 00 39 00 36 00 35 00 30 00 33 00 38 00 32 00))}
		$typelibguid6up = {((41 34 30 34 33 44 34 43 2d 31 36 37 42 2d 34 33 32 36 2d 38 42 45 34 2d 30 31 38 30 38 39 36 35 30 33 38 32) | (41 00 34 00 30 00 34 00 33 00 44 00 34 00 43 00 2d 00 31 00 36 00 37 00 42 00 2d 00 34 00 33 00 32 00 36 00 2d 00 38 00 42 00 45 00 34 00 2d 00 30 00 31 00 38 00 30 00 38 00 39 00 36 00 35 00 30 00 33 00 38 00 32 00))}
		$typelibguid7lo = {((35 31 61 62 66 64 37 35 2d 62 31 37 39 2d 34 39 36 65 2d 38 36 64 62 2d 36 32 65 65 32 61 38 64 65 39 30 64) | (35 00 31 00 61 00 62 00 66 00 64 00 37 00 35 00 2d 00 62 00 31 00 37 00 39 00 2d 00 34 00 39 00 36 00 65 00 2d 00 38 00 36 00 64 00 62 00 2d 00 36 00 32 00 65 00 65 00 32 00 61 00 38 00 64 00 65 00 39 00 30 00 64 00))}
		$typelibguid7up = {((35 31 41 42 46 44 37 35 2d 42 31 37 39 2d 34 39 36 45 2d 38 36 44 42 2d 36 32 45 45 32 41 38 44 45 39 30 44) | (35 00 31 00 41 00 42 00 46 00 44 00 37 00 35 00 2d 00 42 00 31 00 37 00 39 00 2d 00 34 00 39 00 36 00 45 00 2d 00 38 00 36 00 44 00 42 00 2d 00 36 00 32 00 45 00 45 00 32 00 41 00 38 00 44 00 45 00 39 00 30 00 44 00))}
		$typelibguid8lo = {((61 30 36 64 61 37 66 38 2d 66 38 37 65 2d 34 30 36 35 2d 38 31 64 38 2d 61 62 63 33 33 63 62 35 34 37 66 38) | (61 00 30 00 36 00 64 00 61 00 37 00 66 00 38 00 2d 00 66 00 38 00 37 00 65 00 2d 00 34 00 30 00 36 00 35 00 2d 00 38 00 31 00 64 00 38 00 2d 00 61 00 62 00 63 00 33 00 33 00 63 00 62 00 35 00 34 00 37 00 66 00 38 00))}
		$typelibguid8up = {((41 30 36 44 41 37 46 38 2d 46 38 37 45 2d 34 30 36 35 2d 38 31 44 38 2d 41 42 43 33 33 43 42 35 34 37 46 38) | (41 00 30 00 36 00 44 00 41 00 37 00 46 00 38 00 2d 00 46 00 38 00 37 00 45 00 2d 00 34 00 30 00 36 00 35 00 2d 00 38 00 31 00 44 00 38 00 2d 00 41 00 42 00 43 00 33 00 33 00 43 00 42 00 35 00 34 00 37 00 46 00 38 00))}
		$typelibguid9lo = {((65 65 35 31 30 37 31 32 2d 30 34 31 33 2d 34 39 61 31 2d 62 30 38 62 2d 31 66 30 62 30 62 33 33 64 36 65 66) | (65 00 65 00 35 00 31 00 30 00 37 00 31 00 32 00 2d 00 30 00 34 00 31 00 33 00 2d 00 34 00 39 00 61 00 31 00 2d 00 62 00 30 00 38 00 62 00 2d 00 31 00 66 00 30 00 62 00 30 00 62 00 33 00 33 00 64 00 36 00 65 00 66 00))}
		$typelibguid9up = {((45 45 35 31 30 37 31 32 2d 30 34 31 33 2d 34 39 41 31 2d 42 30 38 42 2d 31 46 30 42 30 42 33 33 44 36 45 46) | (45 00 45 00 35 00 31 00 30 00 37 00 31 00 32 00 2d 00 30 00 34 00 31 00 33 00 2d 00 34 00 39 00 41 00 31 00 2d 00 42 00 30 00 38 00 42 00 2d 00 31 00 46 00 30 00 42 00 30 00 42 00 33 00 33 00 44 00 36 00 45 00 46 00))}
		$typelibguid10lo = {((39 37 38 30 64 61 36 35 2d 37 65 32 35 2d 34 31 32 65 2d 39 61 61 31 2d 66 37 37 64 38 32 38 38 31 39 64 36) | (39 00 37 00 38 00 30 00 64 00 61 00 36 00 35 00 2d 00 37 00 65 00 32 00 35 00 2d 00 34 00 31 00 32 00 65 00 2d 00 39 00 61 00 61 00 31 00 2d 00 66 00 37 00 37 00 64 00 38 00 32 00 38 00 38 00 31 00 39 00 64 00 36 00))}
		$typelibguid10up = {((39 37 38 30 44 41 36 35 2d 37 45 32 35 2d 34 31 32 45 2d 39 41 41 31 2d 46 37 37 44 38 32 38 38 31 39 44 36) | (39 00 37 00 38 00 30 00 44 00 41 00 36 00 35 00 2d 00 37 00 45 00 32 00 35 00 2d 00 34 00 31 00 32 00 45 00 2d 00 39 00 41 00 41 00 31 00 2d 00 46 00 37 00 37 00 44 00 38 00 32 00 38 00 38 00 31 00 39 00 44 00 36 00))}
		$typelibguid11lo = {((37 39 31 33 66 65 39 35 2d 33 61 64 35 2d 34 31 66 35 2d 62 66 37 66 2d 65 32 38 66 30 38 30 37 32 34 66 65) | (37 00 39 00 31 00 33 00 66 00 65 00 39 00 35 00 2d 00 33 00 61 00 64 00 35 00 2d 00 34 00 31 00 66 00 35 00 2d 00 62 00 66 00 37 00 66 00 2d 00 65 00 32 00 38 00 66 00 30 00 38 00 30 00 37 00 32 00 34 00 66 00 65 00))}
		$typelibguid11up = {((37 39 31 33 46 45 39 35 2d 33 41 44 35 2d 34 31 46 35 2d 42 46 37 46 2d 45 32 38 46 30 38 30 37 32 34 46 45) | (37 00 39 00 31 00 33 00 46 00 45 00 39 00 35 00 2d 00 33 00 41 00 44 00 35 00 2d 00 34 00 31 00 46 00 35 00 2d 00 42 00 46 00 37 00 46 00 2d 00 45 00 32 00 38 00 46 00 30 00 38 00 30 00 37 00 32 00 34 00 46 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_The_Collection : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Tlgyt/The-Collection"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "4ae78576-ab75-5679-9a29-4d9a1ff03f15"

	strings:
		$typelibguid0lo = {((35 37 39 31 35 39 66 66 2d 33 61 33 64 2d 34 36 61 37 2d 62 30 36 39 2d 39 31 32 30 34 66 65 62 32 31 63 64) | (35 00 37 00 39 00 31 00 35 00 39 00 66 00 66 00 2d 00 33 00 61 00 33 00 64 00 2d 00 34 00 36 00 61 00 37 00 2d 00 62 00 30 00 36 00 39 00 2d 00 39 00 31 00 32 00 30 00 34 00 66 00 65 00 62 00 32 00 31 00 63 00 64 00))}
		$typelibguid0up = {((35 37 39 31 35 39 46 46 2d 33 41 33 44 2d 34 36 41 37 2d 42 30 36 39 2d 39 31 32 30 34 46 45 42 32 31 43 44) | (35 00 37 00 39 00 31 00 35 00 39 00 46 00 46 00 2d 00 33 00 41 00 33 00 44 00 2d 00 34 00 36 00 41 00 37 00 2d 00 42 00 30 00 36 00 39 00 2d 00 39 00 31 00 32 00 30 00 34 00 46 00 45 00 42 00 32 00 31 00 43 00 44 00))}
		$typelibguid1lo = {((35 62 37 64 64 39 62 65 2d 63 38 63 33 2d 34 63 34 66 2d 61 33 35 33 2d 66 65 66 62 38 39 62 61 61 37 62 33) | (35 00 62 00 37 00 64 00 64 00 39 00 62 00 65 00 2d 00 63 00 38 00 63 00 33 00 2d 00 34 00 63 00 34 00 66 00 2d 00 61 00 33 00 35 00 33 00 2d 00 66 00 65 00 66 00 62 00 38 00 39 00 62 00 61 00 61 00 37 00 62 00 33 00))}
		$typelibguid1up = {((35 42 37 44 44 39 42 45 2d 43 38 43 33 2d 34 43 34 46 2d 41 33 35 33 2d 46 45 46 42 38 39 42 41 41 37 42 33) | (35 00 42 00 37 00 44 00 44 00 39 00 42 00 45 00 2d 00 43 00 38 00 43 00 33 00 2d 00 34 00 43 00 34 00 46 00 2d 00 41 00 33 00 35 00 33 00 2d 00 46 00 45 00 46 00 42 00 38 00 39 00 42 00 41 00 41 00 37 00 42 00 33 00))}
		$typelibguid2lo = {((34 33 65 64 63 62 31 66 2d 33 30 39 38 2d 34 61 32 33 2d 61 37 66 32 2d 38 39 35 64 39 32 37 62 63 36 36 31) | (34 00 33 00 65 00 64 00 63 00 62 00 31 00 66 00 2d 00 33 00 30 00 39 00 38 00 2d 00 34 00 61 00 32 00 33 00 2d 00 61 00 37 00 66 00 32 00 2d 00 38 00 39 00 35 00 64 00 39 00 32 00 37 00 62 00 63 00 36 00 36 00 31 00))}
		$typelibguid2up = {((34 33 45 44 43 42 31 46 2d 33 30 39 38 2d 34 41 32 33 2d 41 37 46 32 2d 38 39 35 44 39 32 37 42 43 36 36 31) | (34 00 33 00 45 00 44 00 43 00 42 00 31 00 46 00 2d 00 33 00 30 00 39 00 38 00 2d 00 34 00 41 00 32 00 33 00 2d 00 41 00 37 00 46 00 32 00 2d 00 38 00 39 00 35 00 44 00 39 00 32 00 37 00 42 00 43 00 36 00 36 00 31 00))}
		$typelibguid3lo = {((35 66 31 39 39 31 39 64 2d 63 64 35 31 2d 34 65 37 37 2d 39 37 33 66 2d 38 37 35 36 37 38 33 36 30 61 36 66) | (35 00 66 00 31 00 39 00 39 00 31 00 39 00 64 00 2d 00 63 00 64 00 35 00 31 00 2d 00 34 00 65 00 37 00 37 00 2d 00 39 00 37 00 33 00 66 00 2d 00 38 00 37 00 35 00 36 00 37 00 38 00 33 00 36 00 30 00 61 00 36 00 66 00))}
		$typelibguid3up = {((35 46 31 39 39 31 39 44 2d 43 44 35 31 2d 34 45 37 37 2d 39 37 33 46 2d 38 37 35 36 37 38 33 36 30 41 36 46) | (35 00 46 00 31 00 39 00 39 00 31 00 39 00 44 00 2d 00 43 00 44 00 35 00 31 00 2d 00 34 00 45 00 37 00 37 00 2d 00 39 00 37 00 33 00 46 00 2d 00 38 00 37 00 35 00 36 00 37 00 38 00 33 00 36 00 30 00 41 00 36 00 46 00))}
		$typelibguid4lo = {((31 37 66 62 63 39 32 36 2d 65 31 37 65 2d 34 30 33 34 2d 62 61 31 62 2d 66 62 32 65 62 35 37 66 35 64 64 33) | (31 00 37 00 66 00 62 00 63 00 39 00 32 00 36 00 2d 00 65 00 31 00 37 00 65 00 2d 00 34 00 30 00 33 00 34 00 2d 00 62 00 61 00 31 00 62 00 2d 00 66 00 62 00 32 00 65 00 62 00 35 00 37 00 66 00 35 00 64 00 64 00 33 00))}
		$typelibguid4up = {((31 37 46 42 43 39 32 36 2d 45 31 37 45 2d 34 30 33 34 2d 42 41 31 42 2d 46 42 32 45 42 35 37 46 35 44 44 33) | (31 00 37 00 46 00 42 00 43 00 39 00 32 00 36 00 2d 00 45 00 31 00 37 00 45 00 2d 00 34 00 30 00 33 00 34 00 2d 00 42 00 41 00 31 00 42 00 2d 00 46 00 42 00 32 00 45 00 42 00 35 00 37 00 46 00 35 00 44 00 44 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Change_Lockscreen : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/nccgroup/Change-Lockscreen"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "a817c6e8-95f9-56c6-97b8-4be06658629f"

	strings:
		$typelibguid0lo = {((37 38 36 34 32 61 62 33 2d 65 61 61 36 2d 34 65 39 63 2d 61 39 33 34 2d 65 37 62 30 36 33 38 62 63 31 63 63) | (37 00 38 00 36 00 34 00 32 00 61 00 62 00 33 00 2d 00 65 00 61 00 61 00 36 00 2d 00 34 00 65 00 39 00 63 00 2d 00 61 00 39 00 33 00 34 00 2d 00 65 00 37 00 62 00 30 00 36 00 33 00 38 00 62 00 63 00 31 00 63 00 63 00))}
		$typelibguid0up = {((37 38 36 34 32 41 42 33 2d 45 41 41 36 2d 34 45 39 43 2d 41 39 33 34 2d 45 37 42 30 36 33 38 42 43 31 43 43) | (37 00 38 00 36 00 34 00 32 00 41 00 42 00 33 00 2d 00 45 00 41 00 41 00 36 00 2d 00 34 00 45 00 39 00 43 00 2d 00 41 00 39 00 33 00 34 00 2d 00 45 00 37 00 42 00 30 00 36 00 33 00 38 00 42 00 43 00 31 00 43 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_LOLBITS : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Kudaes/LOLBITS"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "66454ac0-742b-51a3-ac45-1ac9606e8b89"

	strings:
		$typelibguid0lo = {((32 39 64 30 39 61 61 34 2d 65 61 30 63 2d 34 37 63 32 2d 39 37 33 63 2d 31 64 37 36 38 30 38 37 64 35 32 37) | (32 00 39 00 64 00 30 00 39 00 61 00 61 00 34 00 2d 00 65 00 61 00 30 00 63 00 2d 00 34 00 37 00 63 00 32 00 2d 00 39 00 37 00 33 00 63 00 2d 00 31 00 64 00 37 00 36 00 38 00 30 00 38 00 37 00 64 00 35 00 32 00 37 00))}
		$typelibguid0up = {((32 39 44 30 39 41 41 34 2d 45 41 30 43 2d 34 37 43 32 2d 39 37 33 43 2d 31 44 37 36 38 30 38 37 44 35 32 37) | (32 00 39 00 44 00 30 00 39 00 41 00 41 00 34 00 2d 00 45 00 41 00 30 00 43 00 2d 00 34 00 37 00 43 00 32 00 2d 00 39 00 37 00 33 00 43 00 2d 00 31 00 44 00 37 00 36 00 38 00 30 00 38 00 37 00 44 00 35 00 32 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Keylogger : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/BlackVikingPro/Keylogger"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "0576756e-26d5-5165-b621-917126a75a38"

	strings:
		$typelibguid0lo = {((37 61 66 62 63 39 62 66 2d 33 32 64 39 2d 34 36 30 66 2d 38 61 33 30 2d 33 35 65 33 30 61 61 31 35 38 37 39) | (37 00 61 00 66 00 62 00 63 00 39 00 62 00 66 00 2d 00 33 00 32 00 64 00 39 00 2d 00 34 00 36 00 30 00 66 00 2d 00 38 00 61 00 33 00 30 00 2d 00 33 00 35 00 65 00 33 00 30 00 61 00 61 00 31 00 35 00 38 00 37 00 39 00))}
		$typelibguid0up = {((37 41 46 42 43 39 42 46 2d 33 32 44 39 2d 34 36 30 46 2d 38 41 33 30 2d 33 35 45 33 30 41 41 31 35 38 37 39) | (37 00 41 00 46 00 42 00 43 00 39 00 42 00 46 00 2d 00 33 00 32 00 44 00 39 00 2d 00 34 00 36 00 30 00 46 00 2d 00 38 00 41 00 33 00 30 00 2d 00 33 00 35 00 45 00 33 00 30 00 41 00 41 00 31 00 35 00 38 00 37 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_CVE_2020_1337 : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/neofito/CVE-2020-1337"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "4b79867d-761c-5aa8-bf8a-60caa50d8aa6"

	strings:
		$typelibguid0lo = {((64 39 63 32 65 33 63 31 2d 65 39 63 63 2d 34 32 62 30 2d 61 36 37 63 2d 62 36 65 31 61 34 66 39 36 32 63 63) | (64 00 39 00 63 00 32 00 65 00 33 00 63 00 31 00 2d 00 65 00 39 00 63 00 63 00 2d 00 34 00 32 00 62 00 30 00 2d 00 61 00 36 00 37 00 63 00 2d 00 62 00 36 00 65 00 31 00 61 00 34 00 66 00 39 00 36 00 32 00 63 00 63 00))}
		$typelibguid0up = {((44 39 43 32 45 33 43 31 2d 45 39 43 43 2d 34 32 42 30 2d 41 36 37 43 2d 42 36 45 31 41 34 46 39 36 32 43 43) | (44 00 39 00 43 00 32 00 45 00 33 00 43 00 31 00 2d 00 45 00 39 00 43 00 43 00 2d 00 34 00 32 00 42 00 30 00 2d 00 41 00 36 00 37 00 43 00 2d 00 42 00 36 00 45 00 31 00 41 00 34 00 46 00 39 00 36 00 32 00 43 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpLogger : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/djhohnstein/SharpLogger"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "5cce395b-4f6f-5015-b45e-7eb79853296a"

	strings:
		$typelibguid0lo = {((33 36 65 30 30 31 35 32 2d 65 30 37 33 2d 34 64 61 38 2d 61 61 30 63 2d 33 37 35 62 36 64 64 36 38 30 63 34) | (33 00 36 00 65 00 30 00 30 00 31 00 35 00 32 00 2d 00 65 00 30 00 37 00 33 00 2d 00 34 00 64 00 61 00 38 00 2d 00 61 00 61 00 30 00 63 00 2d 00 33 00 37 00 35 00 62 00 36 00 64 00 64 00 36 00 38 00 30 00 63 00 34 00))}
		$typelibguid0up = {((33 36 45 30 30 31 35 32 2d 45 30 37 33 2d 34 44 41 38 2d 41 41 30 43 2d 33 37 35 42 36 44 44 36 38 30 43 34) | (33 00 36 00 45 00 30 00 30 00 31 00 35 00 32 00 2d 00 45 00 30 00 37 00 33 00 2d 00 34 00 44 00 41 00 38 00 2d 00 41 00 41 00 30 00 43 00 2d 00 33 00 37 00 35 00 42 00 36 00 44 00 44 00 36 00 38 00 30 00 43 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_AsyncRAT_C_Sharp : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "858a079d-71e8-516e-a2a9-f0969edc758b"

	strings:
		$typelibguid0lo = {((36 31 39 62 37 36 31 32 2d 64 66 65 61 2d 34 34 32 61 2d 61 39 32 37 2d 64 39 39 37 66 39 39 63 34 39 37 62) | (36 00 31 00 39 00 62 00 37 00 36 00 31 00 32 00 2d 00 64 00 66 00 65 00 61 00 2d 00 34 00 34 00 32 00 61 00 2d 00 61 00 39 00 32 00 37 00 2d 00 64 00 39 00 39 00 37 00 66 00 39 00 39 00 63 00 34 00 39 00 37 00 62 00))}
		$typelibguid0up = {((36 31 39 42 37 36 31 32 2d 44 46 45 41 2d 34 34 32 41 2d 41 39 32 37 2d 44 39 39 37 46 39 39 43 34 39 37 42) | (36 00 31 00 39 00 42 00 37 00 36 00 31 00 32 00 2d 00 44 00 46 00 45 00 41 00 2d 00 34 00 34 00 32 00 41 00 2d 00 41 00 39 00 32 00 37 00 2d 00 44 00 39 00 39 00 37 00 46 00 39 00 39 00 43 00 34 00 39 00 37 00 42 00))}
		$typelibguid1lo = {((34 32 34 62 38 31 62 65 2d 32 66 61 63 2d 34 31 39 66 2d 62 34 62 63 2d 30 30 63 63 62 65 33 38 34 39 31 66) | (34 00 32 00 34 00 62 00 38 00 31 00 62 00 65 00 2d 00 32 00 66 00 61 00 63 00 2d 00 34 00 31 00 39 00 66 00 2d 00 62 00 34 00 62 00 63 00 2d 00 30 00 30 00 63 00 63 00 62 00 65 00 33 00 38 00 34 00 39 00 31 00 66 00))}
		$typelibguid1up = {((34 32 34 42 38 31 42 45 2d 32 46 41 43 2d 34 31 39 46 2d 42 34 42 43 2d 30 30 43 43 42 45 33 38 34 39 31 46) | (34 00 32 00 34 00 42 00 38 00 31 00 42 00 45 00 2d 00 32 00 46 00 41 00 43 00 2d 00 34 00 31 00 39 00 46 00 2d 00 42 00 34 00 42 00 43 00 2d 00 30 00 30 00 43 00 43 00 42 00 45 00 33 00 38 00 34 00 39 00 31 00 46 00))}
		$typelibguid2lo = {((33 37 65 32 30 62 61 66 2d 33 35 37 37 2d 34 63 64 39 2d 62 62 33 39 2d 31 38 36 37 35 38 35 34 65 32 35 35) | (33 00 37 00 65 00 32 00 30 00 62 00 61 00 66 00 2d 00 33 00 35 00 37 00 37 00 2d 00 34 00 63 00 64 00 39 00 2d 00 62 00 62 00 33 00 39 00 2d 00 31 00 38 00 36 00 37 00 35 00 38 00 35 00 34 00 65 00 32 00 35 00 35 00))}
		$typelibguid2up = {((33 37 45 32 30 42 41 46 2d 33 35 37 37 2d 34 43 44 39 2d 42 42 33 39 2d 31 38 36 37 35 38 35 34 45 32 35 35) | (33 00 37 00 45 00 32 00 30 00 42 00 41 00 46 00 2d 00 33 00 35 00 37 00 37 00 2d 00 34 00 43 00 44 00 39 00 2d 00 42 00 42 00 33 00 39 00 2d 00 31 00 38 00 36 00 37 00 35 00 38 00 35 00 34 00 45 00 32 00 35 00 35 00))}
		$typelibguid3lo = {((64 61 66 65 36 38 36 61 2d 34 36 31 62 2d 34 30 32 62 2d 62 62 64 37 2d 32 61 32 66 34 63 38 37 63 37 37 33) | (64 00 61 00 66 00 65 00 36 00 38 00 36 00 61 00 2d 00 34 00 36 00 31 00 62 00 2d 00 34 00 30 00 32 00 62 00 2d 00 62 00 62 00 64 00 37 00 2d 00 32 00 61 00 32 00 66 00 34 00 63 00 38 00 37 00 63 00 37 00 37 00 33 00))}
		$typelibguid3up = {((44 41 46 45 36 38 36 41 2d 34 36 31 42 2d 34 30 32 42 2d 42 42 44 37 2d 32 41 32 46 34 43 38 37 43 37 37 33) | (44 00 41 00 46 00 45 00 36 00 38 00 36 00 41 00 2d 00 34 00 36 00 31 00 42 00 2d 00 34 00 30 00 32 00 42 00 2d 00 42 00 42 00 44 00 37 00 2d 00 32 00 41 00 32 00 46 00 34 00 43 00 38 00 37 00 43 00 37 00 37 00 33 00))}
		$typelibguid4lo = {((65 65 30 33 66 61 61 39 2d 63 39 65 38 2d 34 37 36 36 2d 62 64 34 65 2d 35 63 64 35 34 63 37 66 31 33 64 33) | (65 00 65 00 30 00 33 00 66 00 61 00 61 00 39 00 2d 00 63 00 39 00 65 00 38 00 2d 00 34 00 37 00 36 00 36 00 2d 00 62 00 64 00 34 00 65 00 2d 00 35 00 63 00 64 00 35 00 34 00 63 00 37 00 66 00 31 00 33 00 64 00 33 00))}
		$typelibguid4up = {((45 45 30 33 46 41 41 39 2d 43 39 45 38 2d 34 37 36 36 2d 42 44 34 45 2d 35 43 44 35 34 43 37 46 31 33 44 33) | (45 00 45 00 30 00 33 00 46 00 41 00 41 00 39 00 2d 00 43 00 39 00 45 00 38 00 2d 00 34 00 37 00 36 00 36 00 2d 00 42 00 44 00 34 00 45 00 2d 00 35 00 43 00 44 00 35 00 34 00 43 00 37 00 46 00 31 00 33 00 44 00 33 00))}
		$typelibguid5lo = {((38 62 66 63 38 65 64 32 2d 37 31 63 63 2d 34 39 64 63 2d 39 30 32 30 2d 32 63 38 31 39 39 62 63 32 37 62 36) | (38 00 62 00 66 00 63 00 38 00 65 00 64 00 32 00 2d 00 37 00 31 00 63 00 63 00 2d 00 34 00 39 00 64 00 63 00 2d 00 39 00 30 00 32 00 30 00 2d 00 32 00 63 00 38 00 31 00 39 00 39 00 62 00 63 00 32 00 37 00 62 00 36 00))}
		$typelibguid5up = {((38 42 46 43 38 45 44 32 2d 37 31 43 43 2d 34 39 44 43 2d 39 30 32 30 2d 32 43 38 31 39 39 42 43 32 37 42 36) | (38 00 42 00 46 00 43 00 38 00 45 00 44 00 32 00 2d 00 37 00 31 00 43 00 43 00 2d 00 34 00 39 00 44 00 43 00 2d 00 39 00 30 00 32 00 30 00 2d 00 32 00 43 00 38 00 31 00 39 00 39 00 42 00 43 00 32 00 37 00 42 00 36 00))}
		$typelibguid6lo = {((64 36 34 30 63 33 36 62 2d 32 63 36 36 2d 34 34 39 62 2d 61 31 34 35 2d 65 62 39 38 33 32 32 61 36 37 63 38) | (64 00 36 00 34 00 30 00 63 00 33 00 36 00 62 00 2d 00 32 00 63 00 36 00 36 00 2d 00 34 00 34 00 39 00 62 00 2d 00 61 00 31 00 34 00 35 00 2d 00 65 00 62 00 39 00 38 00 33 00 32 00 32 00 61 00 36 00 37 00 63 00 38 00))}
		$typelibguid6up = {((44 36 34 30 43 33 36 42 2d 32 43 36 36 2d 34 34 39 42 2d 41 31 34 35 2d 45 42 39 38 33 32 32 41 36 37 43 38) | (44 00 36 00 34 00 30 00 43 00 33 00 36 00 42 00 2d 00 32 00 43 00 36 00 36 00 2d 00 34 00 34 00 39 00 42 00 2d 00 41 00 31 00 34 00 35 00 2d 00 45 00 42 00 39 00 38 00 33 00 32 00 32 00 41 00 36 00 37 00 43 00 38 00))}
		$typelibguid7lo = {((38 64 65 34 32 64 61 33 2d 62 65 39 39 2d 34 65 37 65 2d 61 33 64 32 2d 33 66 36 35 65 37 63 31 61 62 63 65) | (38 00 64 00 65 00 34 00 32 00 64 00 61 00 33 00 2d 00 62 00 65 00 39 00 39 00 2d 00 34 00 65 00 37 00 65 00 2d 00 61 00 33 00 64 00 32 00 2d 00 33 00 66 00 36 00 35 00 65 00 37 00 63 00 31 00 61 00 62 00 63 00 65 00))}
		$typelibguid7up = {((38 44 45 34 32 44 41 33 2d 42 45 39 39 2d 34 45 37 45 2d 41 33 44 32 2d 33 46 36 35 45 37 43 31 41 42 43 45) | (38 00 44 00 45 00 34 00 32 00 44 00 41 00 33 00 2d 00 42 00 45 00 39 00 39 00 2d 00 34 00 45 00 37 00 45 00 2d 00 41 00 33 00 44 00 32 00 2d 00 33 00 46 00 36 00 35 00 45 00 37 00 43 00 31 00 41 00 42 00 43 00 45 00))}
		$typelibguid8lo = {((62 65 65 38 38 31 38 36 2d 37 36 39 61 2d 34 35 32 63 2d 39 64 64 39 2d 64 30 65 30 38 31 35 64 39 32 62 66) | (62 00 65 00 65 00 38 00 38 00 31 00 38 00 36 00 2d 00 37 00 36 00 39 00 61 00 2d 00 34 00 35 00 32 00 63 00 2d 00 39 00 64 00 64 00 39 00 2d 00 64 00 30 00 65 00 30 00 38 00 31 00 35 00 64 00 39 00 32 00 62 00 66 00))}
		$typelibguid8up = {((42 45 45 38 38 31 38 36 2d 37 36 39 41 2d 34 35 32 43 2d 39 44 44 39 2d 44 30 45 30 38 31 35 44 39 32 42 46) | (42 00 45 00 45 00 38 00 38 00 31 00 38 00 36 00 2d 00 37 00 36 00 39 00 41 00 2d 00 34 00 35 00 32 00 43 00 2d 00 39 00 44 00 44 00 39 00 2d 00 44 00 30 00 45 00 30 00 38 00 31 00 35 00 44 00 39 00 32 00 42 00 46 00))}
		$typelibguid9lo = {((39 30 34 32 62 35 34 33 2d 31 33 64 31 2d 34 32 62 33 2d 61 35 62 36 2d 35 63 63 39 61 64 35 35 65 31 35 30) | (39 00 30 00 34 00 32 00 62 00 35 00 34 00 33 00 2d 00 31 00 33 00 64 00 31 00 2d 00 34 00 32 00 62 00 33 00 2d 00 61 00 35 00 62 00 36 00 2d 00 35 00 63 00 63 00 39 00 61 00 64 00 35 00 35 00 65 00 31 00 35 00 30 00))}
		$typelibguid9up = {((39 30 34 32 42 35 34 33 2d 31 33 44 31 2d 34 32 42 33 2d 41 35 42 36 2d 35 43 43 39 41 44 35 35 45 31 35 30) | (39 00 30 00 34 00 32 00 42 00 35 00 34 00 33 00 2d 00 31 00 33 00 44 00 31 00 2d 00 34 00 32 00 42 00 33 00 2d 00 41 00 35 00 42 00 36 00 2d 00 35 00 43 00 43 00 39 00 41 00 44 00 35 00 35 00 45 00 31 00 35 00 30 00))}
		$typelibguid10lo = {((36 61 61 34 65 33 39 32 2d 61 61 61 66 2d 34 34 30 38 2d 62 35 35 30 2d 38 35 38 36 33 64 64 34 62 61 61 66) | (36 00 61 00 61 00 34 00 65 00 33 00 39 00 32 00 2d 00 61 00 61 00 61 00 66 00 2d 00 34 00 34 00 30 00 38 00 2d 00 62 00 35 00 35 00 30 00 2d 00 38 00 35 00 38 00 36 00 33 00 64 00 64 00 34 00 62 00 61 00 61 00 66 00))}
		$typelibguid10up = {((36 41 41 34 45 33 39 32 2d 41 41 41 46 2d 34 34 30 38 2d 42 35 35 30 2d 38 35 38 36 33 44 44 34 42 41 41 46) | (36 00 41 00 41 00 34 00 45 00 33 00 39 00 32 00 2d 00 41 00 41 00 41 00 46 00 2d 00 34 00 34 00 30 00 38 00 2d 00 42 00 35 00 35 00 30 00 2d 00 38 00 35 00 38 00 36 00 33 00 44 00 44 00 34 00 42 00 41 00 41 00 46 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_DarkFender : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xyg3n/DarkFender"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "0aea5e05-7788-5581-8bcc-d2e75a291dd9"

	strings:
		$typelibguid0lo = {((31 32 66 64 66 37 63 65 2d 34 61 37 63 2d 34 31 62 36 2d 39 62 33 32 2d 37 36 36 64 64 64 32 39 39 62 65 62) | (31 00 32 00 66 00 64 00 66 00 37 00 63 00 65 00 2d 00 34 00 61 00 37 00 63 00 2d 00 34 00 31 00 62 00 36 00 2d 00 39 00 62 00 33 00 32 00 2d 00 37 00 36 00 36 00 64 00 64 00 64 00 32 00 39 00 39 00 62 00 65 00 62 00))}
		$typelibguid0up = {((31 32 46 44 46 37 43 45 2d 34 41 37 43 2d 34 31 42 36 2d 39 42 33 32 2d 37 36 36 44 44 44 32 39 39 42 45 42) | (31 00 32 00 46 00 44 00 46 00 37 00 43 00 45 00 2d 00 34 00 41 00 37 00 43 00 2d 00 34 00 31 00 42 00 36 00 2d 00 39 00 42 00 33 00 32 00 2d 00 37 00 36 00 36 00 44 00 44 00 44 00 32 00 39 00 39 00 42 00 45 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_MinerDropper : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/DylanAlloy/MinerDropper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "607f72df-b0c1-53df-bf2c-592f55cbfcb7"

	strings:
		$typelibguid0lo = {((34 36 61 37 61 66 38 33 2d 31 64 61 37 2d 34 30 62 32 2d 39 64 38 36 2d 36 66 64 36 32 32 33 66 36 37 39 31) | (34 00 36 00 61 00 37 00 61 00 66 00 38 00 33 00 2d 00 31 00 64 00 61 00 37 00 2d 00 34 00 30 00 62 00 32 00 2d 00 39 00 64 00 38 00 36 00 2d 00 36 00 66 00 64 00 36 00 32 00 32 00 33 00 66 00 36 00 37 00 39 00 31 00))}
		$typelibguid0up = {((34 36 41 37 41 46 38 33 2d 31 44 41 37 2d 34 30 42 32 2d 39 44 38 36 2d 36 46 44 36 32 32 33 46 36 37 39 31) | (34 00 36 00 41 00 37 00 41 00 46 00 38 00 33 00 2d 00 31 00 44 00 41 00 37 00 2d 00 34 00 30 00 42 00 32 00 2d 00 39 00 44 00 38 00 36 00 2d 00 36 00 46 00 44 00 36 00 32 00 32 00 33 00 46 00 36 00 37 00 39 00 31 00))}
		$typelibguid1lo = {((38 34 33 33 61 36 39 33 2d 66 33 39 64 2d 34 35 31 62 2d 39 35 35 62 2d 33 31 63 33 65 37 66 61 36 38 32 35) | (38 00 34 00 33 00 33 00 61 00 36 00 39 00 33 00 2d 00 66 00 33 00 39 00 64 00 2d 00 34 00 35 00 31 00 62 00 2d 00 39 00 35 00 35 00 62 00 2d 00 33 00 31 00 63 00 33 00 65 00 37 00 66 00 61 00 36 00 38 00 32 00 35 00))}
		$typelibguid1up = {((38 34 33 33 41 36 39 33 2d 46 33 39 44 2d 34 35 31 42 2d 39 35 35 42 2d 33 31 43 33 45 37 46 41 36 38 32 35) | (38 00 34 00 33 00 33 00 41 00 36 00 39 00 33 00 2d 00 46 00 33 00 39 00 44 00 2d 00 34 00 35 00 31 00 42 00 2d 00 39 00 35 00 35 00 42 00 2d 00 33 00 31 00 43 00 33 00 45 00 37 00 46 00 41 00 36 00 38 00 32 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpDomainSpray : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/HunnicCyber/SharpDomainSpray"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "cffd3350-4a86-5035-ab15-adbc3ac2a0e9"

	strings:
		$typelibguid0lo = {((37 36 66 66 61 39 32 62 2d 34 32 39 62 2d 34 38 36 35 2d 39 37 30 64 2d 34 65 37 36 37 38 61 63 33 34 65 61) | (37 00 36 00 66 00 66 00 61 00 39 00 32 00 62 00 2d 00 34 00 32 00 39 00 62 00 2d 00 34 00 38 00 36 00 35 00 2d 00 39 00 37 00 30 00 64 00 2d 00 34 00 65 00 37 00 36 00 37 00 38 00 61 00 63 00 33 00 34 00 65 00 61 00))}
		$typelibguid0up = {((37 36 46 46 41 39 32 42 2d 34 32 39 42 2d 34 38 36 35 2d 39 37 30 44 2d 34 45 37 36 37 38 41 43 33 34 45 41) | (37 00 36 00 46 00 46 00 41 00 39 00 32 00 42 00 2d 00 34 00 32 00 39 00 42 00 2d 00 34 00 38 00 36 00 35 00 2d 00 39 00 37 00 30 00 44 00 2d 00 34 00 45 00 37 00 36 00 37 00 38 00 41 00 43 00 33 00 34 00 45 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_iSpyKeylogger : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mwsrc/iSpyKeylogger"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "8607de67-b472-5afc-b2b9-cc758b5ec474"

	strings:
		$typelibguid0lo = {((63 63 63 30 61 33 38 36 2d 63 34 63 65 2d 34 32 65 66 2d 61 61 65 61 2d 62 32 61 66 37 65 66 66 34 61 64 38) | (63 00 63 00 63 00 30 00 61 00 33 00 38 00 36 00 2d 00 63 00 34 00 63 00 65 00 2d 00 34 00 32 00 65 00 66 00 2d 00 61 00 61 00 65 00 61 00 2d 00 62 00 32 00 61 00 66 00 37 00 65 00 66 00 66 00 34 00 61 00 64 00 38 00))}
		$typelibguid0up = {((43 43 43 30 41 33 38 36 2d 43 34 43 45 2d 34 32 45 46 2d 41 41 45 41 2d 42 32 41 46 37 45 46 46 34 41 44 38) | (43 00 43 00 43 00 30 00 41 00 33 00 38 00 36 00 2d 00 43 00 34 00 43 00 45 00 2d 00 34 00 32 00 45 00 46 00 2d 00 41 00 41 00 45 00 41 00 2d 00 42 00 32 00 41 00 46 00 37 00 45 00 46 00 46 00 34 00 41 00 44 00 38 00))}
		$typelibguid1lo = {((38 31 36 62 38 62 39 30 2d 32 39 37 35 2d 34 36 64 33 2d 61 61 63 39 2d 33 63 34 35 62 32 36 34 33 37 66 61) | (38 00 31 00 36 00 62 00 38 00 62 00 39 00 30 00 2d 00 32 00 39 00 37 00 35 00 2d 00 34 00 36 00 64 00 33 00 2d 00 61 00 61 00 63 00 39 00 2d 00 33 00 63 00 34 00 35 00 62 00 32 00 36 00 34 00 33 00 37 00 66 00 61 00))}
		$typelibguid1up = {((38 31 36 42 38 42 39 30 2d 32 39 37 35 2d 34 36 44 33 2d 41 41 43 39 2d 33 43 34 35 42 32 36 34 33 37 46 41) | (38 00 31 00 36 00 42 00 38 00 42 00 39 00 30 00 2d 00 32 00 39 00 37 00 35 00 2d 00 34 00 36 00 44 00 33 00 2d 00 41 00 41 00 43 00 39 00 2d 00 33 00 43 00 34 00 35 00 42 00 32 00 36 00 34 00 33 00 37 00 46 00 41 00))}
		$typelibguid2lo = {((32 37 39 62 35 35 33 33 2d 64 33 61 63 2d 34 33 38 66 2d 62 61 38 39 2d 33 66 65 39 64 65 32 64 61 32 36 33) | (32 00 37 00 39 00 62 00 35 00 35 00 33 00 33 00 2d 00 64 00 33 00 61 00 63 00 2d 00 34 00 33 00 38 00 66 00 2d 00 62 00 61 00 38 00 39 00 2d 00 33 00 66 00 65 00 39 00 64 00 65 00 32 00 64 00 61 00 32 00 36 00 33 00))}
		$typelibguid2up = {((32 37 39 42 35 35 33 33 2d 44 33 41 43 2d 34 33 38 46 2d 42 41 38 39 2d 33 46 45 39 44 45 32 44 41 32 36 33) | (32 00 37 00 39 00 42 00 35 00 35 00 33 00 33 00 2d 00 44 00 33 00 41 00 43 00 2d 00 34 00 33 00 38 00 46 00 2d 00 42 00 41 00 38 00 39 00 2d 00 33 00 46 00 45 00 39 00 44 00 45 00 32 00 44 00 41 00 32 00 36 00 33 00))}
		$typelibguid3lo = {((38 38 64 33 64 63 30 32 2d 32 38 35 33 2d 34 62 66 30 2d 62 36 64 63 2d 61 64 33 31 66 35 31 33 35 64 32 36) | (38 00 38 00 64 00 33 00 64 00 63 00 30 00 32 00 2d 00 32 00 38 00 35 00 33 00 2d 00 34 00 62 00 66 00 30 00 2d 00 62 00 36 00 64 00 63 00 2d 00 61 00 64 00 33 00 31 00 66 00 35 00 31 00 33 00 35 00 64 00 32 00 36 00))}
		$typelibguid3up = {((38 38 44 33 44 43 30 32 2d 32 38 35 33 2d 34 42 46 30 2d 42 36 44 43 2d 41 44 33 31 46 35 31 33 35 44 32 36) | (38 00 38 00 44 00 33 00 44 00 43 00 30 00 32 00 2d 00 32 00 38 00 35 00 33 00 2d 00 34 00 42 00 46 00 30 00 2d 00 42 00 36 00 44 00 43 00 2d 00 41 00 44 00 33 00 31 00 46 00 35 00 31 00 33 00 35 00 44 00 32 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SolarFlare : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mubix/solarflare"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-15"
		modified = "2023-04-06"
		id = "3645e14c-6025-59fa-a5a2-d8dacba8cd94"

	strings:
		$typelibguid0lo = {((63 61 36 30 65 34 39 65 2d 65 65 65 39 2d 34 30 39 62 2d 38 64 31 61 2d 64 31 39 66 31 64 32 37 62 37 65 34) | (63 00 61 00 36 00 30 00 65 00 34 00 39 00 65 00 2d 00 65 00 65 00 65 00 39 00 2d 00 34 00 30 00 39 00 62 00 2d 00 38 00 64 00 31 00 61 00 2d 00 64 00 31 00 39 00 66 00 31 00 64 00 32 00 37 00 62 00 37 00 65 00 34 00))}
		$typelibguid0up = {((43 41 36 30 45 34 39 45 2d 45 45 45 39 2d 34 30 39 42 2d 38 44 31 41 2d 44 31 39 46 31 44 32 37 42 37 45 34) | (43 00 41 00 36 00 30 00 45 00 34 00 39 00 45 00 2d 00 45 00 45 00 45 00 39 00 2d 00 34 00 30 00 39 00 42 00 2d 00 38 00 44 00 31 00 41 00 2d 00 44 00 31 00 39 00 46 00 31 00 44 00 32 00 37 00 42 00 37 00 45 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Snaffler : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/SnaffCon/Snaffler"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "d4b9a8c5-e0d9-5c85-af81-05f6e0f52bff"

	strings:
		$typelibguid0lo = {((32 61 61 30 36 30 62 34 2d 64 65 38 38 2d 34 64 32 61 2d 61 32 36 61 2d 37 36 30 63 31 63 65 66 65 63 33 65) | (32 00 61 00 61 00 30 00 36 00 30 00 62 00 34 00 2d 00 64 00 65 00 38 00 38 00 2d 00 34 00 64 00 32 00 61 00 2d 00 61 00 32 00 36 00 61 00 2d 00 37 00 36 00 30 00 63 00 31 00 63 00 65 00 66 00 65 00 63 00 33 00 65 00))}
		$typelibguid0up = {((32 41 41 30 36 30 42 34 2d 44 45 38 38 2d 34 44 32 41 2d 41 32 36 41 2d 37 36 30 43 31 43 45 46 45 43 33 45) | (32 00 41 00 41 00 30 00 36 00 30 00 42 00 34 00 2d 00 44 00 45 00 38 00 38 00 2d 00 34 00 44 00 32 00 41 00 2d 00 41 00 32 00 36 00 41 00 2d 00 37 00 36 00 30 00 43 00 31 00 43 00 45 00 46 00 45 00 43 00 33 00 45 00))}
		$typelibguid1lo = {((62 31 31 38 38 30 32 64 2d 32 65 34 36 2d 34 65 34 31 2d 61 61 63 37 2d 39 65 65 38 39 30 32 36 38 66 38 62) | (62 00 31 00 31 00 38 00 38 00 30 00 32 00 64 00 2d 00 32 00 65 00 34 00 36 00 2d 00 34 00 65 00 34 00 31 00 2d 00 61 00 61 00 63 00 37 00 2d 00 39 00 65 00 65 00 38 00 39 00 30 00 32 00 36 00 38 00 66 00 38 00 62 00))}
		$typelibguid1up = {((42 31 31 38 38 30 32 44 2d 32 45 34 36 2d 34 45 34 31 2d 41 41 43 37 2d 39 45 45 38 39 30 32 36 38 46 38 42) | (42 00 31 00 31 00 38 00 38 00 30 00 32 00 44 00 2d 00 32 00 45 00 34 00 36 00 2d 00 34 00 45 00 34 00 31 00 2d 00 41 00 41 00 43 00 37 00 2d 00 39 00 45 00 45 00 38 00 39 00 30 00 32 00 36 00 38 00 46 00 38 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpShares : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/djhohnstein/SharpShares/"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		id = "e96aa79b-1da2-5b0c-9ac2-b6e201e06ec6"

	strings:
		$typelibguid0lo = {((66 65 39 66 64 64 65 35 2d 33 66 33 38 2d 34 66 31 34 2d 38 63 36 34 2d 63 33 33 32 38 63 32 31 35 63 66 32) | (66 00 65 00 39 00 66 00 64 00 64 00 65 00 35 00 2d 00 33 00 66 00 33 00 38 00 2d 00 34 00 66 00 31 00 34 00 2d 00 38 00 63 00 36 00 34 00 2d 00 63 00 33 00 33 00 32 00 38 00 63 00 32 00 31 00 35 00 63 00 66 00 32 00))}
		$typelibguid0up = {((46 45 39 46 44 44 45 35 2d 33 46 33 38 2d 34 46 31 34 2d 38 43 36 34 2d 43 33 33 32 38 43 32 31 35 43 46 32) | (46 00 45 00 39 00 46 00 44 00 44 00 45 00 35 00 2d 00 33 00 46 00 33 00 38 00 2d 00 34 00 46 00 31 00 34 00 2d 00 38 00 43 00 36 00 34 00 2d 00 43 00 33 00 33 00 32 00 38 00 43 00 32 00 31 00 35 00 43 00 46 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpEDRChecker : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/PwnDexter/SharpEDRChecker"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-18"
		modified = "2023-04-06"
		id = "f7ff344e-f8ee-5c3a-bdd1-de3cae8e7dfb"

	strings:
		$typelibguid0lo = {((62 64 66 65 65 32 33 33 2d 33 66 65 64 2d 34 32 65 35 2d 61 61 36 34 2d 34 39 32 65 62 32 61 63 37 30 34 37) | (62 00 64 00 66 00 65 00 65 00 32 00 33 00 33 00 2d 00 33 00 66 00 65 00 64 00 2d 00 34 00 32 00 65 00 35 00 2d 00 61 00 61 00 36 00 34 00 2d 00 34 00 39 00 32 00 65 00 62 00 32 00 61 00 63 00 37 00 30 00 34 00 37 00))}
		$typelibguid0up = {((42 44 46 45 45 32 33 33 2d 33 46 45 44 2d 34 32 45 35 2d 41 41 36 34 2d 34 39 32 45 42 32 41 43 37 30 34 37) | (42 00 44 00 46 00 45 00 45 00 32 00 33 00 33 00 2d 00 33 00 46 00 45 00 44 00 2d 00 34 00 32 00 45 00 35 00 2d 00 41 00 41 00 36 00 34 00 2d 00 34 00 39 00 32 00 45 00 42 00 32 00 41 00 43 00 37 00 30 00 34 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpClipHistory : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FSecureLABS/SharpClipHistory"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		id = "89ca4717-a4ec-5371-8dc3-bdb9933384af"

	strings:
		$typelibguid0lo = {((31 31 32 36 64 35 62 34 2d 65 66 63 37 2d 34 62 33 33 2d 61 35 39 34 2d 62 39 36 33 66 31 30 37 66 65 38 32) | (31 00 31 00 32 00 36 00 64 00 35 00 62 00 34 00 2d 00 65 00 66 00 63 00 37 00 2d 00 34 00 62 00 33 00 33 00 2d 00 61 00 35 00 39 00 34 00 2d 00 62 00 39 00 36 00 33 00 66 00 31 00 30 00 37 00 66 00 65 00 38 00 32 00))}
		$typelibguid0up = {((31 31 32 36 44 35 42 34 2d 45 46 43 37 2d 34 42 33 33 2d 41 35 39 34 2d 42 39 36 33 46 31 30 37 46 45 38 32) | (31 00 31 00 32 00 36 00 44 00 35 00 42 00 34 00 2d 00 45 00 46 00 43 00 37 00 2d 00 34 00 42 00 33 00 33 00 2d 00 41 00 35 00 39 00 34 00 2d 00 42 00 39 00 36 00 33 00 46 00 31 00 30 00 37 00 46 00 45 00 38 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpGPO_RemoteAccessPolicies : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FSecureLABS/SharpGPO-RemoteAccessPolicies"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		id = "642c2672-2327-5a4a-af91-6e0559996908"

	strings:
		$typelibguid0lo = {((66 62 62 31 61 62 63 66 2d 32 62 30 36 2d 34 37 61 30 2d 39 33 31 31 2d 31 37 62 61 33 64 30 66 32 61 35 30) | (66 00 62 00 62 00 31 00 61 00 62 00 63 00 66 00 2d 00 32 00 62 00 30 00 36 00 2d 00 34 00 37 00 61 00 30 00 2d 00 39 00 33 00 31 00 31 00 2d 00 31 00 37 00 62 00 61 00 33 00 64 00 30 00 66 00 32 00 61 00 35 00 30 00))}
		$typelibguid0up = {((46 42 42 31 41 42 43 46 2d 32 42 30 36 2d 34 37 41 30 2d 39 33 31 31 2d 31 37 42 41 33 44 30 46 32 41 35 30) | (46 00 42 00 42 00 31 00 41 00 42 00 43 00 46 00 2d 00 32 00 42 00 30 00 36 00 2d 00 34 00 37 00 41 00 30 00 2d 00 39 00 33 00 31 00 31 00 2d 00 31 00 37 00 42 00 41 00 33 00 44 00 30 00 46 00 32 00 41 00 35 00 30 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Absinthe : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/cameronhotchkies/Absinthe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		id = "8f25593b-b9d2-5807-b299-b039ecfd43a5"

	strings:
		$typelibguid0lo = {((39 39 33 36 61 65 37 33 2d 66 62 34 65 2d 34 63 35 65 2d 61 35 66 62 2d 66 38 61 61 65 62 33 62 39 62 64 36) | (39 00 39 00 33 00 36 00 61 00 65 00 37 00 33 00 2d 00 66 00 62 00 34 00 65 00 2d 00 34 00 63 00 35 00 65 00 2d 00 61 00 35 00 66 00 62 00 2d 00 66 00 38 00 61 00 61 00 65 00 62 00 33 00 62 00 39 00 62 00 64 00 36 00))}
		$typelibguid0up = {((39 39 33 36 41 45 37 33 2d 46 42 34 45 2d 34 43 35 45 2d 41 35 46 42 2d 46 38 41 41 45 42 33 42 39 42 44 36) | (39 00 39 00 33 00 36 00 41 00 45 00 37 00 33 00 2d 00 46 00 42 00 34 00 45 00 2d 00 34 00 43 00 35 00 45 00 2d 00 41 00 35 00 46 00 42 00 2d 00 46 00 38 00 41 00 41 00 45 00 42 00 33 00 42 00 39 00 42 00 44 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_ExploitRemotingService : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tyranid/ExploitRemotingService"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		id = "2f0b9635-2b2e-5825-baeb-69d7ae3791b1"

	strings:
		$typelibguid0lo = {((66 64 31 37 61 65 33 38 2d 32 66 64 33 2d 34 30 35 66 2d 62 38 35 62 2d 65 39 64 31 34 65 38 65 38 32 36 31) | (66 00 64 00 31 00 37 00 61 00 65 00 33 00 38 00 2d 00 32 00 66 00 64 00 33 00 2d 00 34 00 30 00 35 00 66 00 2d 00 62 00 38 00 35 00 62 00 2d 00 65 00 39 00 64 00 31 00 34 00 65 00 38 00 65 00 38 00 32 00 36 00 31 00))}
		$typelibguid0up = {((46 44 31 37 41 45 33 38 2d 32 46 44 33 2d 34 30 35 46 2d 42 38 35 42 2d 45 39 44 31 34 45 38 45 38 32 36 31) | (46 00 44 00 31 00 37 00 41 00 45 00 33 00 38 00 2d 00 32 00 46 00 44 00 33 00 2d 00 34 00 30 00 35 00 46 00 2d 00 42 00 38 00 35 00 42 00 2d 00 45 00 39 00 44 00 31 00 34 00 45 00 38 00 45 00 38 00 32 00 36 00 31 00))}
		$typelibguid1lo = {((31 38 35 30 62 39 62 62 2d 34 61 32 33 2d 34 64 37 34 2d 39 36 62 38 2d 35 38 66 32 37 34 36 37 34 35 36 36) | (31 00 38 00 35 00 30 00 62 00 39 00 62 00 62 00 2d 00 34 00 61 00 32 00 33 00 2d 00 34 00 64 00 37 00 34 00 2d 00 39 00 36 00 62 00 38 00 2d 00 35 00 38 00 66 00 32 00 37 00 34 00 36 00 37 00 34 00 35 00 36 00 36 00))}
		$typelibguid1up = {((31 38 35 30 42 39 42 42 2d 34 41 32 33 2d 34 44 37 34 2d 39 36 42 38 2d 35 38 46 32 37 34 36 37 34 35 36 36) | (31 00 38 00 35 00 30 00 42 00 39 00 42 00 42 00 2d 00 34 00 41 00 32 00 33 00 2d 00 34 00 44 00 37 00 34 00 2d 00 39 00 36 00 42 00 38 00 2d 00 35 00 38 00 46 00 32 00 37 00 34 00 36 00 37 00 34 00 35 00 36 00 36 00))}
		$typelibguid2lo = {((32 39 37 63 62 63 61 31 2d 65 66 61 33 2d 34 66 32 61 2d 38 64 35 66 2d 65 31 66 61 66 30 32 62 61 35 38 37) | (32 00 39 00 37 00 63 00 62 00 63 00 61 00 31 00 2d 00 65 00 66 00 61 00 33 00 2d 00 34 00 66 00 32 00 61 00 2d 00 38 00 64 00 35 00 66 00 2d 00 65 00 31 00 66 00 61 00 66 00 30 00 32 00 62 00 61 00 35 00 38 00 37 00))}
		$typelibguid2up = {((32 39 37 43 42 43 41 31 2d 45 46 41 33 2d 34 46 32 41 2d 38 44 35 46 2d 45 31 46 41 46 30 32 42 41 35 38 37) | (32 00 39 00 37 00 43 00 42 00 43 00 41 00 31 00 2d 00 45 00 46 00 41 00 33 00 2d 00 34 00 46 00 32 00 41 00 2d 00 38 00 44 00 35 00 46 00 2d 00 45 00 31 00 46 00 41 00 46 00 30 00 32 00 42 00 41 00 35 00 38 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Xploit : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/shargon/Xploit"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		id = "11ba6c14-06b6-5d9f-ac69-08ae506877e7"

	strings:
		$typelibguid0lo = {((34 35 34 35 63 66 64 65 2d 39 65 65 35 2d 34 66 31 62 2d 62 39 36 36 2d 64 31 32 38 61 66 30 62 39 61 36 65) | (34 00 35 00 34 00 35 00 63 00 66 00 64 00 65 00 2d 00 39 00 65 00 65 00 35 00 2d 00 34 00 66 00 31 00 62 00 2d 00 62 00 39 00 36 00 36 00 2d 00 64 00 31 00 32 00 38 00 61 00 66 00 30 00 62 00 39 00 61 00 36 00 65 00))}
		$typelibguid0up = {((34 35 34 35 43 46 44 45 2d 39 45 45 35 2d 34 46 31 42 2d 42 39 36 36 2d 44 31 32 38 41 46 30 42 39 41 36 45) | (34 00 35 00 34 00 35 00 43 00 46 00 44 00 45 00 2d 00 39 00 45 00 45 00 35 00 2d 00 34 00 46 00 31 00 42 00 2d 00 42 00 39 00 36 00 36 00 2d 00 44 00 31 00 32 00 38 00 41 00 46 00 30 00 42 00 39 00 41 00 36 00 45 00))}
		$typelibguid1lo = {((33 33 38 34 39 64 32 62 2d 33 62 65 38 2d 34 31 65 38 2d 61 31 65 32 2d 36 31 34 63 39 34 63 34 35 33 33 63) | (33 00 33 00 38 00 34 00 39 00 64 00 32 00 62 00 2d 00 33 00 62 00 65 00 38 00 2d 00 34 00 31 00 65 00 38 00 2d 00 61 00 31 00 65 00 32 00 2d 00 36 00 31 00 34 00 63 00 39 00 34 00 63 00 34 00 35 00 33 00 33 00 63 00))}
		$typelibguid1up = {((33 33 38 34 39 44 32 42 2d 33 42 45 38 2d 34 31 45 38 2d 41 31 45 32 2d 36 31 34 43 39 34 43 34 35 33 33 43) | (33 00 33 00 38 00 34 00 39 00 44 00 32 00 42 00 2d 00 33 00 42 00 45 00 38 00 2d 00 34 00 31 00 45 00 38 00 2d 00 41 00 31 00 45 00 32 00 2d 00 36 00 31 00 34 00 43 00 39 00 34 00 43 00 34 00 35 00 33 00 33 00 43 00))}
		$typelibguid2lo = {((63 32 64 63 37 33 63 63 2d 61 39 35 39 2d 34 39 36 35 2d 38 34 39 39 2d 61 39 65 31 37 32 30 65 35 39 34 62) | (63 00 32 00 64 00 63 00 37 00 33 00 63 00 63 00 2d 00 61 00 39 00 35 00 39 00 2d 00 34 00 39 00 36 00 35 00 2d 00 38 00 34 00 39 00 39 00 2d 00 61 00 39 00 65 00 31 00 37 00 32 00 30 00 65 00 35 00 39 00 34 00 62 00))}
		$typelibguid2up = {((43 32 44 43 37 33 43 43 2d 41 39 35 39 2d 34 39 36 35 2d 38 34 39 39 2d 41 39 45 31 37 32 30 45 35 39 34 42) | (43 00 32 00 44 00 43 00 37 00 33 00 43 00 43 00 2d 00 41 00 39 00 35 00 39 00 2d 00 34 00 39 00 36 00 35 00 2d 00 38 00 34 00 39 00 39 00 2d 00 41 00 39 00 45 00 31 00 37 00 32 00 30 00 45 00 35 00 39 00 34 00 42 00))}
		$typelibguid3lo = {((37 37 30 35 39 66 61 31 2d 34 62 37 64 2d 34 34 30 36 2d 62 63 31 61 2d 63 62 32 36 31 30 38 36 66 39 31 35) | (37 00 37 00 30 00 35 00 39 00 66 00 61 00 31 00 2d 00 34 00 62 00 37 00 64 00 2d 00 34 00 34 00 30 00 36 00 2d 00 62 00 63 00 31 00 61 00 2d 00 63 00 62 00 32 00 36 00 31 00 30 00 38 00 36 00 66 00 39 00 31 00 35 00))}
		$typelibguid3up = {((37 37 30 35 39 46 41 31 2d 34 42 37 44 2d 34 34 30 36 2d 42 43 31 41 2d 43 42 32 36 31 30 38 36 46 39 31 35) | (37 00 37 00 30 00 35 00 39 00 46 00 41 00 31 00 2d 00 34 00 42 00 37 00 44 00 2d 00 34 00 34 00 30 00 36 00 2d 00 42 00 43 00 31 00 41 00 2d 00 43 00 42 00 32 00 36 00 31 00 30 00 38 00 36 00 46 00 39 00 31 00 35 00))}
		$typelibguid4lo = {((61 34 61 30 34 63 34 64 2d 35 34 39 30 2d 34 33 30 39 2d 39 63 39 30 2d 33 35 31 65 35 65 35 66 64 36 64 31) | (61 00 34 00 61 00 30 00 34 00 63 00 34 00 64 00 2d 00 35 00 34 00 39 00 30 00 2d 00 34 00 33 00 30 00 39 00 2d 00 39 00 63 00 39 00 30 00 2d 00 33 00 35 00 31 00 65 00 35 00 65 00 35 00 66 00 64 00 36 00 64 00 31 00))}
		$typelibguid4up = {((41 34 41 30 34 43 34 44 2d 35 34 39 30 2d 34 33 30 39 2d 39 43 39 30 2d 33 35 31 45 35 45 35 46 44 36 44 31) | (41 00 34 00 41 00 30 00 34 00 43 00 34 00 44 00 2d 00 35 00 34 00 39 00 30 00 2d 00 34 00 33 00 30 00 39 00 2d 00 39 00 43 00 39 00 30 00 2d 00 33 00 35 00 31 00 45 00 35 00 45 00 35 00 46 00 44 00 36 00 44 00 31 00))}
		$typelibguid5lo = {((63 61 36 34 66 39 31 38 2d 33 32 39 36 2d 34 62 37 64 2d 39 63 65 36 2d 62 39 38 33 38 39 38 39 36 37 36 35) | (63 00 61 00 36 00 34 00 66 00 39 00 31 00 38 00 2d 00 33 00 32 00 39 00 36 00 2d 00 34 00 62 00 37 00 64 00 2d 00 39 00 63 00 65 00 36 00 2d 00 62 00 39 00 38 00 33 00 38 00 39 00 38 00 39 00 36 00 37 00 36 00 35 00))}
		$typelibguid5up = {((43 41 36 34 46 39 31 38 2d 33 32 39 36 2d 34 42 37 44 2d 39 43 45 36 2d 42 39 38 33 38 39 38 39 36 37 36 35) | (43 00 41 00 36 00 34 00 46 00 39 00 31 00 38 00 2d 00 33 00 32 00 39 00 36 00 2d 00 34 00 42 00 37 00 44 00 2d 00 39 00 43 00 45 00 36 00 2d 00 42 00 39 00 38 00 33 00 38 00 39 00 38 00 39 00 36 00 37 00 36 00 35 00))}
		$typelibguid6lo = {((31 30 66 65 33 32 61 30 2d 64 37 39 31 2d 34 37 62 32 2d 38 35 33 30 2d 30 62 31 39 64 39 31 34 33 34 66 37) | (31 00 30 00 66 00 65 00 33 00 32 00 61 00 30 00 2d 00 64 00 37 00 39 00 31 00 2d 00 34 00 37 00 62 00 32 00 2d 00 38 00 35 00 33 00 30 00 2d 00 30 00 62 00 31 00 39 00 64 00 39 00 31 00 34 00 33 00 34 00 66 00 37 00))}
		$typelibguid6up = {((31 30 46 45 33 32 41 30 2d 44 37 39 31 2d 34 37 42 32 2d 38 35 33 30 2d 30 42 31 39 44 39 31 34 33 34 46 37) | (31 00 30 00 46 00 45 00 33 00 32 00 41 00 30 00 2d 00 44 00 37 00 39 00 31 00 2d 00 34 00 37 00 42 00 32 00 2d 00 38 00 35 00 33 00 30 00 2d 00 30 00 42 00 31 00 39 00 44 00 39 00 31 00 34 00 33 00 34 00 46 00 37 00))}
		$typelibguid7lo = {((36 37 39 62 62 61 35 37 2d 33 30 36 33 2d 34 66 31 37 2d 62 34 39 31 2d 34 66 30 61 37 33 30 64 36 62 30 32) | (36 00 37 00 39 00 62 00 62 00 61 00 35 00 37 00 2d 00 33 00 30 00 36 00 33 00 2d 00 34 00 66 00 31 00 37 00 2d 00 62 00 34 00 39 00 31 00 2d 00 34 00 66 00 30 00 61 00 37 00 33 00 30 00 64 00 36 00 62 00 30 00 32 00))}
		$typelibguid7up = {((36 37 39 42 42 41 35 37 2d 33 30 36 33 2d 34 46 31 37 2d 42 34 39 31 2d 34 46 30 41 37 33 30 44 36 42 30 32) | (36 00 37 00 39 00 42 00 42 00 41 00 35 00 37 00 2d 00 33 00 30 00 36 00 33 00 2d 00 34 00 46 00 31 00 37 00 2d 00 42 00 34 00 39 00 31 00 2d 00 34 00 46 00 30 00 41 00 37 00 33 00 30 00 44 00 36 00 42 00 30 00 32 00))}
		$typelibguid8lo = {((30 39 38 31 65 31 36 34 2d 35 39 33 30 2d 34 62 61 30 2d 39 38 33 63 2d 31 63 66 36 37 39 65 35 30 33 33 66) | (30 00 39 00 38 00 31 00 65 00 31 00 36 00 34 00 2d 00 35 00 39 00 33 00 30 00 2d 00 34 00 62 00 61 00 30 00 2d 00 39 00 38 00 33 00 63 00 2d 00 31 00 63 00 66 00 36 00 37 00 39 00 65 00 35 00 30 00 33 00 33 00 66 00))}
		$typelibguid8up = {((30 39 38 31 45 31 36 34 2d 35 39 33 30 2d 34 42 41 30 2d 39 38 33 43 2d 31 43 46 36 37 39 45 35 30 33 33 46) | (30 00 39 00 38 00 31 00 45 00 31 00 36 00 34 00 2d 00 35 00 39 00 33 00 30 00 2d 00 34 00 42 00 41 00 30 00 2d 00 39 00 38 00 33 00 43 00 2d 00 31 00 43 00 46 00 36 00 37 00 39 00 45 00 35 00 30 00 33 00 33 00 46 00))}
		$typelibguid9lo = {((32 61 38 34 34 63 61 32 2d 35 64 36 63 2d 34 35 62 35 2d 39 36 33 62 2d 37 64 63 61 31 31 34 30 65 31 36 66) | (32 00 61 00 38 00 34 00 34 00 63 00 61 00 32 00 2d 00 35 00 64 00 36 00 63 00 2d 00 34 00 35 00 62 00 35 00 2d 00 39 00 36 00 33 00 62 00 2d 00 37 00 64 00 63 00 61 00 31 00 31 00 34 00 30 00 65 00 31 00 36 00 66 00))}
		$typelibguid9up = {((32 41 38 34 34 43 41 32 2d 35 44 36 43 2d 34 35 42 35 2d 39 36 33 42 2d 37 44 43 41 31 31 34 30 45 31 36 46) | (32 00 41 00 38 00 34 00 34 00 43 00 41 00 32 00 2d 00 35 00 44 00 36 00 43 00 2d 00 34 00 35 00 42 00 35 00 2d 00 39 00 36 00 33 00 42 00 2d 00 37 00 44 00 43 00 41 00 31 00 31 00 34 00 30 00 45 00 31 00 36 00 46 00))}
		$typelibguid10lo = {((37 64 37 35 63 61 31 31 2d 38 37 34 35 2d 34 33 38 32 2d 62 33 65 62 2d 63 34 31 34 31 36 64 62 63 34 38 63) | (37 00 64 00 37 00 35 00 63 00 61 00 31 00 31 00 2d 00 38 00 37 00 34 00 35 00 2d 00 34 00 33 00 38 00 32 00 2d 00 62 00 33 00 65 00 62 00 2d 00 63 00 34 00 31 00 34 00 31 00 36 00 64 00 62 00 63 00 34 00 38 00 63 00))}
		$typelibguid10up = {((37 44 37 35 43 41 31 31 2d 38 37 34 35 2d 34 33 38 32 2d 42 33 45 42 2d 43 34 31 34 31 36 44 42 43 34 38 43) | (37 00 44 00 37 00 35 00 43 00 41 00 31 00 31 00 2d 00 38 00 37 00 34 00 35 00 2d 00 34 00 33 00 38 00 32 00 2d 00 42 00 33 00 45 00 42 00 2d 00 43 00 34 00 31 00 34 00 31 00 36 00 44 00 42 00 43 00 34 00 38 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_PoC : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/thezdi/PoC"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		id = "5669bc1a-b32e-5ae7-bf94-8ed2a124c765"

	strings:
		$typelibguid0lo = {((38 39 66 39 64 34 31 31 2d 65 32 37 33 2d 34 31 62 62 2d 38 37 31 31 2d 32 30 39 66 64 32 35 31 63 61 38 38) | (38 00 39 00 66 00 39 00 64 00 34 00 31 00 31 00 2d 00 65 00 32 00 37 00 33 00 2d 00 34 00 31 00 62 00 62 00 2d 00 38 00 37 00 31 00 31 00 2d 00 32 00 30 00 39 00 66 00 64 00 32 00 35 00 31 00 63 00 61 00 38 00 38 00))}
		$typelibguid0up = {((38 39 46 39 44 34 31 31 2d 45 32 37 33 2d 34 31 42 42 2d 38 37 31 31 2d 32 30 39 46 44 32 35 31 43 41 38 38) | (38 00 39 00 46 00 39 00 44 00 34 00 31 00 31 00 2d 00 45 00 32 00 37 00 33 00 2d 00 34 00 31 00 42 00 42 00 2d 00 38 00 37 00 31 00 31 00 2d 00 32 00 30 00 39 00 46 00 44 00 32 00 35 00 31 00 43 00 41 00 38 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpGPOAbuse : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FSecureLABS/SharpGPOAbuse"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		id = "ea27044f-69be-5db7-8d77-28dafb18c7e5"

	strings:
		$typelibguid0lo = {((34 66 34 39 35 37 38 34 2d 62 34 34 33 2d 34 38 33 38 2d 39 66 61 36 2d 39 31 34 39 32 39 33 61 66 37 38 35) | (34 00 66 00 34 00 39 00 35 00 37 00 38 00 34 00 2d 00 62 00 34 00 34 00 33 00 2d 00 34 00 38 00 33 00 38 00 2d 00 39 00 66 00 61 00 36 00 2d 00 39 00 31 00 34 00 39 00 32 00 39 00 33 00 61 00 66 00 37 00 38 00 35 00))}
		$typelibguid0up = {((34 46 34 39 35 37 38 34 2d 42 34 34 33 2d 34 38 33 38 2d 39 46 41 36 2d 39 31 34 39 32 39 33 41 46 37 38 35) | (34 00 46 00 34 00 39 00 35 00 37 00 38 00 34 00 2d 00 42 00 34 00 34 00 33 00 2d 00 34 00 38 00 33 00 38 00 2d 00 39 00 46 00 41 00 36 00 2d 00 39 00 31 00 34 00 39 00 32 00 39 00 33 00 41 00 46 00 37 00 38 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Watson : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rasta-mouse/Watson"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		id = "6dc7bb08-0b34-50a0-8ae8-02d96d66a334"

	strings:
		$typelibguid0lo = {((34 39 61 64 35 66 33 38 2d 39 65 33 37 2d 34 39 36 37 2d 39 65 38 34 2d 66 65 31 39 63 37 34 33 34 65 64 37) | (34 00 39 00 61 00 64 00 35 00 66 00 33 00 38 00 2d 00 39 00 65 00 33 00 37 00 2d 00 34 00 39 00 36 00 37 00 2d 00 39 00 65 00 38 00 34 00 2d 00 66 00 65 00 31 00 39 00 63 00 37 00 34 00 33 00 34 00 65 00 64 00 37 00))}
		$typelibguid0up = {((34 39 41 44 35 46 33 38 2d 39 45 33 37 2d 34 39 36 37 2d 39 45 38 34 2d 46 45 31 39 43 37 34 33 34 45 44 37) | (34 00 39 00 41 00 44 00 35 00 46 00 33 00 38 00 2d 00 39 00 45 00 33 00 37 00 2d 00 34 00 39 00 36 00 37 00 2d 00 39 00 45 00 38 00 34 00 2d 00 46 00 45 00 31 00 39 00 43 00 37 00 34 00 33 00 34 00 45 00 44 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_StandIn : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FuzzySecurity/StandIn"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		id = "2af3c28a-ce5d-5dea-9abe-ff54b180049e"

	strings:
		$typelibguid0lo = {((30 31 63 31 34 32 62 61 2d 37 61 66 31 2d 34 38 64 36 2d 62 31 38 35 2d 38 31 31 34 37 61 32 66 37 64 62 37) | (30 00 31 00 63 00 31 00 34 00 32 00 62 00 61 00 2d 00 37 00 61 00 66 00 31 00 2d 00 34 00 38 00 64 00 36 00 2d 00 62 00 31 00 38 00 35 00 2d 00 38 00 31 00 31 00 34 00 37 00 61 00 32 00 66 00 37 00 64 00 62 00 37 00))}
		$typelibguid0up = {((30 31 43 31 34 32 42 41 2d 37 41 46 31 2d 34 38 44 36 2d 42 31 38 35 2d 38 31 31 34 37 41 32 46 37 44 42 37) | (30 00 31 00 43 00 31 00 34 00 32 00 42 00 41 00 2d 00 37 00 41 00 46 00 31 00 2d 00 34 00 38 00 44 00 36 00 2d 00 42 00 31 00 38 00 35 00 2d 00 38 00 31 00 31 00 34 00 37 00 41 00 32 00 46 00 37 00 44 00 42 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_azure_password_harvesting : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/guardicore/azure_password_harvesting"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		id = "681cf9da-d664-5402-b7ac-eb2cfad85da9"

	strings:
		$typelibguid0lo = {((37 61 64 31 66 66 32 64 2d 33 32 61 63 2d 34 63 35 34 2d 62 36 31 35 2d 39 62 62 31 36 34 31 36 30 64 61 63) | (37 00 61 00 64 00 31 00 66 00 66 00 32 00 64 00 2d 00 33 00 32 00 61 00 63 00 2d 00 34 00 63 00 35 00 34 00 2d 00 62 00 36 00 31 00 35 00 2d 00 39 00 62 00 62 00 31 00 36 00 34 00 31 00 36 00 30 00 64 00 61 00 63 00))}
		$typelibguid0up = {((37 41 44 31 46 46 32 44 2d 33 32 41 43 2d 34 43 35 34 2d 42 36 31 35 2d 39 42 42 31 36 34 31 36 30 44 41 43) | (37 00 41 00 44 00 31 00 46 00 46 00 32 00 44 00 2d 00 33 00 32 00 41 00 43 00 2d 00 34 00 43 00 35 00 34 00 2d 00 42 00 36 00 31 00 35 00 2d 00 39 00 42 00 42 00 31 00 36 00 34 00 31 00 36 00 30 00 44 00 41 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_PowerOPS : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/fdiskyou/PowerOPS"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		id = "3ef9f099-13c9-5b6f-8615-232240530078"

	strings:
		$typelibguid0lo = {((32 61 33 63 35 39 32 31 2d 37 34 34 32 2d 34 32 63 33 2d 38 63 62 39 2d 32 34 66 32 31 64 30 62 32 34 31 34) | (32 00 61 00 33 00 63 00 35 00 39 00 32 00 31 00 2d 00 37 00 34 00 34 00 32 00 2d 00 34 00 32 00 63 00 33 00 2d 00 38 00 63 00 62 00 39 00 2d 00 32 00 34 00 66 00 32 00 31 00 64 00 30 00 62 00 32 00 34 00 31 00 34 00))}
		$typelibguid0up = {((32 41 33 43 35 39 32 31 2d 37 34 34 32 2d 34 32 43 33 2d 38 43 42 39 2d 32 34 46 32 31 44 30 42 32 34 31 34) | (32 00 41 00 33 00 43 00 35 00 39 00 32 00 31 00 2d 00 37 00 34 00 34 00 32 00 2d 00 34 00 32 00 43 00 33 00 2d 00 38 00 43 00 42 00 39 00 2d 00 32 00 34 00 46 00 32 00 31 00 44 00 30 00 42 00 32 00 34 00 31 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Random_CSharpTools : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/xorrior/Random-CSharpTools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		id = "ad8b5573-ad20-50cd-927b-a6401b10e653"

	strings:
		$typelibguid0lo = {((66 37 66 63 31 39 64 61 2d 36 37 61 33 2d 34 33 37 64 2d 62 33 62 30 2d 32 61 32 35 37 66 37 37 61 30 30 62) | (66 00 37 00 66 00 63 00 31 00 39 00 64 00 61 00 2d 00 36 00 37 00 61 00 33 00 2d 00 34 00 33 00 37 00 64 00 2d 00 62 00 33 00 62 00 30 00 2d 00 32 00 61 00 32 00 35 00 37 00 66 00 37 00 37 00 61 00 30 00 30 00 62 00))}
		$typelibguid0up = {((46 37 46 43 31 39 44 41 2d 36 37 41 33 2d 34 33 37 44 2d 42 33 42 30 2d 32 41 32 35 37 46 37 37 41 30 30 42) | (46 00 37 00 46 00 43 00 31 00 39 00 44 00 41 00 2d 00 36 00 37 00 41 00 33 00 2d 00 34 00 33 00 37 00 44 00 2d 00 42 00 33 00 42 00 30 00 2d 00 32 00 41 00 32 00 35 00 37 00 46 00 37 00 37 00 41 00 30 00 30 00 42 00))}
		$typelibguid1lo = {((34 37 65 38 35 62 62 36 2d 39 31 33 38 2d 34 33 37 34 2d 38 30 39 32 2d 30 61 65 62 33 30 31 66 65 36 34 62) | (34 00 37 00 65 00 38 00 35 00 62 00 62 00 36 00 2d 00 39 00 31 00 33 00 38 00 2d 00 34 00 33 00 37 00 34 00 2d 00 38 00 30 00 39 00 32 00 2d 00 30 00 61 00 65 00 62 00 33 00 30 00 31 00 66 00 65 00 36 00 34 00 62 00))}
		$typelibguid1up = {((34 37 45 38 35 42 42 36 2d 39 31 33 38 2d 34 33 37 34 2d 38 30 39 32 2d 30 41 45 42 33 30 31 46 45 36 34 42) | (34 00 37 00 45 00 38 00 35 00 42 00 42 00 36 00 2d 00 39 00 31 00 33 00 38 00 2d 00 34 00 33 00 37 00 34 00 2d 00 38 00 30 00 39 00 32 00 2d 00 30 00 41 00 45 00 42 00 33 00 30 00 31 00 46 00 45 00 36 00 34 00 42 00))}
		$typelibguid2lo = {((63 37 64 38 35 34 64 38 2d 34 65 33 61 2d 34 33 61 36 2d 38 37 32 66 2d 65 30 37 31 30 65 35 39 34 33 66 37) | (63 00 37 00 64 00 38 00 35 00 34 00 64 00 38 00 2d 00 34 00 65 00 33 00 61 00 2d 00 34 00 33 00 61 00 36 00 2d 00 38 00 37 00 32 00 66 00 2d 00 65 00 30 00 37 00 31 00 30 00 65 00 35 00 39 00 34 00 33 00 66 00 37 00))}
		$typelibguid2up = {((43 37 44 38 35 34 44 38 2d 34 45 33 41 2d 34 33 41 36 2d 38 37 32 46 2d 45 30 37 31 30 45 35 39 34 33 46 37) | (43 00 37 00 44 00 38 00 35 00 34 00 44 00 38 00 2d 00 34 00 45 00 33 00 41 00 2d 00 34 00 33 00 41 00 36 00 2d 00 38 00 37 00 32 00 46 00 2d 00 45 00 30 00 37 00 31 00 30 00 45 00 35 00 39 00 34 00 33 00 46 00 37 00))}
		$typelibguid3lo = {((64 36 36 38 35 34 33 30 2d 38 64 38 64 2d 34 65 32 65 2d 62 32 30 32 2d 64 65 31 34 65 66 61 32 35 32 31 31) | (64 00 36 00 36 00 38 00 35 00 34 00 33 00 30 00 2d 00 38 00 64 00 38 00 64 00 2d 00 34 00 65 00 32 00 65 00 2d 00 62 00 32 00 30 00 32 00 2d 00 64 00 65 00 31 00 34 00 65 00 66 00 61 00 32 00 35 00 32 00 31 00 31 00))}
		$typelibguid3up = {((44 36 36 38 35 34 33 30 2d 38 44 38 44 2d 34 45 32 45 2d 42 32 30 32 2d 44 45 31 34 45 46 41 32 35 32 31 31) | (44 00 36 00 36 00 38 00 35 00 34 00 33 00 30 00 2d 00 38 00 44 00 38 00 44 00 2d 00 34 00 45 00 32 00 45 00 2d 00 42 00 32 00 30 00 32 00 2d 00 44 00 45 00 31 00 34 00 45 00 46 00 41 00 32 00 35 00 32 00 31 00 31 00))}
		$typelibguid4lo = {((31 64 66 39 32 35 66 63 2d 39 61 38 39 2d 34 31 37 30 2d 62 37 36 33 2d 31 63 37 33 35 34 33 30 62 37 64 30) | (31 00 64 00 66 00 39 00 32 00 35 00 66 00 63 00 2d 00 39 00 61 00 38 00 39 00 2d 00 34 00 31 00 37 00 30 00 2d 00 62 00 37 00 36 00 33 00 2d 00 31 00 63 00 37 00 33 00 35 00 34 00 33 00 30 00 62 00 37 00 64 00 30 00))}
		$typelibguid4up = {((31 44 46 39 32 35 46 43 2d 39 41 38 39 2d 34 31 37 30 2d 42 37 36 33 2d 31 43 37 33 35 34 33 30 42 37 44 30) | (31 00 44 00 46 00 39 00 32 00 35 00 46 00 43 00 2d 00 39 00 41 00 38 00 39 00 2d 00 34 00 31 00 37 00 30 00 2d 00 42 00 37 00 36 00 33 00 2d 00 31 00 43 00 37 00 33 00 35 00 34 00 33 00 30 00 42 00 37 00 44 00 30 00))}
		$typelibguid5lo = {((38 31 37 63 63 36 31 62 2d 38 34 37 31 2d 34 63 31 65 2d 62 35 64 36 2d 63 37 35 34 66 63 35 35 30 61 30 33) | (38 00 31 00 37 00 63 00 63 00 36 00 31 00 62 00 2d 00 38 00 34 00 37 00 31 00 2d 00 34 00 63 00 31 00 65 00 2d 00 62 00 35 00 64 00 36 00 2d 00 63 00 37 00 35 00 34 00 66 00 63 00 35 00 35 00 30 00 61 00 30 00 33 00))}
		$typelibguid5up = {((38 31 37 43 43 36 31 42 2d 38 34 37 31 2d 34 43 31 45 2d 42 35 44 36 2d 43 37 35 34 46 43 35 35 30 41 30 33) | (38 00 31 00 37 00 43 00 43 00 36 00 31 00 42 00 2d 00 38 00 34 00 37 00 31 00 2d 00 34 00 43 00 31 00 45 00 2d 00 42 00 35 00 44 00 36 00 2d 00 43 00 37 00 35 00 34 00 46 00 43 00 35 00 35 00 30 00 41 00 30 00 33 00))}
		$typelibguid6lo = {((36 30 31 31 36 36 31 33 2d 63 37 34 65 2d 34 31 62 39 2d 62 38 30 65 2d 33 35 65 30 32 66 32 35 38 39 31 65) | (36 00 30 00 31 00 31 00 36 00 36 00 31 00 33 00 2d 00 63 00 37 00 34 00 65 00 2d 00 34 00 31 00 62 00 39 00 2d 00 62 00 38 00 30 00 65 00 2d 00 33 00 35 00 65 00 30 00 32 00 66 00 32 00 35 00 38 00 39 00 31 00 65 00))}
		$typelibguid6up = {((36 30 31 31 36 36 31 33 2d 43 37 34 45 2d 34 31 42 39 2d 42 38 30 45 2d 33 35 45 30 32 46 32 35 38 39 31 45) | (36 00 30 00 31 00 31 00 36 00 36 00 31 00 33 00 2d 00 43 00 37 00 34 00 45 00 2d 00 34 00 31 00 42 00 39 00 2d 00 42 00 38 00 30 00 45 00 2d 00 33 00 35 00 45 00 30 00 32 00 46 00 32 00 35 00 38 00 39 00 31 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_CVE_2020_0668 : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/RedCursorSecurityConsulting/CVE-2020-0668"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "54c87578-f0f1-5108-a736-b6acd9624d29"

	strings:
		$typelibguid0lo = {((31 62 34 63 35 65 63 31 2d 32 38 34 35 2d 34 30 66 64 2d 61 31 37 33 2d 36 32 63 34 35 30 66 31 32 65 61 35) | (31 00 62 00 34 00 63 00 35 00 65 00 63 00 31 00 2d 00 32 00 38 00 34 00 35 00 2d 00 34 00 30 00 66 00 64 00 2d 00 61 00 31 00 37 00 33 00 2d 00 36 00 32 00 63 00 34 00 35 00 30 00 66 00 31 00 32 00 65 00 61 00 35 00))}
		$typelibguid0up = {((31 42 34 43 35 45 43 31 2d 32 38 34 35 2d 34 30 46 44 2d 41 31 37 33 2d 36 32 43 34 35 30 46 31 32 45 41 35) | (31 00 42 00 34 00 43 00 35 00 45 00 43 00 31 00 2d 00 32 00 38 00 34 00 35 00 2d 00 34 00 30 00 46 00 44 00 2d 00 41 00 31 00 37 00 33 00 2d 00 36 00 32 00 43 00 34 00 35 00 30 00 46 00 31 00 32 00 45 00 41 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_WindowsRpcClients : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tyranid/WindowsRpcClients"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "70fd7431-8c32-52a4-be9f-2a19ef77f2cc"

	strings:
		$typelibguid0lo = {((38 34 33 64 38 38 36 32 2d 34 32 65 62 2d 34 39 65 65 2d 39 34 65 36 2d 62 63 61 37 39 38 64 64 33 33 65 61) | (38 00 34 00 33 00 64 00 38 00 38 00 36 00 32 00 2d 00 34 00 32 00 65 00 62 00 2d 00 34 00 39 00 65 00 65 00 2d 00 39 00 34 00 65 00 36 00 2d 00 62 00 63 00 61 00 37 00 39 00 38 00 64 00 64 00 33 00 33 00 65 00 61 00))}
		$typelibguid0up = {((38 34 33 44 38 38 36 32 2d 34 32 45 42 2d 34 39 45 45 2d 39 34 45 36 2d 42 43 41 37 39 38 44 44 33 33 45 41) | (38 00 34 00 33 00 44 00 38 00 38 00 36 00 32 00 2d 00 34 00 32 00 45 00 42 00 2d 00 34 00 39 00 45 00 45 00 2d 00 39 00 34 00 45 00 36 00 2d 00 42 00 43 00 41 00 37 00 39 00 38 00 44 00 44 00 33 00 33 00 45 00 41 00))}
		$typelibguid1lo = {((36 33 32 65 34 63 33 62 2d 33 30 31 33 2d 34 36 66 63 2d 62 63 36 65 2d 32 32 38 32 38 62 66 36 32 39 65 33) | (36 00 33 00 32 00 65 00 34 00 63 00 33 00 62 00 2d 00 33 00 30 00 31 00 33 00 2d 00 34 00 36 00 66 00 63 00 2d 00 62 00 63 00 36 00 65 00 2d 00 32 00 32 00 38 00 32 00 38 00 62 00 66 00 36 00 32 00 39 00 65 00 33 00))}
		$typelibguid1up = {((36 33 32 45 34 43 33 42 2d 33 30 31 33 2d 34 36 46 43 2d 42 43 36 45 2d 32 32 38 32 38 42 46 36 32 39 45 33) | (36 00 33 00 32 00 45 00 34 00 43 00 33 00 42 00 2d 00 33 00 30 00 31 00 33 00 2d 00 34 00 36 00 46 00 43 00 2d 00 42 00 43 00 36 00 45 00 2d 00 32 00 32 00 38 00 32 00 38 00 42 00 46 00 36 00 32 00 39 00 45 00 33 00))}
		$typelibguid2lo = {((61 32 30 39 31 64 32 66 2d 36 66 37 65 2d 34 31 31 38 2d 61 32 30 33 2d 34 63 65 61 34 62 65 61 36 62 66 61) | (61 00 32 00 30 00 39 00 31 00 64 00 32 00 66 00 2d 00 36 00 66 00 37 00 65 00 2d 00 34 00 31 00 31 00 38 00 2d 00 61 00 32 00 30 00 33 00 2d 00 34 00 63 00 65 00 61 00 34 00 62 00 65 00 61 00 36 00 62 00 66 00 61 00))}
		$typelibguid2up = {((41 32 30 39 31 44 32 46 2d 36 46 37 45 2d 34 31 31 38 2d 41 32 30 33 2d 34 43 45 41 34 42 45 41 36 42 46 41) | (41 00 32 00 30 00 39 00 31 00 44 00 32 00 46 00 2d 00 36 00 46 00 37 00 45 00 2d 00 34 00 31 00 31 00 38 00 2d 00 41 00 32 00 30 00 33 00 2d 00 34 00 43 00 45 00 41 00 34 00 42 00 45 00 41 00 36 00 42 00 46 00 41 00))}
		$typelibguid3lo = {((39 35 30 65 66 38 63 65 2d 65 63 39 32 2d 34 65 30 32 2d 62 31 32 32 2d 30 64 34 31 64 38 33 30 36 35 62 38) | (39 00 35 00 30 00 65 00 66 00 38 00 63 00 65 00 2d 00 65 00 63 00 39 00 32 00 2d 00 34 00 65 00 30 00 32 00 2d 00 62 00 31 00 32 00 32 00 2d 00 30 00 64 00 34 00 31 00 64 00 38 00 33 00 30 00 36 00 35 00 62 00 38 00))}
		$typelibguid3up = {((39 35 30 45 46 38 43 45 2d 45 43 39 32 2d 34 45 30 32 2d 42 31 32 32 2d 30 44 34 31 44 38 33 30 36 35 42 38) | (39 00 35 00 30 00 45 00 46 00 38 00 43 00 45 00 2d 00 45 00 43 00 39 00 32 00 2d 00 34 00 45 00 30 00 32 00 2d 00 42 00 31 00 32 00 32 00 2d 00 30 00 44 00 34 00 31 00 44 00 38 00 33 00 30 00 36 00 35 00 42 00 38 00))}
		$typelibguid4lo = {((64 35 31 33 30 31 62 63 2d 33 31 61 61 2d 34 34 37 35 2d 38 39 34 34 2d 38 38 32 65 63 66 38 30 65 31 30 64) | (64 00 35 00 31 00 33 00 30 00 31 00 62 00 63 00 2d 00 33 00 31 00 61 00 61 00 2d 00 34 00 34 00 37 00 35 00 2d 00 38 00 39 00 34 00 34 00 2d 00 38 00 38 00 32 00 65 00 63 00 66 00 38 00 30 00 65 00 31 00 30 00 64 00))}
		$typelibguid4up = {((44 35 31 33 30 31 42 43 2d 33 31 41 41 2d 34 34 37 35 2d 38 39 34 34 2d 38 38 32 45 43 46 38 30 45 31 30 44) | (44 00 35 00 31 00 33 00 30 00 31 00 42 00 43 00 2d 00 33 00 31 00 41 00 41 00 2d 00 34 00 34 00 37 00 35 00 2d 00 38 00 39 00 34 00 34 00 2d 00 38 00 38 00 32 00 45 00 43 00 46 00 38 00 30 00 45 00 31 00 30 00 44 00))}
		$typelibguid5lo = {((38 32 33 66 66 31 31 31 2d 34 64 65 32 2d 34 36 33 37 2d 61 66 30 31 2d 34 62 64 63 33 63 61 34 63 66 31 35) | (38 00 32 00 33 00 66 00 66 00 31 00 31 00 31 00 2d 00 34 00 64 00 65 00 32 00 2d 00 34 00 36 00 33 00 37 00 2d 00 61 00 66 00 30 00 31 00 2d 00 34 00 62 00 64 00 63 00 33 00 63 00 61 00 34 00 63 00 66 00 31 00 35 00))}
		$typelibguid5up = {((38 32 33 46 46 31 31 31 2d 34 44 45 32 2d 34 36 33 37 2d 41 46 30 31 2d 34 42 44 43 33 43 41 34 43 46 31 35) | (38 00 32 00 33 00 46 00 46 00 31 00 31 00 31 00 2d 00 34 00 44 00 45 00 32 00 2d 00 34 00 36 00 33 00 37 00 2d 00 41 00 46 00 30 00 31 00 2d 00 34 00 42 00 44 00 43 00 33 00 43 00 41 00 34 00 43 00 46 00 31 00 35 00))}
		$typelibguid6lo = {((35 64 32 38 66 31 35 65 2d 33 62 62 38 2d 34 30 38 38 2d 61 62 65 30 2d 62 35 31 37 62 33 31 64 34 35 39 35) | (35 00 64 00 32 00 38 00 66 00 31 00 35 00 65 00 2d 00 33 00 62 00 62 00 38 00 2d 00 34 00 30 00 38 00 38 00 2d 00 61 00 62 00 65 00 30 00 2d 00 62 00 35 00 31 00 37 00 62 00 33 00 31 00 64 00 34 00 35 00 39 00 35 00))}
		$typelibguid6up = {((35 44 32 38 46 31 35 45 2d 33 42 42 38 2d 34 30 38 38 2d 41 42 45 30 2d 42 35 31 37 42 33 31 44 34 35 39 35) | (35 00 44 00 32 00 38 00 46 00 31 00 35 00 45 00 2d 00 33 00 42 00 42 00 38 00 2d 00 34 00 30 00 38 00 38 00 2d 00 41 00 42 00 45 00 30 00 2d 00 42 00 35 00 31 00 37 00 42 00 33 00 31 00 44 00 34 00 35 00 39 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpFruit : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rvrsh3ll/SharpFruit"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "bf318530-b17d-5275-84b2-c284528bdae6"

	strings:
		$typelibguid0lo = {((33 64 61 32 66 36 64 65 2d 37 35 62 65 2d 34 63 39 64 2d 38 30 37 30 2d 30 38 64 61 34 35 65 37 39 37 36 31) | (33 00 64 00 61 00 32 00 66 00 36 00 64 00 65 00 2d 00 37 00 35 00 62 00 65 00 2d 00 34 00 63 00 39 00 64 00 2d 00 38 00 30 00 37 00 30 00 2d 00 30 00 38 00 64 00 61 00 34 00 35 00 65 00 37 00 39 00 37 00 36 00 31 00))}
		$typelibguid0up = {((33 44 41 32 46 36 44 45 2d 37 35 42 45 2d 34 43 39 44 2d 38 30 37 30 2d 30 38 44 41 34 35 45 37 39 37 36 31) | (33 00 44 00 41 00 32 00 46 00 36 00 44 00 45 00 2d 00 37 00 35 00 42 00 45 00 2d 00 34 00 43 00 39 00 44 00 2d 00 38 00 30 00 37 00 30 00 2d 00 30 00 38 00 44 00 41 00 34 00 35 00 45 00 37 00 39 00 37 00 36 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpWitness : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rasta-mouse/SharpWitness"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "5e707da6-b2dd-511e-89ad-d19b93e8fca6"

	strings:
		$typelibguid0lo = {((62 39 66 36 65 63 33 34 2d 34 63 63 63 2d 34 32 34 37 2d 62 63 65 66 2d 63 31 64 61 61 62 39 62 34 34 36 39) | (62 00 39 00 66 00 36 00 65 00 63 00 33 00 34 00 2d 00 34 00 63 00 63 00 63 00 2d 00 34 00 32 00 34 00 37 00 2d 00 62 00 63 00 65 00 66 00 2d 00 63 00 31 00 64 00 61 00 61 00 62 00 39 00 62 00 34 00 34 00 36 00 39 00))}
		$typelibguid0up = {((42 39 46 36 45 43 33 34 2d 34 43 43 43 2d 34 32 34 37 2d 42 43 45 46 2d 43 31 44 41 41 42 39 42 34 34 36 39) | (42 00 39 00 46 00 36 00 45 00 43 00 33 00 34 00 2d 00 34 00 43 00 43 00 43 00 2d 00 34 00 32 00 34 00 37 00 2d 00 42 00 43 00 45 00 46 00 2d 00 43 00 31 00 44 00 41 00 41 00 42 00 39 00 42 00 34 00 34 00 36 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_RexCrypter : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/syrex1013/RexCrypter"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "5ebbeab3-3e93-5544-8f74-3d1b47335d8b"

	strings:
		$typelibguid0lo = {((31 30 63 64 37 63 31 63 2d 65 35 36 64 2d 34 62 31 62 2d 38 30 64 63 2d 65 34 63 34 39 36 63 35 66 65 63 35) | (31 00 30 00 63 00 64 00 37 00 63 00 31 00 63 00 2d 00 65 00 35 00 36 00 64 00 2d 00 34 00 62 00 31 00 62 00 2d 00 38 00 30 00 64 00 63 00 2d 00 65 00 34 00 63 00 34 00 39 00 36 00 63 00 35 00 66 00 65 00 63 00 35 00))}
		$typelibguid0up = {((31 30 43 44 37 43 31 43 2d 45 35 36 44 2d 34 42 31 42 2d 38 30 44 43 2d 45 34 43 34 39 36 43 35 46 45 43 35) | (31 00 30 00 43 00 44 00 37 00 43 00 31 00 43 00 2d 00 45 00 35 00 36 00 44 00 2d 00 34 00 42 00 31 00 42 00 2d 00 38 00 30 00 44 00 43 00 2d 00 45 00 34 00 43 00 34 00 39 00 36 00 43 00 35 00 46 00 45 00 43 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharPersist : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/fireeye/SharPersist"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "0c181186-7bb4-502b-8937-60cfd88ce689"

	strings:
		$typelibguid0lo = {((39 64 31 62 38 35 33 65 2d 35 38 66 31 2d 34 62 61 35 2d 61 65 66 63 2d 35 63 32 32 31 63 61 33 30 65 34 38) | (39 00 64 00 31 00 62 00 38 00 35 00 33 00 65 00 2d 00 35 00 38 00 66 00 31 00 2d 00 34 00 62 00 61 00 35 00 2d 00 61 00 65 00 66 00 63 00 2d 00 35 00 63 00 32 00 32 00 31 00 63 00 61 00 33 00 30 00 65 00 34 00 38 00))}
		$typelibguid0up = {((39 44 31 42 38 35 33 45 2d 35 38 46 31 2d 34 42 41 35 2d 41 45 46 43 2d 35 43 32 32 31 43 41 33 30 45 34 38) | (39 00 44 00 31 00 42 00 38 00 35 00 33 00 45 00 2d 00 35 00 38 00 46 00 31 00 2d 00 34 00 42 00 41 00 35 00 2d 00 41 00 45 00 46 00 43 00 2d 00 35 00 43 00 32 00 32 00 31 00 43 00 41 00 33 00 30 00 45 00 34 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_CVE_2019_1253 : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/padovah4ck/CVE-2019-1253"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "3e18b533-1b85-5eaf-bb3d-aa5b90fd2e28"

	strings:
		$typelibguid0lo = {((35 38 34 39 36 34 63 31 2d 66 39 38 33 2d 34 39 38 64 2d 38 33 37 30 2d 32 33 65 32 37 66 64 64 30 33 39 39) | (35 00 38 00 34 00 39 00 36 00 34 00 63 00 31 00 2d 00 66 00 39 00 38 00 33 00 2d 00 34 00 39 00 38 00 64 00 2d 00 38 00 33 00 37 00 30 00 2d 00 32 00 33 00 65 00 32 00 37 00 66 00 64 00 64 00 30 00 33 00 39 00 39 00))}
		$typelibguid0up = {((35 38 34 39 36 34 43 31 2d 46 39 38 33 2d 34 39 38 44 2d 38 33 37 30 2d 32 33 45 32 37 46 44 44 30 33 39 39) | (35 00 38 00 34 00 39 00 36 00 34 00 43 00 31 00 2d 00 46 00 39 00 38 00 33 00 2d 00 34 00 39 00 38 00 44 00 2d 00 38 00 33 00 37 00 30 00 2d 00 32 00 33 00 45 00 32 00 37 00 46 00 44 00 44 00 30 00 33 00 39 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_scout : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jaredhaight/scout"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "cd24cca7-3bc0-5e7a-9817-dc3b26ec8358"

	strings:
		$typelibguid0lo = {((64 39 63 37 36 65 38 32 2d 62 38 34 38 2d 34 37 64 34 2d 38 66 32 32 2d 39 39 62 66 32 32 61 38 65 65 31 31) | (64 00 39 00 63 00 37 00 36 00 65 00 38 00 32 00 2d 00 62 00 38 00 34 00 38 00 2d 00 34 00 37 00 64 00 34 00 2d 00 38 00 66 00 32 00 32 00 2d 00 39 00 39 00 62 00 66 00 32 00 32 00 61 00 38 00 65 00 65 00 31 00 31 00))}
		$typelibguid0up = {((44 39 43 37 36 45 38 32 2d 42 38 34 38 2d 34 37 44 34 2d 38 46 32 32 2d 39 39 42 46 32 32 41 38 45 45 31 31) | (44 00 39 00 43 00 37 00 36 00 45 00 38 00 32 00 2d 00 42 00 38 00 34 00 38 00 2d 00 34 00 37 00 44 00 34 00 2d 00 38 00 46 00 32 00 32 00 2d 00 39 00 39 00 42 00 46 00 32 00 32 00 41 00 38 00 45 00 45 00 31 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Grouper2 : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/l0ss/Grouper2/"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "a9cd9a16-b2a5-5d15-af89-7a8d0f1835bb"

	strings:
		$typelibguid0lo = {((35 64 65 63 61 65 61 33 2d 32 36 31 30 2d 34 30 36 35 2d 39 39 64 63 2d 36 35 62 39 62 34 62 61 36 63 63 64) | (35 00 64 00 65 00 63 00 61 00 65 00 61 00 33 00 2d 00 32 00 36 00 31 00 30 00 2d 00 34 00 30 00 36 00 35 00 2d 00 39 00 39 00 64 00 63 00 2d 00 36 00 35 00 62 00 39 00 62 00 34 00 62 00 61 00 36 00 63 00 63 00 64 00))}
		$typelibguid0up = {((35 44 45 43 41 45 41 33 2d 32 36 31 30 2d 34 30 36 35 2d 39 39 44 43 2d 36 35 42 39 42 34 42 41 36 43 43 44) | (35 00 44 00 45 00 43 00 41 00 45 00 41 00 33 00 2d 00 32 00 36 00 31 00 30 00 2d 00 34 00 30 00 36 00 35 00 2d 00 39 00 39 00 44 00 43 00 2d 00 36 00 35 00 42 00 39 00 42 00 34 00 42 00 41 00 36 00 43 00 43 00 44 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_CasperStager : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ustayready/CasperStager"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "0ad18d2b-b7cc-5316-a8e8-b05d4439b8e1"

	strings:
		$typelibguid0lo = {((63 36 35 33 61 39 66 32 2d 30 39 33 39 2d 34 33 63 38 2d 39 62 39 33 2d 66 65 64 35 65 32 65 34 63 37 65 36) | (63 00 36 00 35 00 33 00 61 00 39 00 66 00 32 00 2d 00 30 00 39 00 33 00 39 00 2d 00 34 00 33 00 63 00 38 00 2d 00 39 00 62 00 39 00 33 00 2d 00 66 00 65 00 64 00 35 00 65 00 32 00 65 00 34 00 63 00 37 00 65 00 36 00))}
		$typelibguid0up = {((43 36 35 33 41 39 46 32 2d 30 39 33 39 2d 34 33 43 38 2d 39 42 39 33 2d 46 45 44 35 45 32 45 34 43 37 45 36) | (43 00 36 00 35 00 33 00 41 00 39 00 46 00 32 00 2d 00 30 00 39 00 33 00 39 00 2d 00 34 00 33 00 43 00 38 00 2d 00 39 00 42 00 39 00 33 00 2d 00 46 00 45 00 44 00 35 00 45 00 32 00 45 00 34 00 43 00 37 00 45 00 36 00))}
		$typelibguid1lo = {((34 38 64 66 63 35 35 65 2d 36 61 65 35 2d 34 61 33 36 2d 61 62 65 66 2d 31 34 62 63 30 39 64 37 35 31 30 62) | (34 00 38 00 64 00 66 00 63 00 35 00 35 00 65 00 2d 00 36 00 61 00 65 00 35 00 2d 00 34 00 61 00 33 00 36 00 2d 00 61 00 62 00 65 00 66 00 2d 00 31 00 34 00 62 00 63 00 30 00 39 00 64 00 37 00 35 00 31 00 30 00 62 00))}
		$typelibguid1up = {((34 38 44 46 43 35 35 45 2d 36 41 45 35 2d 34 41 33 36 2d 41 42 45 46 2d 31 34 42 43 30 39 44 37 35 31 30 42) | (34 00 38 00 44 00 46 00 43 00 35 00 35 00 45 00 2d 00 36 00 41 00 45 00 35 00 2d 00 34 00 41 00 33 00 36 00 2d 00 41 00 42 00 45 00 46 00 2d 00 31 00 34 00 42 00 43 00 30 00 39 00 44 00 37 00 35 00 31 00 30 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_TellMeYourSecrets : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xbadjuju/TellMeYourSecrets"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "b00c353b-0446-5faa-87e5-0a7ba6ec2286"

	strings:
		$typelibguid0lo = {((39 62 34 34 38 30 36 32 2d 37 32 31 39 2d 34 64 38 32 2d 39 61 30 61 2d 65 37 38 34 63 34 62 33 61 61 32 37) | (39 00 62 00 34 00 34 00 38 00 30 00 36 00 32 00 2d 00 37 00 32 00 31 00 39 00 2d 00 34 00 64 00 38 00 32 00 2d 00 39 00 61 00 30 00 61 00 2d 00 65 00 37 00 38 00 34 00 63 00 34 00 62 00 33 00 61 00 61 00 32 00 37 00))}
		$typelibguid0up = {((39 42 34 34 38 30 36 32 2d 37 32 31 39 2d 34 44 38 32 2d 39 41 30 41 2d 45 37 38 34 43 34 42 33 41 41 32 37) | (39 00 42 00 34 00 34 00 38 00 30 00 36 00 32 00 2d 00 37 00 32 00 31 00 39 00 2d 00 34 00 44 00 38 00 32 00 2d 00 39 00 41 00 30 00 41 00 2d 00 45 00 37 00 38 00 34 00 43 00 34 00 42 00 33 00 41 00 41 00 32 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpExcel4_DCOM : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rvrsh3ll/SharpExcel4-DCOM"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "12d3f26b-40ca-5034-a7c2-9be9c8a7599b"

	strings:
		$typelibguid0lo = {((36 38 62 38 33 63 65 35 2d 62 62 64 39 2d 34 65 65 33 2d 62 31 63 63 2d 35 65 39 32 32 33 66 61 62 35 32 62) | (36 00 38 00 62 00 38 00 33 00 63 00 65 00 35 00 2d 00 62 00 62 00 64 00 39 00 2d 00 34 00 65 00 65 00 33 00 2d 00 62 00 31 00 63 00 63 00 2d 00 35 00 65 00 39 00 32 00 32 00 33 00 66 00 61 00 62 00 35 00 32 00 62 00))}
		$typelibguid0up = {((36 38 42 38 33 43 45 35 2d 42 42 44 39 2d 34 45 45 33 2d 42 31 43 43 2d 35 45 39 32 32 33 46 41 42 35 32 42) | (36 00 38 00 42 00 38 00 33 00 43 00 45 00 35 00 2d 00 42 00 42 00 44 00 39 00 2d 00 34 00 45 00 45 00 33 00 2d 00 42 00 31 00 43 00 43 00 2d 00 35 00 45 00 39 00 32 00 32 00 33 00 46 00 41 00 42 00 35 00 32 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpShooter : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mdsecactivebreach/SharpShooter"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "a59e6fe9-dbaf-5830-8cf1-485ff4dd939a"

	strings:
		$typelibguid0lo = {((35 36 35 39 38 66 31 63 2d 36 64 38 38 2d 34 39 39 34 2d 61 33 39 32 2d 61 66 33 33 37 61 62 65 35 37 37 37) | (35 00 36 00 35 00 39 00 38 00 66 00 31 00 63 00 2d 00 36 00 64 00 38 00 38 00 2d 00 34 00 39 00 39 00 34 00 2d 00 61 00 33 00 39 00 32 00 2d 00 61 00 66 00 33 00 33 00 37 00 61 00 62 00 65 00 35 00 37 00 37 00 37 00))}
		$typelibguid0up = {((35 36 35 39 38 46 31 43 2d 36 44 38 38 2d 34 39 39 34 2d 41 33 39 32 2d 41 46 33 33 37 41 42 45 35 37 37 37) | (35 00 36 00 35 00 39 00 38 00 46 00 31 00 43 00 2d 00 36 00 44 00 38 00 38 00 2d 00 34 00 39 00 39 00 34 00 2d 00 41 00 33 00 39 00 32 00 2d 00 41 00 46 00 33 00 33 00 37 00 41 00 42 00 45 00 35 00 37 00 37 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_NoMSBuild : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rvrsh3ll/NoMSBuild"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "9bc0661d-c60f-582b-8f88-87e3dfa13ddd"

	strings:
		$typelibguid0lo = {((30 33 34 61 37 62 39 66 2d 31 38 64 66 2d 34 35 64 61 2d 62 38 37 30 2d 30 65 31 63 65 66 35 30 30 32 31 35) | (30 00 33 00 34 00 61 00 37 00 62 00 39 00 66 00 2d 00 31 00 38 00 64 00 66 00 2d 00 34 00 35 00 64 00 61 00 2d 00 62 00 38 00 37 00 30 00 2d 00 30 00 65 00 31 00 63 00 65 00 66 00 35 00 30 00 30 00 32 00 31 00 35 00))}
		$typelibguid0up = {((30 33 34 41 37 42 39 46 2d 31 38 44 46 2d 34 35 44 41 2d 42 38 37 30 2d 30 45 31 43 45 46 35 30 30 32 31 35) | (30 00 33 00 34 00 41 00 37 00 42 00 39 00 46 00 2d 00 31 00 38 00 44 00 46 00 2d 00 34 00 35 00 44 00 41 00 2d 00 42 00 38 00 37 00 30 00 2d 00 30 00 45 00 31 00 43 00 45 00 46 00 35 00 30 00 30 00 32 00 31 00 35 00))}
		$typelibguid1lo = {((35 39 62 34 34 39 64 37 2d 63 31 65 38 2d 34 66 34 37 2d 38 30 62 38 2d 37 33 37 35 31 37 38 39 36 31 64 62) | (35 00 39 00 62 00 34 00 34 00 39 00 64 00 37 00 2d 00 63 00 31 00 65 00 38 00 2d 00 34 00 66 00 34 00 37 00 2d 00 38 00 30 00 62 00 38 00 2d 00 37 00 33 00 37 00 35 00 31 00 37 00 38 00 39 00 36 00 31 00 64 00 62 00))}
		$typelibguid1up = {((35 39 42 34 34 39 44 37 2d 43 31 45 38 2d 34 46 34 37 2d 38 30 42 38 2d 37 33 37 35 31 37 38 39 36 31 44 42) | (35 00 39 00 42 00 34 00 34 00 39 00 44 00 37 00 2d 00 43 00 31 00 45 00 38 00 2d 00 34 00 46 00 34 00 37 00 2d 00 38 00 30 00 42 00 38 00 2d 00 37 00 33 00 37 00 35 00 31 00 37 00 38 00 39 00 36 00 31 00 44 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_TeleShadow2 : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ParsingTeam/TeleShadow2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "5b22f2c4-0bd1-5a5a-8867-8fbc773d2b44"

	strings:
		$typelibguid0lo = {((34 32 63 35 63 33 35 36 2d 33 39 63 66 2d 34 63 30 37 2d 39 36 64 66 2d 65 62 62 30 63 63 66 37 38 63 61 34) | (34 00 32 00 63 00 35 00 63 00 33 00 35 00 36 00 2d 00 33 00 39 00 63 00 66 00 2d 00 34 00 63 00 30 00 37 00 2d 00 39 00 36 00 64 00 66 00 2d 00 65 00 62 00 62 00 30 00 63 00 63 00 66 00 37 00 38 00 63 00 61 00 34 00))}
		$typelibguid0up = {((34 32 43 35 43 33 35 36 2d 33 39 43 46 2d 34 43 30 37 2d 39 36 44 46 2d 45 42 42 30 43 43 46 37 38 43 41 34) | (34 00 32 00 43 00 35 00 43 00 33 00 35 00 36 00 2d 00 33 00 39 00 43 00 46 00 2d 00 34 00 43 00 30 00 37 00 2d 00 39 00 36 00 44 00 46 00 2d 00 45 00 42 00 42 00 30 00 43 00 43 00 46 00 37 00 38 00 43 00 41 00 34 00))}
		$typelibguid1lo = {((30 32 34 32 62 35 62 31 2d 34 64 32 36 2d 34 31 33 65 2d 38 63 38 63 2d 31 33 62 34 65 64 33 30 64 35 31 30) | (30 00 32 00 34 00 32 00 62 00 35 00 62 00 31 00 2d 00 34 00 64 00 32 00 36 00 2d 00 34 00 31 00 33 00 65 00 2d 00 38 00 63 00 38 00 63 00 2d 00 31 00 33 00 62 00 34 00 65 00 64 00 33 00 30 00 64 00 35 00 31 00 30 00))}
		$typelibguid1up = {((30 32 34 32 42 35 42 31 2d 34 44 32 36 2d 34 31 33 45 2d 38 43 38 43 2d 31 33 42 34 45 44 33 30 44 35 31 30) | (30 00 32 00 34 00 32 00 42 00 35 00 42 00 31 00 2d 00 34 00 44 00 32 00 36 00 2d 00 34 00 31 00 33 00 45 00 2d 00 38 00 43 00 38 00 43 00 2d 00 31 00 33 00 42 00 34 00 45 00 44 00 33 00 30 00 44 00 35 00 31 00 30 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_BadPotato : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/BeichenDream/BadPotato"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "8bee12fc-fc29-5256-b559-d914ef202c0c"

	strings:
		$typelibguid0lo = {((30 35 32 37 61 31 34 66 2d 31 35 39 31 2d 34 64 39 34 2d 39 34 33 65 2d 64 36 64 37 38 34 61 35 30 35 34 39) | (30 00 35 00 32 00 37 00 61 00 31 00 34 00 66 00 2d 00 31 00 35 00 39 00 31 00 2d 00 34 00 64 00 39 00 34 00 2d 00 39 00 34 00 33 00 65 00 2d 00 64 00 36 00 64 00 37 00 38 00 34 00 61 00 35 00 30 00 35 00 34 00 39 00))}
		$typelibguid0up = {((30 35 32 37 41 31 34 46 2d 31 35 39 31 2d 34 44 39 34 2d 39 34 33 45 2d 44 36 44 37 38 34 41 35 30 35 34 39) | (30 00 35 00 32 00 37 00 41 00 31 00 34 00 46 00 2d 00 31 00 35 00 39 00 31 00 2d 00 34 00 44 00 39 00 34 00 2d 00 39 00 34 00 33 00 45 00 2d 00 44 00 36 00 44 00 37 00 38 00 34 00 41 00 35 00 30 00 35 00 34 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_LethalHTA : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/codewhitesec/LethalHTA"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "e8e1ad03-a5f0-5508-b78d-0de7bdaf4704"

	strings:
		$typelibguid0lo = {((37 38 34 63 64 65 31 37 2d 66 66 30 66 2d 34 65 34 33 2d 39 31 31 61 2d 31 39 31 31 39 65 38 39 63 34 33 66) | (37 00 38 00 34 00 63 00 64 00 65 00 31 00 37 00 2d 00 66 00 66 00 30 00 66 00 2d 00 34 00 65 00 34 00 33 00 2d 00 39 00 31 00 31 00 61 00 2d 00 31 00 39 00 31 00 31 00 39 00 65 00 38 00 39 00 63 00 34 00 33 00 66 00))}
		$typelibguid0up = {((37 38 34 43 44 45 31 37 2d 46 46 30 46 2d 34 45 34 33 2d 39 31 31 41 2d 31 39 31 31 39 45 38 39 43 34 33 46) | (37 00 38 00 34 00 43 00 44 00 45 00 31 00 37 00 2d 00 46 00 46 00 30 00 46 00 2d 00 34 00 45 00 34 00 33 00 2d 00 39 00 31 00 31 00 41 00 2d 00 31 00 39 00 31 00 31 00 39 00 45 00 38 00 39 00 43 00 34 00 33 00 46 00))}
		$typelibguid1lo = {((37 65 32 64 65 32 63 30 2d 36 31 64 63 2d 34 33 61 62 2d 61 30 65 63 2d 63 32 37 65 65 32 31 37 32 65 61 36) | (37 00 65 00 32 00 64 00 65 00 32 00 63 00 30 00 2d 00 36 00 31 00 64 00 63 00 2d 00 34 00 33 00 61 00 62 00 2d 00 61 00 30 00 65 00 63 00 2d 00 63 00 32 00 37 00 65 00 65 00 32 00 31 00 37 00 32 00 65 00 61 00 36 00))}
		$typelibguid1up = {((37 45 32 44 45 32 43 30 2d 36 31 44 43 2d 34 33 41 42 2d 41 30 45 43 2d 43 32 37 45 45 32 31 37 32 45 41 36) | (37 00 45 00 32 00 44 00 45 00 32 00 43 00 30 00 2d 00 36 00 31 00 44 00 43 00 2d 00 34 00 33 00 41 00 42 00 2d 00 41 00 30 00 45 00 43 00 2d 00 43 00 32 00 37 00 45 00 45 00 32 00 31 00 37 00 32 00 45 00 41 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpStat : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Raikia/SharpStat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "649c6cc0-e43b-558c-9567-00f352af528b"

	strings:
		$typelibguid0lo = {((66 66 63 35 63 37 32 31 2d 34 39 63 38 2d 34 34 38 64 2d 38 66 66 34 2d 32 65 33 61 37 62 37 63 63 33 38 33) | (66 00 66 00 63 00 35 00 63 00 37 00 32 00 31 00 2d 00 34 00 39 00 63 00 38 00 2d 00 34 00 34 00 38 00 64 00 2d 00 38 00 66 00 66 00 34 00 2d 00 32 00 65 00 33 00 61 00 37 00 62 00 37 00 63 00 63 00 33 00 38 00 33 00))}
		$typelibguid0up = {((46 46 43 35 43 37 32 31 2d 34 39 43 38 2d 34 34 38 44 2d 38 46 46 34 2d 32 45 33 41 37 42 37 43 43 33 38 33) | (46 00 46 00 43 00 35 00 43 00 37 00 32 00 31 00 2d 00 34 00 39 00 43 00 38 00 2d 00 34 00 34 00 38 00 44 00 2d 00 38 00 46 00 46 00 34 00 2d 00 32 00 45 00 33 00 41 00 37 00 42 00 37 00 43 00 43 00 33 00 38 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SneakyService : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/malcomvetter/SneakyService"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "d02d34f0-7aa1-5110-b7ea-670b5fb98150"

	strings:
		$typelibguid0lo = {((38 39 37 38 31 39 64 35 2d 35 38 65 30 2d 34 36 61 30 2d 38 65 31 61 2d 39 31 65 61 36 61 32 36 39 64 38 34) | (38 00 39 00 37 00 38 00 31 00 39 00 64 00 35 00 2d 00 35 00 38 00 65 00 30 00 2d 00 34 00 36 00 61 00 30 00 2d 00 38 00 65 00 31 00 61 00 2d 00 39 00 31 00 65 00 61 00 36 00 61 00 32 00 36 00 39 00 64 00 38 00 34 00))}
		$typelibguid0up = {((38 39 37 38 31 39 44 35 2d 35 38 45 30 2d 34 36 41 30 2d 38 45 31 41 2d 39 31 45 41 36 41 32 36 39 44 38 34) | (38 00 39 00 37 00 38 00 31 00 39 00 44 00 35 00 2d 00 35 00 38 00 45 00 30 00 2d 00 34 00 36 00 41 00 30 00 2d 00 38 00 45 00 31 00 41 00 2d 00 39 00 31 00 45 00 41 00 36 00 41 00 32 00 36 00 39 00 44 00 38 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpExec : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/anthemtotheego/SharpExec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "5faff0aa-9ffe-5ac0-b9e0-ca9f79350036"

	strings:
		$typelibguid0lo = {((37 66 62 61 64 31 32 36 2d 65 32 31 63 2d 34 63 34 65 2d 61 39 66 30 2d 36 31 33 66 63 66 35 38 35 61 37 31) | (37 00 66 00 62 00 61 00 64 00 31 00 32 00 36 00 2d 00 65 00 32 00 31 00 63 00 2d 00 34 00 63 00 34 00 65 00 2d 00 61 00 39 00 66 00 30 00 2d 00 36 00 31 00 33 00 66 00 63 00 66 00 35 00 38 00 35 00 61 00 37 00 31 00))}
		$typelibguid0up = {((37 46 42 41 44 31 32 36 2d 45 32 31 43 2d 34 43 34 45 2d 41 39 46 30 2d 36 31 33 46 43 46 35 38 35 41 37 31) | (37 00 46 00 42 00 41 00 44 00 31 00 32 00 36 00 2d 00 45 00 32 00 31 00 43 00 2d 00 34 00 43 00 34 00 45 00 2d 00 41 00 39 00 46 00 30 00 2d 00 36 00 31 00 33 00 46 00 43 00 46 00 35 00 38 00 35 00 41 00 37 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpCOM : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rvrsh3ll/SharpCOM"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "94da3da4-a8aa-5735-9a04-1f2447a330aa"

	strings:
		$typelibguid0lo = {((35 31 39 36 30 66 37 64 2d 37 36 66 65 2d 34 39 39 66 2d 61 66 62 64 2d 61 63 61 62 64 37 62 61 35 30 64 31) | (35 00 31 00 39 00 36 00 30 00 66 00 37 00 64 00 2d 00 37 00 36 00 66 00 65 00 2d 00 34 00 39 00 39 00 66 00 2d 00 61 00 66 00 62 00 64 00 2d 00 61 00 63 00 61 00 62 00 64 00 37 00 62 00 61 00 35 00 30 00 64 00 31 00))}
		$typelibguid0up = {((35 31 39 36 30 46 37 44 2d 37 36 46 45 2d 34 39 39 46 2d 41 46 42 44 2d 41 43 41 42 44 37 42 41 35 30 44 31) | (35 00 31 00 39 00 36 00 30 00 46 00 37 00 44 00 2d 00 37 00 36 00 46 00 45 00 2d 00 34 00 39 00 39 00 46 00 2d 00 41 00 46 00 42 00 44 00 2d 00 41 00 43 00 41 00 42 00 44 00 37 00 42 00 41 00 35 00 30 00 44 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Inception : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/two06/Inception"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "8d18f1d5-9c9a-5258-9f96-fa24b702c6ad"

	strings:
		$typelibguid0lo = {((30 33 64 39 36 62 38 63 2d 65 66 64 31 2d 34 34 61 39 2d 38 64 62 32 2d 30 62 37 34 64 62 35 64 32 34 37 61) | (30 00 33 00 64 00 39 00 36 00 62 00 38 00 63 00 2d 00 65 00 66 00 64 00 31 00 2d 00 34 00 34 00 61 00 39 00 2d 00 38 00 64 00 62 00 32 00 2d 00 30 00 62 00 37 00 34 00 64 00 62 00 35 00 64 00 32 00 34 00 37 00 61 00))}
		$typelibguid0up = {((30 33 44 39 36 42 38 43 2d 45 46 44 31 2d 34 34 41 39 2d 38 44 42 32 2d 30 42 37 34 44 42 35 44 32 34 37 41) | (30 00 33 00 44 00 39 00 36 00 42 00 38 00 43 00 2d 00 45 00 46 00 44 00 31 00 2d 00 34 00 34 00 41 00 39 00 2d 00 38 00 44 00 42 00 32 00 2d 00 30 00 42 00 37 00 34 00 44 00 42 00 35 00 44 00 32 00 34 00 37 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpWMI_1 : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/QAX-A-Team/sharpwmi"
		old_rule_name = "HKTL_NET_GUID_sharpwmi"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "cd5a1c7b-a45a-5541-b1b0-cf19c991ed22"

	strings:
		$typelibguid0lo = {((62 62 33 35 37 64 33 38 2d 36 64 63 31 2d 34 66 32 30 2d 61 35 34 63 2d 64 36 36 34 62 64 32 30 36 37 37 65) | (62 00 62 00 33 00 35 00 37 00 64 00 33 00 38 00 2d 00 36 00 64 00 63 00 31 00 2d 00 34 00 66 00 32 00 30 00 2d 00 61 00 35 00 34 00 63 00 2d 00 64 00 36 00 36 00 34 00 62 00 64 00 32 00 30 00 36 00 37 00 37 00 65 00))}
		$typelibguid0up = {((42 42 33 35 37 44 33 38 2d 36 44 43 31 2d 34 46 32 30 2d 41 35 34 43 2d 44 36 36 34 42 44 32 30 36 37 37 45) | (42 00 42 00 33 00 35 00 37 00 44 00 33 00 38 00 2d 00 36 00 44 00 43 00 31 00 2d 00 34 00 46 00 32 00 30 00 2d 00 41 00 35 00 34 00 43 00 2d 00 44 00 36 00 36 00 34 00 42 00 44 00 32 00 30 00 36 00 37 00 37 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_CVE_2019_1064 : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/RythmStick/CVE-2019-1064"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "4640e874-faa4-58dc-a3f3-18246a343f15"

	strings:
		$typelibguid0lo = {((66 66 39 37 65 39 38 61 2d 36 33 35 65 2d 34 65 61 39 2d 62 32 64 30 2d 31 61 31 33 66 36 62 64 62 63 33 38) | (66 00 66 00 39 00 37 00 65 00 39 00 38 00 61 00 2d 00 36 00 33 00 35 00 65 00 2d 00 34 00 65 00 61 00 39 00 2d 00 62 00 32 00 64 00 30 00 2d 00 31 00 61 00 31 00 33 00 66 00 36 00 62 00 64 00 62 00 63 00 33 00 38 00))}
		$typelibguid0up = {((46 46 39 37 45 39 38 41 2d 36 33 35 45 2d 34 45 41 39 2d 42 32 44 30 2d 31 41 31 33 46 36 42 44 42 43 33 38) | (46 00 46 00 39 00 37 00 45 00 39 00 38 00 41 00 2d 00 36 00 33 00 35 00 45 00 2d 00 34 00 45 00 41 00 39 00 2d 00 42 00 32 00 44 00 30 00 2d 00 31 00 41 00 31 00 33 00 46 00 36 00 42 00 44 00 42 00 43 00 33 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Tokenvator : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xbadjuju/Tokenvator"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "84ebb6b3-cf11-5172-95d4-d114bfeb0bc7"

	strings:
		$typelibguid0lo = {((34 62 32 62 33 62 64 34 2d 64 32 38 66 2d 34 34 63 63 2d 39 36 62 33 2d 34 61 32 66 36 34 32 31 33 31 30 39) | (34 00 62 00 32 00 62 00 33 00 62 00 64 00 34 00 2d 00 64 00 32 00 38 00 66 00 2d 00 34 00 34 00 63 00 63 00 2d 00 39 00 36 00 62 00 33 00 2d 00 34 00 61 00 32 00 66 00 36 00 34 00 32 00 31 00 33 00 31 00 30 00 39 00))}
		$typelibguid0up = {((34 42 32 42 33 42 44 34 2d 44 32 38 46 2d 34 34 43 43 2d 39 36 42 33 2d 34 41 32 46 36 34 32 31 33 31 30 39) | (34 00 42 00 32 00 42 00 33 00 42 00 44 00 34 00 2d 00 44 00 32 00 38 00 46 00 2d 00 34 00 34 00 43 00 43 00 2d 00 39 00 36 00 42 00 33 00 2d 00 34 00 41 00 32 00 46 00 36 00 34 00 32 00 31 00 33 00 31 00 30 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_WheresMyImplant : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xbadjuju/WheresMyImplant"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "c99523ce-e2c0-5a21-89d1-70c0dd970731"

	strings:
		$typelibguid0lo = {((63 63 61 35 39 65 34 65 2d 63 65 34 64 2d 34 30 66 63 2d 39 36 35 66 2d 33 34 35 36 30 33 33 30 63 37 65 36) | (63 00 63 00 61 00 35 00 39 00 65 00 34 00 65 00 2d 00 63 00 65 00 34 00 64 00 2d 00 34 00 30 00 66 00 63 00 2d 00 39 00 36 00 35 00 66 00 2d 00 33 00 34 00 35 00 36 00 30 00 33 00 33 00 30 00 63 00 37 00 65 00 36 00))}
		$typelibguid0up = {((43 43 41 35 39 45 34 45 2d 43 45 34 44 2d 34 30 46 43 2d 39 36 35 46 2d 33 34 35 36 30 33 33 30 43 37 45 36) | (43 00 43 00 41 00 35 00 39 00 45 00 34 00 45 00 2d 00 43 00 45 00 34 00 44 00 2d 00 34 00 30 00 46 00 43 00 2d 00 39 00 36 00 35 00 46 00 2d 00 33 00 34 00 35 00 36 00 30 00 33 00 33 00 30 00 43 00 37 00 45 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Naga : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/byt3bl33d3r/Naga"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "3a9d3154-a8f1-57a4-8b61-498e2ebdfa42"

	strings:
		$typelibguid0lo = {((39 39 34 32 38 37 33 32 2d 34 39 37 39 2d 34 37 62 36 2d 61 33 32 33 2d 30 62 62 37 64 36 64 30 37 63 39 35) | (39 00 39 00 34 00 32 00 38 00 37 00 33 00 32 00 2d 00 34 00 39 00 37 00 39 00 2d 00 34 00 37 00 62 00 36 00 2d 00 61 00 33 00 32 00 33 00 2d 00 30 00 62 00 62 00 37 00 64 00 36 00 64 00 30 00 37 00 63 00 39 00 35 00))}
		$typelibguid0up = {((39 39 34 32 38 37 33 32 2d 34 39 37 39 2d 34 37 42 36 2d 41 33 32 33 2d 30 42 42 37 44 36 44 30 37 43 39 35) | (39 00 39 00 34 00 32 00 38 00 37 00 33 00 32 00 2d 00 34 00 39 00 37 00 39 00 2d 00 34 00 37 00 42 00 36 00 2d 00 41 00 33 00 32 00 33 00 2d 00 30 00 42 00 42 00 37 00 44 00 36 00 44 00 30 00 37 00 43 00 39 00 35 00))}
		$typelibguid1lo = {((61 32 63 39 34 38 38 66 2d 36 30 36 37 2d 34 62 31 37 2d 38 63 36 66 2d 32 64 34 36 34 65 36 35 63 35 33 35) | (61 00 32 00 63 00 39 00 34 00 38 00 38 00 66 00 2d 00 36 00 30 00 36 00 37 00 2d 00 34 00 62 00 31 00 37 00 2d 00 38 00 63 00 36 00 66 00 2d 00 32 00 64 00 34 00 36 00 34 00 65 00 36 00 35 00 63 00 35 00 33 00 35 00))}
		$typelibguid1up = {((41 32 43 39 34 38 38 46 2d 36 30 36 37 2d 34 42 31 37 2d 38 43 36 46 2d 32 44 34 36 34 45 36 35 43 35 33 35) | (41 00 32 00 43 00 39 00 34 00 38 00 38 00 46 00 2d 00 36 00 30 00 36 00 37 00 2d 00 34 00 42 00 31 00 37 00 2d 00 38 00 43 00 36 00 46 00 2d 00 32 00 44 00 34 00 36 00 34 00 45 00 36 00 35 00 43 00 35 00 33 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpBox : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/P1CKLES/SharpBox"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "fda1a67f-d746-5ddb-a33f-97d608b13bc9"

	strings:
		$typelibguid0lo = {((36 31 36 63 31 61 66 62 2d 32 39 34 34 2d 34 32 65 64 2d 39 39 35 31 2d 62 66 34 33 35 63 61 64 62 36 30 30) | (36 00 31 00 36 00 63 00 31 00 61 00 66 00 62 00 2d 00 32 00 39 00 34 00 34 00 2d 00 34 00 32 00 65 00 64 00 2d 00 39 00 39 00 35 00 31 00 2d 00 62 00 66 00 34 00 33 00 35 00 63 00 61 00 64 00 62 00 36 00 30 00 30 00))}
		$typelibguid0up = {((36 31 36 43 31 41 46 42 2d 32 39 34 34 2d 34 32 45 44 2d 39 39 35 31 2d 42 46 34 33 35 43 41 44 42 36 30 30) | (36 00 31 00 36 00 43 00 31 00 41 00 46 00 42 00 2d 00 32 00 39 00 34 00 34 00 2d 00 34 00 32 00 45 00 44 00 2d 00 39 00 39 00 35 00 31 00 2d 00 42 00 46 00 34 00 33 00 35 00 43 00 41 00 44 00 42 00 36 00 30 00 30 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_rundotnetdll32 : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xbadjuju/rundotnetdll32"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "266c8add-d2ca-5e46-8594-5d190447d133"

	strings:
		$typelibguid0lo = {((61 37 36 36 64 62 32 38 2d 39 34 62 36 2d 34 65 64 31 2d 61 65 66 39 2d 35 32 30 30 62 62 64 64 38 63 61 37) | (61 00 37 00 36 00 36 00 64 00 62 00 32 00 38 00 2d 00 39 00 34 00 62 00 36 00 2d 00 34 00 65 00 64 00 31 00 2d 00 61 00 65 00 66 00 39 00 2d 00 35 00 32 00 30 00 30 00 62 00 62 00 64 00 64 00 38 00 63 00 61 00 37 00))}
		$typelibguid0up = {((41 37 36 36 44 42 32 38 2d 39 34 42 36 2d 34 45 44 31 2d 41 45 46 39 2d 35 32 30 30 42 42 44 44 38 43 41 37) | (41 00 37 00 36 00 36 00 44 00 42 00 32 00 38 00 2d 00 39 00 34 00 42 00 36 00 2d 00 34 00 45 00 44 00 31 00 2d 00 41 00 45 00 46 00 39 00 2d 00 35 00 32 00 30 00 30 00 42 00 42 00 44 00 44 00 38 00 43 00 41 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_AntiDebug : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/malcomvetter/AntiDebug"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "f381081b-d0cb-593d-ad3d-28816f770b67"

	strings:
		$typelibguid0lo = {((39 39 37 32 36 35 63 31 2d 31 33 34 32 2d 34 64 34 34 2d 61 64 65 64 2d 36 37 39 36 34 61 33 32 66 38 35 39) | (39 00 39 00 37 00 32 00 36 00 35 00 63 00 31 00 2d 00 31 00 33 00 34 00 32 00 2d 00 34 00 64 00 34 00 34 00 2d 00 61 00 64 00 65 00 64 00 2d 00 36 00 37 00 39 00 36 00 34 00 61 00 33 00 32 00 66 00 38 00 35 00 39 00))}
		$typelibguid0up = {((39 39 37 32 36 35 43 31 2d 31 33 34 32 2d 34 44 34 34 2d 41 44 45 44 2d 36 37 39 36 34 41 33 32 46 38 35 39) | (39 00 39 00 37 00 32 00 36 00 35 00 43 00 31 00 2d 00 31 00 33 00 34 00 32 00 2d 00 34 00 44 00 34 00 34 00 2d 00 41 00 44 00 45 00 44 00 2d 00 36 00 37 00 39 00 36 00 34 00 41 00 33 00 32 00 46 00 38 00 35 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_DInvisibleRegistry : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NVISO-BE/DInvisibleRegistry"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "98409bbe-6346-5825-b7f7-c1afeac2b038"

	strings:
		$typelibguid0lo = {((33 31 64 35 37 36 66 62 2d 39 66 62 39 2d 34 35 35 65 2d 61 62 30 32 2d 63 37 38 39 38 31 36 33 34 63 36 35) | (33 00 31 00 64 00 35 00 37 00 36 00 66 00 62 00 2d 00 39 00 66 00 62 00 39 00 2d 00 34 00 35 00 35 00 65 00 2d 00 61 00 62 00 30 00 32 00 2d 00 63 00 37 00 38 00 39 00 38 00 31 00 36 00 33 00 34 00 63 00 36 00 35 00))}
		$typelibguid0up = {((33 31 44 35 37 36 46 42 2d 39 46 42 39 2d 34 35 35 45 2d 41 42 30 32 2d 43 37 38 39 38 31 36 33 34 43 36 35) | (33 00 31 00 44 00 35 00 37 00 36 00 46 00 42 00 2d 00 39 00 46 00 42 00 39 00 2d 00 34 00 35 00 35 00 45 00 2d 00 41 00 42 00 30 00 32 00 2d 00 43 00 37 00 38 00 39 00 38 00 31 00 36 00 33 00 34 00 43 00 36 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_TikiTorch : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rasta-mouse/TikiTorch"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "354ee690-a0d0-5cc5-a73b-53b916ed0169"

	strings:
		$typelibguid0lo = {((38 30 36 63 36 63 37 32 2d 34 61 64 63 2d 34 33 64 39 2d 62 30 32 38 2d 36 38 37 32 66 61 34 38 64 33 33 34) | (38 00 30 00 36 00 63 00 36 00 63 00 37 00 32 00 2d 00 34 00 61 00 64 00 63 00 2d 00 34 00 33 00 64 00 39 00 2d 00 62 00 30 00 32 00 38 00 2d 00 36 00 38 00 37 00 32 00 66 00 61 00 34 00 38 00 64 00 33 00 33 00 34 00))}
		$typelibguid0up = {((38 30 36 43 36 43 37 32 2d 34 41 44 43 2d 34 33 44 39 2d 42 30 32 38 2d 36 38 37 32 46 41 34 38 44 33 33 34) | (38 00 30 00 36 00 43 00 36 00 43 00 37 00 32 00 2d 00 34 00 41 00 44 00 43 00 2d 00 34 00 33 00 44 00 39 00 2d 00 42 00 30 00 32 00 38 00 2d 00 36 00 38 00 37 00 32 00 46 00 41 00 34 00 38 00 44 00 33 00 33 00 34 00))}
		$typelibguid1lo = {((32 65 66 39 64 38 66 37 2d 36 62 37 37 2d 34 62 37 35 2d 38 32 32 62 2d 36 61 35 33 61 39 32 32 63 33 30 66) | (32 00 65 00 66 00 39 00 64 00 38 00 66 00 37 00 2d 00 36 00 62 00 37 00 37 00 2d 00 34 00 62 00 37 00 35 00 2d 00 38 00 32 00 32 00 62 00 2d 00 36 00 61 00 35 00 33 00 61 00 39 00 32 00 32 00 63 00 33 00 30 00 66 00))}
		$typelibguid1up = {((32 45 46 39 44 38 46 37 2d 36 42 37 37 2d 34 42 37 35 2d 38 32 32 42 2d 36 41 35 33 41 39 32 32 43 33 30 46) | (32 00 45 00 46 00 39 00 44 00 38 00 46 00 37 00 2d 00 36 00 42 00 37 00 37 00 2d 00 34 00 42 00 37 00 35 00 2d 00 38 00 32 00 32 00 42 00 2d 00 36 00 41 00 35 00 33 00 41 00 39 00 32 00 32 00 43 00 33 00 30 00 46 00))}
		$typelibguid2lo = {((38 66 35 66 33 61 39 35 2d 66 30 35 63 2d 34 64 63 65 2d 38 62 63 33 2d 64 30 61 30 64 34 31 35 33 64 62 36) | (38 00 66 00 35 00 66 00 33 00 61 00 39 00 35 00 2d 00 66 00 30 00 35 00 63 00 2d 00 34 00 64 00 63 00 65 00 2d 00 38 00 62 00 63 00 33 00 2d 00 64 00 30 00 61 00 30 00 64 00 34 00 31 00 35 00 33 00 64 00 62 00 36 00))}
		$typelibguid2up = {((38 46 35 46 33 41 39 35 2d 46 30 35 43 2d 34 44 43 45 2d 38 42 43 33 2d 44 30 41 30 44 34 31 35 33 44 42 36) | (38 00 46 00 35 00 46 00 33 00 41 00 39 00 35 00 2d 00 46 00 30 00 35 00 43 00 2d 00 34 00 44 00 43 00 45 00 2d 00 38 00 42 00 43 00 33 00 2d 00 44 00 30 00 41 00 30 00 44 00 34 00 31 00 35 00 33 00 44 00 42 00 36 00))}
		$typelibguid3lo = {((31 66 37 30 37 34 30 35 2d 39 37 30 38 2d 34 61 33 34 2d 61 38 30 39 2d 32 63 36 32 62 38 34 64 34 66 30 61) | (31 00 66 00 37 00 30 00 37 00 34 00 30 00 35 00 2d 00 39 00 37 00 30 00 38 00 2d 00 34 00 61 00 33 00 34 00 2d 00 61 00 38 00 30 00 39 00 2d 00 32 00 63 00 36 00 32 00 62 00 38 00 34 00 64 00 34 00 66 00 30 00 61 00))}
		$typelibguid3up = {((31 46 37 30 37 34 30 35 2d 39 37 30 38 2d 34 41 33 34 2d 41 38 30 39 2d 32 43 36 32 42 38 34 44 34 46 30 41) | (31 00 46 00 37 00 30 00 37 00 34 00 30 00 35 00 2d 00 39 00 37 00 30 00 38 00 2d 00 34 00 41 00 33 00 34 00 2d 00 41 00 38 00 30 00 39 00 2d 00 32 00 43 00 36 00 32 00 42 00 38 00 34 00 44 00 34 00 46 00 30 00 41 00))}
		$typelibguid4lo = {((39 37 34 32 31 33 32 35 2d 62 36 64 38 2d 34 39 65 35 2d 61 64 66 30 2d 65 32 31 32 36 61 62 63 31 37 65 65) | (39 00 37 00 34 00 32 00 31 00 33 00 32 00 35 00 2d 00 62 00 36 00 64 00 38 00 2d 00 34 00 39 00 65 00 35 00 2d 00 61 00 64 00 66 00 30 00 2d 00 65 00 32 00 31 00 32 00 36 00 61 00 62 00 63 00 31 00 37 00 65 00 65 00))}
		$typelibguid4up = {((39 37 34 32 31 33 32 35 2d 42 36 44 38 2d 34 39 45 35 2d 41 44 46 30 2d 45 32 31 32 36 41 42 43 31 37 45 45) | (39 00 37 00 34 00 32 00 31 00 33 00 32 00 35 00 2d 00 42 00 36 00 44 00 38 00 2d 00 34 00 39 00 45 00 35 00 2d 00 41 00 44 00 46 00 30 00 2d 00 45 00 32 00 31 00 32 00 36 00 41 00 42 00 43 00 31 00 37 00 45 00 45 00))}
		$typelibguid5lo = {((30 36 63 32 34 37 64 61 2d 65 32 65 31 2d 34 37 66 33 2d 62 63 33 63 2d 64 61 30 38 33 38 61 36 64 66 31 66) | (30 00 36 00 63 00 32 00 34 00 37 00 64 00 61 00 2d 00 65 00 32 00 65 00 31 00 2d 00 34 00 37 00 66 00 33 00 2d 00 62 00 63 00 33 00 63 00 2d 00 64 00 61 00 30 00 38 00 33 00 38 00 61 00 36 00 64 00 66 00 31 00 66 00))}
		$typelibguid5up = {((30 36 43 32 34 37 44 41 2d 45 32 45 31 2d 34 37 46 33 2d 42 43 33 43 2d 44 41 30 38 33 38 41 36 44 46 31 46) | (30 00 36 00 43 00 32 00 34 00 37 00 44 00 41 00 2d 00 45 00 32 00 45 00 31 00 2d 00 34 00 37 00 46 00 33 00 2d 00 42 00 43 00 33 00 43 00 2d 00 44 00 41 00 30 00 38 00 33 00 38 00 41 00 36 00 44 00 46 00 31 00 46 00))}
		$typelibguid6lo = {((66 63 37 30 30 61 63 36 2d 35 31 38 32 2d 34 32 31 66 2d 38 38 35 33 2d 30 61 64 31 38 63 64 62 65 62 33 39) | (66 00 63 00 37 00 30 00 30 00 61 00 63 00 36 00 2d 00 35 00 31 00 38 00 32 00 2d 00 34 00 32 00 31 00 66 00 2d 00 38 00 38 00 35 00 33 00 2d 00 30 00 61 00 64 00 31 00 38 00 63 00 64 00 62 00 65 00 62 00 33 00 39 00))}
		$typelibguid6up = {((46 43 37 30 30 41 43 36 2d 35 31 38 32 2d 34 32 31 46 2d 38 38 35 33 2d 30 41 44 31 38 43 44 42 45 42 33 39) | (46 00 43 00 37 00 30 00 30 00 41 00 43 00 36 00 2d 00 35 00 31 00 38 00 32 00 2d 00 34 00 32 00 31 00 46 00 2d 00 38 00 38 00 35 00 33 00 2d 00 30 00 41 00 44 00 31 00 38 00 43 00 44 00 42 00 45 00 42 00 33 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_HiveJack : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Viralmaniar/HiveJack"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "10567ef4-780f-5e93-9061-3214116d6bbb"

	strings:
		$typelibguid0lo = {((65 31 32 65 36 32 66 65 2d 62 65 61 33 2d 34 39 38 39 2d 62 66 30 34 2d 36 66 37 36 30 32 38 36 32 33 65 33) | (65 00 31 00 32 00 65 00 36 00 32 00 66 00 65 00 2d 00 62 00 65 00 61 00 33 00 2d 00 34 00 39 00 38 00 39 00 2d 00 62 00 66 00 30 00 34 00 2d 00 36 00 66 00 37 00 36 00 30 00 32 00 38 00 36 00 32 00 33 00 65 00 33 00))}
		$typelibguid0up = {((45 31 32 45 36 32 46 45 2d 42 45 41 33 2d 34 39 38 39 2d 42 46 30 34 2d 36 46 37 36 30 32 38 36 32 33 45 33) | (45 00 31 00 32 00 45 00 36 00 32 00 46 00 45 00 2d 00 42 00 45 00 41 00 33 00 2d 00 34 00 39 00 38 00 39 00 2d 00 42 00 46 00 30 00 34 00 2d 00 36 00 46 00 37 00 36 00 30 00 32 00 38 00 36 00 32 00 33 00 45 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_DecryptAutoLogon : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/securesean/DecryptAutoLogon"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "3ef58da9-16c1-54cf-9d06-a05680548cf5"

	strings:
		$typelibguid0lo = {((30 31 35 61 33 37 66 63 2d 35 33 64 30 2d 34 39 39 62 2d 62 66 66 65 2d 61 62 38 38 63 35 30 38 36 30 34 30) | (30 00 31 00 35 00 61 00 33 00 37 00 66 00 63 00 2d 00 35 00 33 00 64 00 30 00 2d 00 34 00 39 00 39 00 62 00 2d 00 62 00 66 00 66 00 65 00 2d 00 61 00 62 00 38 00 38 00 63 00 35 00 30 00 38 00 36 00 30 00 34 00 30 00))}
		$typelibguid0up = {((30 31 35 41 33 37 46 43 2d 35 33 44 30 2d 34 39 39 42 2d 42 46 46 45 2d 41 42 38 38 43 35 30 38 36 30 34 30) | (30 00 31 00 35 00 41 00 33 00 37 00 46 00 43 00 2d 00 35 00 33 00 44 00 30 00 2d 00 34 00 39 00 39 00 42 00 2d 00 42 00 46 00 46 00 45 00 2d 00 41 00 42 00 38 00 38 00 43 00 35 00 30 00 38 00 36 00 30 00 34 00 30 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_UnstoppableService : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/malcomvetter/UnstoppableService"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "8c65fbee-d779-57a8-851b-7583be66c67a"

	strings:
		$typelibguid0lo = {((30 63 31 31 37 65 65 35 2d 32 61 32 31 2d 64 65 61 64 2d 62 65 65 66 2d 38 63 63 37 66 30 63 61 61 61 38 36) | (30 00 63 00 31 00 31 00 37 00 65 00 65 00 35 00 2d 00 32 00 61 00 32 00 31 00 2d 00 64 00 65 00 61 00 64 00 2d 00 62 00 65 00 65 00 66 00 2d 00 38 00 63 00 63 00 37 00 66 00 30 00 63 00 61 00 61 00 61 00 38 00 36 00))}
		$typelibguid0up = {((30 43 31 31 37 45 45 35 2d 32 41 32 31 2d 44 45 41 44 2d 42 45 45 46 2d 38 43 43 37 46 30 43 41 41 41 38 36) | (30 00 43 00 31 00 31 00 37 00 45 00 45 00 35 00 2d 00 32 00 41 00 32 00 31 00 2d 00 44 00 45 00 41 00 44 00 2d 00 42 00 45 00 45 00 46 00 2d 00 38 00 43 00 43 00 37 00 46 00 30 00 43 00 41 00 41 00 41 00 38 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpWMI_2 : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/SharpWMI"
		old_rule_name = "HKTL_NET_GUID_SharpWMI"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "e6ab2f5e-2a5a-5be9-9b66-96cb745fd199"

	strings:
		$typelibguid0lo = {((36 64 64 32 32 38 38 30 2d 64 61 63 35 2d 34 62 34 64 2d 39 63 39 31 2d 38 63 33 35 63 63 37 62 38 31 38 30) | (36 00 64 00 64 00 32 00 32 00 38 00 38 00 30 00 2d 00 64 00 61 00 63 00 35 00 2d 00 34 00 62 00 34 00 64 00 2d 00 39 00 63 00 39 00 31 00 2d 00 38 00 63 00 33 00 35 00 63 00 63 00 37 00 62 00 38 00 31 00 38 00 30 00))}
		$typelibguid0up = {((36 44 44 32 32 38 38 30 2d 44 41 43 35 2d 34 42 34 44 2d 39 43 39 31 2d 38 43 33 35 43 43 37 42 38 31 38 30) | (36 00 44 00 44 00 32 00 32 00 38 00 38 00 30 00 2d 00 44 00 41 00 43 00 35 00 2d 00 34 00 42 00 34 00 44 00 2d 00 39 00 43 00 39 00 31 00 2d 00 38 00 43 00 33 00 35 00 43 00 43 00 37 00 42 00 38 00 31 00 38 00 30 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_EWSToolkit : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rasta-mouse/EWSToolkit"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "acde7744-d17f-5e47-a5e2-ff4f4c4d8093"

	strings:
		$typelibguid0lo = {((63 61 35 33 36 64 36 37 2d 35 33 63 39 2d 34 33 62 35 2d 38 62 63 38 2d 39 61 30 35 66 64 63 35 36 37 65 64) | (63 00 61 00 35 00 33 00 36 00 64 00 36 00 37 00 2d 00 35 00 33 00 63 00 39 00 2d 00 34 00 33 00 62 00 35 00 2d 00 38 00 62 00 63 00 38 00 2d 00 39 00 61 00 30 00 35 00 66 00 64 00 63 00 35 00 36 00 37 00 65 00 64 00))}
		$typelibguid0up = {((43 41 35 33 36 44 36 37 2d 35 33 43 39 2d 34 33 42 35 2d 38 42 43 38 2d 39 41 30 35 46 44 43 35 36 37 45 44) | (43 00 41 00 35 00 33 00 36 00 44 00 36 00 37 00 2d 00 35 00 33 00 43 00 39 00 2d 00 34 00 33 00 42 00 35 00 2d 00 38 00 42 00 43 00 38 00 2d 00 39 00 41 00 30 00 35 00 46 00 44 00 43 00 35 00 36 00 37 00 45 00 44 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SweetPotato : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/CCob/SweetPotato"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "0e347d94-51eb-5589-93d8-b19fec7f2365"

	strings:
		$typelibguid0lo = {((36 61 65 62 35 30 30 34 2d 36 30 39 33 2d 34 63 32 33 2d 61 65 61 65 2d 39 31 31 64 36 34 63 61 63 63 35 38) | (36 00 61 00 65 00 62 00 35 00 30 00 30 00 34 00 2d 00 36 00 30 00 39 00 33 00 2d 00 34 00 63 00 32 00 33 00 2d 00 61 00 65 00 61 00 65 00 2d 00 39 00 31 00 31 00 64 00 36 00 34 00 63 00 61 00 63 00 63 00 35 00 38 00))}
		$typelibguid0up = {((36 41 45 42 35 30 30 34 2d 36 30 39 33 2d 34 43 32 33 2d 41 45 41 45 2d 39 31 31 44 36 34 43 41 43 43 35 38) | (36 00 41 00 45 00 42 00 35 00 30 00 30 00 34 00 2d 00 36 00 30 00 39 00 33 00 2d 00 34 00 43 00 32 00 33 00 2d 00 41 00 45 00 41 00 45 00 2d 00 39 00 31 00 31 00 44 00 36 00 34 00 43 00 41 00 43 00 43 00 35 00 38 00))}
		$typelibguid1lo = {((31 62 66 39 63 31 30 66 2d 36 66 38 39 2d 34 35 32 30 2d 39 64 32 65 2d 61 61 66 31 37 64 31 37 62 61 35 65) | (31 00 62 00 66 00 39 00 63 00 31 00 30 00 66 00 2d 00 36 00 66 00 38 00 39 00 2d 00 34 00 35 00 32 00 30 00 2d 00 39 00 64 00 32 00 65 00 2d 00 61 00 61 00 66 00 31 00 37 00 64 00 31 00 37 00 62 00 61 00 35 00 65 00))}
		$typelibguid1up = {((31 42 46 39 43 31 30 46 2d 36 46 38 39 2d 34 35 32 30 2d 39 44 32 45 2d 41 41 46 31 37 44 31 37 42 41 35 45) | (31 00 42 00 46 00 39 00 43 00 31 00 30 00 46 00 2d 00 36 00 46 00 38 00 39 00 2d 00 34 00 35 00 32 00 30 00 2d 00 39 00 44 00 32 00 45 00 2d 00 41 00 41 00 46 00 31 00 37 00 44 00 31 00 37 00 42 00 41 00 35 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_memscan : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/nccgroup/memscan"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "35175fe1-a583-50d1-8b0c-71f19b898817"

	strings:
		$typelibguid0lo = {((37 39 34 36 32 66 38 37 2d 38 34 31 38 2d 34 38 33 34 2d 39 33 35 36 2d 38 63 31 31 65 34 34 63 65 31 38 39) | (37 00 39 00 34 00 36 00 32 00 66 00 38 00 37 00 2d 00 38 00 34 00 31 00 38 00 2d 00 34 00 38 00 33 00 34 00 2d 00 39 00 33 00 35 00 36 00 2d 00 38 00 63 00 31 00 31 00 65 00 34 00 34 00 63 00 65 00 31 00 38 00 39 00))}
		$typelibguid0up = {((37 39 34 36 32 46 38 37 2d 38 34 31 38 2d 34 38 33 34 2d 39 33 35 36 2d 38 43 31 31 45 34 34 43 45 31 38 39) | (37 00 39 00 34 00 36 00 32 00 46 00 38 00 37 00 2d 00 38 00 34 00 31 00 38 00 2d 00 34 00 38 00 33 00 34 00 2d 00 39 00 33 00 35 00 36 00 2d 00 38 00 43 00 31 00 31 00 45 00 34 00 34 00 43 00 45 00 31 00 38 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpStay : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xthirteen/SharpStay"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "e5bde5a9-8e09-59ce-ad01-e29836813cf8"

	strings:
		$typelibguid0lo = {((32 39 36 33 63 39 35 34 2d 37 62 31 65 2d 34 37 66 35 2d 62 34 66 61 2d 32 66 63 31 66 30 64 35 36 61 65 61) | (32 00 39 00 36 00 33 00 63 00 39 00 35 00 34 00 2d 00 37 00 62 00 31 00 65 00 2d 00 34 00 37 00 66 00 35 00 2d 00 62 00 34 00 66 00 61 00 2d 00 32 00 66 00 63 00 31 00 66 00 30 00 64 00 35 00 36 00 61 00 65 00 61 00))}
		$typelibguid0up = {((32 39 36 33 43 39 35 34 2d 37 42 31 45 2d 34 37 46 35 2d 42 34 46 41 2d 32 46 43 31 46 30 44 35 36 41 45 41) | (32 00 39 00 36 00 33 00 43 00 39 00 35 00 34 00 2d 00 37 00 42 00 31 00 45 00 2d 00 34 00 37 00 46 00 35 00 2d 00 42 00 34 00 46 00 41 00 2d 00 32 00 46 00 43 00 31 00 46 00 30 00 44 00 35 00 36 00 41 00 45 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpLocker : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Pickfordmatt/SharpLocker"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "9525422a-d670-5475-abdc-b7ecd1ab9943"

	strings:
		$typelibguid0lo = {((61 36 66 38 35 30 30 66 2d 36 38 62 63 2d 34 65 66 63 2d 39 36 32 61 2d 36 63 36 65 36 38 64 38 39 33 61 66) | (61 00 36 00 66 00 38 00 35 00 30 00 30 00 66 00 2d 00 36 00 38 00 62 00 63 00 2d 00 34 00 65 00 66 00 63 00 2d 00 39 00 36 00 32 00 61 00 2d 00 36 00 63 00 36 00 65 00 36 00 38 00 64 00 38 00 39 00 33 00 61 00 66 00))}
		$typelibguid0up = {((41 36 46 38 35 30 30 46 2d 36 38 42 43 2d 34 45 46 43 2d 39 36 32 41 2d 36 43 36 45 36 38 44 38 39 33 41 46) | (41 00 36 00 46 00 38 00 35 00 30 00 30 00 46 00 2d 00 36 00 38 00 42 00 43 00 2d 00 34 00 45 00 46 00 43 00 2d 00 39 00 36 00 32 00 41 00 2d 00 36 00 43 00 36 00 45 00 36 00 38 00 44 00 38 00 39 00 33 00 41 00 46 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SauronEye : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/vivami/SauronEye"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "3b624dde-a63e-58ac-a4db-af931f1d8553"

	strings:
		$typelibguid0lo = {((30 66 34 33 30 34 33 64 2d 38 39 35 37 2d 34 61 64 65 2d 61 30 66 34 2d 32 35 63 31 31 32 32 65 38 31 31 38) | (30 00 66 00 34 00 33 00 30 00 34 00 33 00 64 00 2d 00 38 00 39 00 35 00 37 00 2d 00 34 00 61 00 64 00 65 00 2d 00 61 00 30 00 66 00 34 00 2d 00 32 00 35 00 63 00 31 00 31 00 32 00 32 00 65 00 38 00 31 00 31 00 38 00))}
		$typelibguid0up = {((30 46 34 33 30 34 33 44 2d 38 39 35 37 2d 34 41 44 45 2d 41 30 46 34 2d 32 35 43 31 31 32 32 45 38 31 31 38) | (30 00 46 00 34 00 33 00 30 00 34 00 33 00 44 00 2d 00 38 00 39 00 35 00 37 00 2d 00 34 00 41 00 44 00 45 00 2d 00 41 00 30 00 46 00 34 00 2d 00 32 00 35 00 43 00 31 00 31 00 32 00 32 00 45 00 38 00 31 00 31 00 38 00))}
		$typelibguid1lo = {((30 38 36 62 66 30 63 61 2d 66 31 65 34 2d 34 65 38 66 2d 39 30 34 30 2d 61 38 63 33 37 61 34 39 66 61 32 36) | (30 00 38 00 36 00 62 00 66 00 30 00 63 00 61 00 2d 00 66 00 31 00 65 00 34 00 2d 00 34 00 65 00 38 00 66 00 2d 00 39 00 30 00 34 00 30 00 2d 00 61 00 38 00 63 00 33 00 37 00 61 00 34 00 39 00 66 00 61 00 32 00 36 00))}
		$typelibguid1up = {((30 38 36 42 46 30 43 41 2d 46 31 45 34 2d 34 45 38 46 2d 39 30 34 30 2d 41 38 43 33 37 41 34 39 46 41 32 36) | (30 00 38 00 36 00 42 00 46 00 30 00 43 00 41 00 2d 00 46 00 31 00 45 00 34 00 2d 00 34 00 45 00 38 00 46 00 2d 00 39 00 30 00 34 00 30 00 2d 00 41 00 38 00 43 00 33 00 37 00 41 00 34 00 39 00 46 00 41 00 32 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_sitrep : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mdsecactivebreach/sitrep"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "5f2ac63e-4be1-520c-82b1-1957027a63e2"

	strings:
		$typelibguid0lo = {((31 32 39 36 33 34 39 37 2d 39 38 38 66 2d 34 36 63 30 2d 39 32 31 32 2d 32 38 62 34 62 32 62 31 38 33 31 62) | (31 00 32 00 39 00 36 00 33 00 34 00 39 00 37 00 2d 00 39 00 38 00 38 00 66 00 2d 00 34 00 36 00 63 00 30 00 2d 00 39 00 32 00 31 00 32 00 2d 00 32 00 38 00 62 00 34 00 62 00 32 00 62 00 31 00 38 00 33 00 31 00 62 00))}
		$typelibguid0up = {((31 32 39 36 33 34 39 37 2d 39 38 38 46 2d 34 36 43 30 2d 39 32 31 32 2d 32 38 42 34 42 32 42 31 38 33 31 42) | (31 00 32 00 39 00 36 00 33 00 34 00 39 00 37 00 2d 00 39 00 38 00 38 00 46 00 2d 00 34 00 36 00 43 00 30 00 2d 00 39 00 32 00 31 00 32 00 2d 00 32 00 38 00 42 00 34 00 42 00 32 00 42 00 31 00 38 00 33 00 31 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpClipboard : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/slyd0g/SharpClipboard"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "fd1b7786-8853-5858-ab03-da350e44f738"

	strings:
		$typelibguid0lo = {((39 37 34 38 34 32 31 31 2d 34 37 32 36 2d 34 31 32 39 2d 38 36 61 61 2d 61 65 30 31 64 31 37 36 39 30 62 65) | (39 00 37 00 34 00 38 00 34 00 32 00 31 00 31 00 2d 00 34 00 37 00 32 00 36 00 2d 00 34 00 31 00 32 00 39 00 2d 00 38 00 36 00 61 00 61 00 2d 00 61 00 65 00 30 00 31 00 64 00 31 00 37 00 36 00 39 00 30 00 62 00 65 00))}
		$typelibguid0up = {((39 37 34 38 34 32 31 31 2d 34 37 32 36 2d 34 31 32 39 2d 38 36 41 41 2d 41 45 30 31 44 31 37 36 39 30 42 45) | (39 00 37 00 34 00 38 00 34 00 32 00 31 00 31 00 2d 00 34 00 37 00 32 00 36 00 2d 00 34 00 31 00 32 00 39 00 2d 00 38 00 36 00 41 00 41 00 2d 00 41 00 45 00 30 00 31 00 44 00 31 00 37 00 36 00 39 00 30 00 42 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpCookieMonster : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/m0rv4i/SharpCookieMonster"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "87be6949-f4f5-5a5a-b804-c627ed0f4355"

	strings:
		$typelibguid0lo = {((35 36 36 63 35 35 35 36 2d 31 32 30 34 2d 34 64 62 39 2d 39 64 63 38 2d 61 32 34 30 39 31 62 61 61 61 38 65) | (35 00 36 00 36 00 63 00 35 00 35 00 35 00 36 00 2d 00 31 00 32 00 30 00 34 00 2d 00 34 00 64 00 62 00 39 00 2d 00 39 00 64 00 63 00 38 00 2d 00 61 00 32 00 34 00 30 00 39 00 31 00 62 00 61 00 61 00 61 00 38 00 65 00))}
		$typelibguid0up = {((35 36 36 43 35 35 35 36 2d 31 32 30 34 2d 34 44 42 39 2d 39 44 43 38 2d 41 32 34 30 39 31 42 41 41 41 38 45) | (35 00 36 00 36 00 43 00 35 00 35 00 35 00 36 00 2d 00 31 00 32 00 30 00 34 00 2d 00 34 00 44 00 42 00 39 00 2d 00 39 00 44 00 43 00 38 00 2d 00 41 00 32 00 34 00 30 00 39 00 31 00 42 00 41 00 41 00 41 00 38 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_p0wnedShell : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "390b94d1-dda9-5a85-80ae-c79a3f7b0b9d"

	strings:
		$typelibguid0lo = {((32 65 39 62 31 34 36 32 2d 66 34 37 63 2d 34 38 63 61 2d 39 64 38 35 2d 30 30 34 34 39 33 38 39 32 33 38 31) | (32 00 65 00 39 00 62 00 31 00 34 00 36 00 32 00 2d 00 66 00 34 00 37 00 63 00 2d 00 34 00 38 00 63 00 61 00 2d 00 39 00 64 00 38 00 35 00 2d 00 30 00 30 00 34 00 34 00 39 00 33 00 38 00 39 00 32 00 33 00 38 00 31 00))}
		$typelibguid0up = {((32 45 39 42 31 34 36 32 2d 46 34 37 43 2d 34 38 43 41 2d 39 44 38 35 2d 30 30 34 34 39 33 38 39 32 33 38 31) | (32 00 45 00 39 00 42 00 31 00 34 00 36 00 32 00 2d 00 46 00 34 00 37 00 43 00 2d 00 34 00 38 00 43 00 41 00 2d 00 39 00 44 00 38 00 35 00 2d 00 30 00 30 00 34 00 34 00 39 00 33 00 38 00 39 00 32 00 33 00 38 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpMove : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xthirteen/SharpMove"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "e52392f9-614c-596e-8efd-aa0a2fa44e60"

	strings:
		$typelibguid0lo = {((38 62 66 38 32 62 62 65 2d 39 30 39 63 2d 34 37 37 37 2d 61 32 66 63 2d 65 61 37 63 30 37 30 66 66 34 33 65) | (38 00 62 00 66 00 38 00 32 00 62 00 62 00 65 00 2d 00 39 00 30 00 39 00 63 00 2d 00 34 00 37 00 37 00 37 00 2d 00 61 00 32 00 66 00 63 00 2d 00 65 00 61 00 37 00 63 00 30 00 37 00 30 00 66 00 66 00 34 00 33 00 65 00))}
		$typelibguid0up = {((38 42 46 38 32 42 42 45 2d 39 30 39 43 2d 34 37 37 37 2d 41 32 46 43 2d 45 41 37 43 30 37 30 46 46 34 33 45) | (38 00 42 00 46 00 38 00 32 00 42 00 42 00 45 00 2d 00 39 00 30 00 39 00 43 00 2d 00 34 00 37 00 37 00 37 00 2d 00 41 00 32 00 46 00 43 00 2d 00 45 00 41 00 37 00 43 00 30 00 37 00 30 00 46 00 46 00 34 00 33 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_C_Sharp_R_A_T_Client : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/AdvancedHacker101/C-Sharp-R.A.T-Client"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "f5df8257-d202-58e3-9c4a-1dfc9dd52f2a"

	strings:
		$typelibguid0lo = {((36 64 39 65 38 38 35 32 2d 65 38 36 63 2d 34 65 33 36 2d 39 63 62 34 2d 62 33 63 33 38 35 33 65 64 36 62 38) | (36 00 64 00 39 00 65 00 38 00 38 00 35 00 32 00 2d 00 65 00 38 00 36 00 63 00 2d 00 34 00 65 00 33 00 36 00 2d 00 39 00 63 00 62 00 34 00 2d 00 62 00 33 00 63 00 33 00 38 00 35 00 33 00 65 00 64 00 36 00 62 00 38 00))}
		$typelibguid0up = {((36 44 39 45 38 38 35 32 2d 45 38 36 43 2d 34 45 33 36 2d 39 43 42 34 2d 42 33 43 33 38 35 33 45 44 36 42 38) | (36 00 44 00 39 00 45 00 38 00 38 00 35 00 32 00 2d 00 45 00 38 00 36 00 43 00 2d 00 34 00 45 00 33 00 36 00 2d 00 39 00 43 00 42 00 34 00 2d 00 42 00 33 00 43 00 33 00 38 00 35 00 33 00 45 00 44 00 36 00 42 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpPrinter : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rvrsh3ll/SharpPrinter"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "10270351-ad80-5330-971b-bc8f635f05f4"

	strings:
		$typelibguid0lo = {((34 31 62 32 64 31 65 35 2d 34 63 35 64 2d 34 34 34 63 2d 61 61 34 37 2d 36 32 39 39 35 35 34 30 31 65 64 39) | (34 00 31 00 62 00 32 00 64 00 31 00 65 00 35 00 2d 00 34 00 63 00 35 00 64 00 2d 00 34 00 34 00 34 00 63 00 2d 00 61 00 61 00 34 00 37 00 2d 00 36 00 32 00 39 00 39 00 35 00 35 00 34 00 30 00 31 00 65 00 64 00 39 00))}
		$typelibguid0up = {((34 31 42 32 44 31 45 35 2d 34 43 35 44 2d 34 34 34 43 2d 41 41 34 37 2d 36 32 39 39 35 35 34 30 31 45 44 39) | (34 00 31 00 42 00 32 00 44 00 31 00 45 00 35 00 2d 00 34 00 43 00 35 00 44 00 2d 00 34 00 34 00 34 00 43 00 2d 00 41 00 41 00 34 00 37 00 2d 00 36 00 32 00 39 00 39 00 35 00 35 00 34 00 30 00 31 00 45 00 44 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_EvilFOCA : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ElevenPaths/EvilFOCA"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "2b2f5f6f-4224-5013-9e85-0ac088826bea"

	strings:
		$typelibguid0lo = {((66 32 36 62 64 62 34 61 2d 35 38 34 36 2d 34 62 65 63 2d 38 66 35 32 2d 33 63 33 39 64 33 32 64 66 34 39 35) | (66 00 32 00 36 00 62 00 64 00 62 00 34 00 61 00 2d 00 35 00 38 00 34 00 36 00 2d 00 34 00 62 00 65 00 63 00 2d 00 38 00 66 00 35 00 32 00 2d 00 33 00 63 00 33 00 39 00 64 00 33 00 32 00 64 00 66 00 34 00 39 00 35 00))}
		$typelibguid0up = {((46 32 36 42 44 42 34 41 2d 35 38 34 36 2d 34 42 45 43 2d 38 46 35 32 2d 33 43 33 39 44 33 32 44 46 34 39 35) | (46 00 32 00 36 00 42 00 44 00 42 00 34 00 41 00 2d 00 35 00 38 00 34 00 36 00 2d 00 34 00 42 00 45 00 43 00 2d 00 38 00 46 00 35 00 32 00 2d 00 33 00 43 00 33 00 39 00 44 00 33 00 32 00 44 00 46 00 34 00 39 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_PoshC2_Misc : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/nettitude/PoshC2_Misc"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "245803cb-63d8-5c75-b672-912091cf4a80"

	strings:
		$typelibguid0lo = {((38 35 37 37 33 65 62 37 2d 62 31 35 39 2d 34 35 66 65 2d 39 36 63 64 2d 31 31 62 61 64 35 31 64 61 36 64 65) | (38 00 35 00 37 00 37 00 33 00 65 00 62 00 37 00 2d 00 62 00 31 00 35 00 39 00 2d 00 34 00 35 00 66 00 65 00 2d 00 39 00 36 00 63 00 64 00 2d 00 31 00 31 00 62 00 61 00 64 00 35 00 31 00 64 00 61 00 36 00 64 00 65 00))}
		$typelibguid0up = {((38 35 37 37 33 45 42 37 2d 42 31 35 39 2d 34 35 46 45 2d 39 36 43 44 2d 31 31 42 41 44 35 31 44 41 36 44 45) | (38 00 35 00 37 00 37 00 33 00 45 00 42 00 37 00 2d 00 42 00 31 00 35 00 39 00 2d 00 34 00 35 00 46 00 45 00 2d 00 39 00 36 00 43 00 44 00 2d 00 31 00 31 00 42 00 41 00 44 00 35 00 31 00 44 00 41 00 36 00 44 00 45 00))}
		$typelibguid1lo = {((39 64 33 32 61 64 35 39 2d 34 30 39 33 2d 34 32 30 64 2d 62 34 35 63 2d 35 66 66 66 33 39 31 65 39 39 30 64) | (39 00 64 00 33 00 32 00 61 00 64 00 35 00 39 00 2d 00 34 00 30 00 39 00 33 00 2d 00 34 00 32 00 30 00 64 00 2d 00 62 00 34 00 35 00 63 00 2d 00 35 00 66 00 66 00 66 00 33 00 39 00 31 00 65 00 39 00 39 00 30 00 64 00))}
		$typelibguid1up = {((39 44 33 32 41 44 35 39 2d 34 30 39 33 2d 34 32 30 44 2d 42 34 35 43 2d 35 46 46 46 33 39 31 45 39 39 30 44) | (39 00 44 00 33 00 32 00 41 00 44 00 35 00 39 00 2d 00 34 00 30 00 39 00 33 00 2d 00 34 00 32 00 30 00 44 00 2d 00 42 00 34 00 35 00 43 00 2d 00 35 00 46 00 46 00 46 00 33 00 39 00 31 00 45 00 39 00 39 00 30 00 44 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Sharpire : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xbadjuju/Sharpire"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "32bdaa0f-3afc-5e0e-a20f-e21f33909af7"

	strings:
		$typelibguid0lo = {((33 39 62 37 35 31 32 30 2d 30 37 66 65 2d 34 38 33 33 2d 61 30 32 65 2d 35 37 39 66 66 38 62 36 38 33 33 31) | (33 00 39 00 62 00 37 00 35 00 31 00 32 00 30 00 2d 00 30 00 37 00 66 00 65 00 2d 00 34 00 38 00 33 00 33 00 2d 00 61 00 30 00 32 00 65 00 2d 00 35 00 37 00 39 00 66 00 66 00 38 00 62 00 36 00 38 00 33 00 33 00 31 00))}
		$typelibguid0up = {((33 39 42 37 35 31 32 30 2d 30 37 46 45 2d 34 38 33 33 2d 41 30 32 45 2d 35 37 39 46 46 38 42 36 38 33 33 31) | (33 00 39 00 42 00 37 00 35 00 31 00 32 00 30 00 2d 00 30 00 37 00 46 00 45 00 2d 00 34 00 38 00 33 00 33 00 2d 00 41 00 30 00 32 00 45 00 2d 00 35 00 37 00 39 00 46 00 46 00 38 00 42 00 36 00 38 00 33 00 33 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Sharp_SMBExec : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/checkymander/Sharp-SMBExec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "6a1024af-734c-5974-af50-db51dbd694ff"

	strings:
		$typelibguid0lo = {((33 34 34 65 65 35 35 61 2d 34 65 33 32 2d 34 36 66 32 2d 61 30 30 33 2d 36 39 61 64 35 32 62 35 35 39 34 35) | (33 00 34 00 34 00 65 00 65 00 35 00 35 00 61 00 2d 00 34 00 65 00 33 00 32 00 2d 00 34 00 36 00 66 00 32 00 2d 00 61 00 30 00 30 00 33 00 2d 00 36 00 39 00 61 00 64 00 35 00 32 00 62 00 35 00 35 00 39 00 34 00 35 00))}
		$typelibguid0up = {((33 34 34 45 45 35 35 41 2d 34 45 33 32 2d 34 36 46 32 2d 41 30 30 33 2d 36 39 41 44 35 32 42 35 35 39 34 35) | (33 00 34 00 34 00 45 00 45 00 35 00 35 00 41 00 2d 00 34 00 45 00 33 00 32 00 2d 00 34 00 36 00 46 00 32 00 2d 00 41 00 30 00 30 00 33 00 2d 00 36 00 39 00 41 00 44 00 35 00 32 00 42 00 35 00 35 00 39 00 34 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_MiscTools : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rasta-mouse/MiscTools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "ce49cc7b-a5a5-52b7-a7bf-bbb0c5b29b8a"

	strings:
		$typelibguid0lo = {((33 38 34 65 39 36 34 37 2d 32 38 61 39 2d 34 38 33 35 2d 38 66 61 37 2d 32 34 37 32 62 31 61 63 65 64 63 30) | (33 00 38 00 34 00 65 00 39 00 36 00 34 00 37 00 2d 00 32 00 38 00 61 00 39 00 2d 00 34 00 38 00 33 00 35 00 2d 00 38 00 66 00 61 00 37 00 2d 00 32 00 34 00 37 00 32 00 62 00 31 00 61 00 63 00 65 00 64 00 63 00 30 00))}
		$typelibguid0up = {((33 38 34 45 39 36 34 37 2d 32 38 41 39 2d 34 38 33 35 2d 38 46 41 37 2d 32 34 37 32 42 31 41 43 45 44 43 30) | (33 00 38 00 34 00 45 00 39 00 36 00 34 00 37 00 2d 00 32 00 38 00 41 00 39 00 2d 00 34 00 38 00 33 00 35 00 2d 00 38 00 46 00 41 00 37 00 2d 00 32 00 34 00 37 00 32 00 42 00 31 00 41 00 43 00 45 00 44 00 43 00 30 00))}
		$typelibguid1lo = {((64 37 65 63 30 65 66 35 2d 31 35 37 63 2d 34 35 33 33 2d 62 62 63 64 2d 30 66 65 30 37 30 66 62 66 38 64 39) | (64 00 37 00 65 00 63 00 30 00 65 00 66 00 35 00 2d 00 31 00 35 00 37 00 63 00 2d 00 34 00 35 00 33 00 33 00 2d 00 62 00 62 00 63 00 64 00 2d 00 30 00 66 00 65 00 30 00 37 00 30 00 66 00 62 00 66 00 38 00 64 00 39 00))}
		$typelibguid1up = {((44 37 45 43 30 45 46 35 2d 31 35 37 43 2d 34 35 33 33 2d 42 42 43 44 2d 30 46 45 30 37 30 46 42 46 38 44 39) | (44 00 37 00 45 00 43 00 30 00 45 00 46 00 35 00 2d 00 31 00 35 00 37 00 43 00 2d 00 34 00 35 00 33 00 33 00 2d 00 42 00 42 00 43 00 44 00 2d 00 30 00 46 00 45 00 30 00 37 00 30 00 46 00 42 00 46 00 38 00 44 00 39 00))}
		$typelibguid2lo = {((31 30 30 38 35 64 39 38 2d 34 38 62 39 2d 34 32 61 38 2d 62 31 35 62 2d 63 62 32 37 61 32 34 33 37 36 31 62) | (31 00 30 00 30 00 38 00 35 00 64 00 39 00 38 00 2d 00 34 00 38 00 62 00 39 00 2d 00 34 00 32 00 61 00 38 00 2d 00 62 00 31 00 35 00 62 00 2d 00 63 00 62 00 32 00 37 00 61 00 32 00 34 00 33 00 37 00 36 00 31 00 62 00))}
		$typelibguid2up = {((31 30 30 38 35 44 39 38 2d 34 38 42 39 2d 34 32 41 38 2d 42 31 35 42 2d 43 42 32 37 41 32 34 33 37 36 31 42) | (31 00 30 00 30 00 38 00 35 00 44 00 39 00 38 00 2d 00 34 00 38 00 42 00 39 00 2d 00 34 00 32 00 41 00 38 00 2d 00 42 00 31 00 35 00 42 00 2d 00 43 00 42 00 32 00 37 00 41 00 32 00 34 00 33 00 37 00 36 00 31 00 42 00))}
		$typelibguid3lo = {((36 61 61 63 64 31 35 39 2d 66 34 65 37 2d 34 36 33 32 2d 62 61 64 31 2d 32 61 65 38 35 32 36 61 39 36 33 33) | (36 00 61 00 61 00 63 00 64 00 31 00 35 00 39 00 2d 00 66 00 34 00 65 00 37 00 2d 00 34 00 36 00 33 00 32 00 2d 00 62 00 61 00 64 00 31 00 2d 00 32 00 61 00 65 00 38 00 35 00 32 00 36 00 61 00 39 00 36 00 33 00 33 00))}
		$typelibguid3up = {((36 41 41 43 44 31 35 39 2d 46 34 45 37 2d 34 36 33 32 2d 42 41 44 31 2d 32 41 45 38 35 32 36 41 39 36 33 33) | (36 00 41 00 41 00 43 00 44 00 31 00 35 00 39 00 2d 00 46 00 34 00 45 00 37 00 2d 00 34 00 36 00 33 00 32 00 2d 00 42 00 41 00 44 00 31 00 2d 00 32 00 41 00 45 00 38 00 35 00 32 00 36 00 41 00 39 00 36 00 33 00 33 00))}
		$typelibguid4lo = {((34 39 61 36 37 31 39 65 2d 31 31 61 38 2d 34 36 65 36 2d 61 64 37 61 2d 31 64 62 31 62 65 39 66 65 61 33 37) | (34 00 39 00 61 00 36 00 37 00 31 00 39 00 65 00 2d 00 31 00 31 00 61 00 38 00 2d 00 34 00 36 00 65 00 36 00 2d 00 61 00 64 00 37 00 61 00 2d 00 31 00 64 00 62 00 31 00 62 00 65 00 39 00 66 00 65 00 61 00 33 00 37 00))}
		$typelibguid4up = {((34 39 41 36 37 31 39 45 2d 31 31 41 38 2d 34 36 45 36 2d 41 44 37 41 2d 31 44 42 31 42 45 39 46 45 41 33 37) | (34 00 39 00 41 00 36 00 37 00 31 00 39 00 45 00 2d 00 31 00 31 00 41 00 38 00 2d 00 34 00 36 00 45 00 36 00 2d 00 41 00 44 00 37 00 41 00 2d 00 31 00 44 00 42 00 31 00 42 00 45 00 39 00 46 00 45 00 41 00 33 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_MemoryMapper : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jasondrawdy/MemoryMapper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "c978be10-315c-54e7-afea-f97e9a5f2d18"

	strings:
		$typelibguid0lo = {((62 39 66 62 66 33 61 63 2d 30 35 64 38 2d 34 63 64 35 2d 39 36 39 34 2d 62 32 32 34 64 34 65 36 63 30 65 61) | (62 00 39 00 66 00 62 00 66 00 33 00 61 00 63 00 2d 00 30 00 35 00 64 00 38 00 2d 00 34 00 63 00 64 00 35 00 2d 00 39 00 36 00 39 00 34 00 2d 00 62 00 32 00 32 00 34 00 64 00 34 00 65 00 36 00 63 00 30 00 65 00 61 00))}
		$typelibguid0up = {((42 39 46 42 46 33 41 43 2d 30 35 44 38 2d 34 43 44 35 2d 39 36 39 34 2d 42 32 32 34 44 34 45 36 43 30 45 41) | (42 00 39 00 46 00 42 00 46 00 33 00 41 00 43 00 2d 00 30 00 35 00 44 00 38 00 2d 00 34 00 43 00 44 00 35 00 2d 00 39 00 36 00 39 00 34 00 2d 00 42 00 32 00 32 00 34 00 44 00 34 00 45 00 36 00 43 00 30 00 45 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_VanillaRAT : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/DannyTheSloth/VanillaRAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "9448e8d0-5bfc-5683-b633-284e43d24642"

	strings:
		$typelibguid0lo = {((64 30 66 32 65 65 36 37 2d 30 61 35 30 2d 34 32 33 64 2d 62 66 65 36 2d 38 34 35 64 61 38 39 32 61 32 64 62) | (64 00 30 00 66 00 32 00 65 00 65 00 36 00 37 00 2d 00 30 00 61 00 35 00 30 00 2d 00 34 00 32 00 33 00 64 00 2d 00 62 00 66 00 65 00 36 00 2d 00 38 00 34 00 35 00 64 00 61 00 38 00 39 00 32 00 61 00 32 00 64 00 62 00))}
		$typelibguid0up = {((44 30 46 32 45 45 36 37 2d 30 41 35 30 2d 34 32 33 44 2d 42 46 45 36 2d 38 34 35 44 41 38 39 32 41 32 44 42) | (44 00 30 00 46 00 32 00 45 00 45 00 36 00 37 00 2d 00 30 00 41 00 35 00 30 00 2d 00 34 00 32 00 33 00 44 00 2d 00 42 00 46 00 45 00 36 00 2d 00 38 00 34 00 35 00 44 00 41 00 38 00 39 00 32 00 41 00 32 00 44 00 42 00))}
		$typelibguid1lo = {((61 35 39 33 66 63 64 32 2d 63 38 61 62 2d 34 35 66 36 2d 39 61 65 62 2d 38 61 62 35 65 32 30 61 62 34 30 32) | (61 00 35 00 39 00 33 00 66 00 63 00 64 00 32 00 2d 00 63 00 38 00 61 00 62 00 2d 00 34 00 35 00 66 00 36 00 2d 00 39 00 61 00 65 00 62 00 2d 00 38 00 61 00 62 00 35 00 65 00 32 00 30 00 61 00 62 00 34 00 30 00 32 00))}
		$typelibguid1up = {((41 35 39 33 46 43 44 32 2d 43 38 41 42 2d 34 35 46 36 2d 39 41 45 42 2d 38 41 42 35 45 32 30 41 42 34 30 32) | (41 00 35 00 39 00 33 00 46 00 43 00 44 00 32 00 2d 00 43 00 38 00 41 00 42 00 2d 00 34 00 35 00 46 00 36 00 2d 00 39 00 41 00 45 00 42 00 2d 00 38 00 41 00 42 00 35 00 45 00 32 00 30 00 41 00 42 00 34 00 30 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_UnmanagedPowerShell : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/leechristensen/UnmanagedPowerShell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "49ff1362-0ac5-580d-97f3-516f2a10072b"

	strings:
		$typelibguid0lo = {((64 66 63 34 65 65 62 62 2d 37 33 38 34 2d 34 64 62 35 2d 39 62 61 64 2d 32 35 37 32 30 33 30 32 39 62 64 39) | (64 00 66 00 63 00 34 00 65 00 65 00 62 00 62 00 2d 00 37 00 33 00 38 00 34 00 2d 00 34 00 64 00 62 00 35 00 2d 00 39 00 62 00 61 00 64 00 2d 00 32 00 35 00 37 00 32 00 30 00 33 00 30 00 32 00 39 00 62 00 64 00 39 00))}
		$typelibguid0up = {((44 46 43 34 45 45 42 42 2d 37 33 38 34 2d 34 44 42 35 2d 39 42 41 44 2d 32 35 37 32 30 33 30 32 39 42 44 39) | (44 00 46 00 43 00 34 00 45 00 45 00 42 00 42 00 2d 00 37 00 33 00 38 00 34 00 2d 00 34 00 44 00 42 00 35 00 2d 00 39 00 42 00 41 00 44 00 2d 00 32 00 35 00 37 00 32 00 30 00 33 00 30 00 32 00 39 00 42 00 44 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Quasar : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/quasar/Quasar"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "b938cf7d-27fd-5fa2-b0e5-d4da5670f3ef"

	strings:
		$typelibguid0lo = {((63 66 64 61 36 64 32 65 2d 38 61 62 33 2d 34 33 34 39 2d 62 38 39 61 2d 33 33 65 31 66 30 64 61 62 33 32 62) | (63 00 66 00 64 00 61 00 36 00 64 00 32 00 65 00 2d 00 38 00 61 00 62 00 33 00 2d 00 34 00 33 00 34 00 39 00 2d 00 62 00 38 00 39 00 61 00 2d 00 33 00 33 00 65 00 31 00 66 00 30 00 64 00 61 00 62 00 33 00 32 00 62 00))}
		$typelibguid0up = {((43 46 44 41 36 44 32 45 2d 38 41 42 33 2d 34 33 34 39 2d 42 38 39 41 2d 33 33 45 31 46 30 44 41 42 33 32 42) | (43 00 46 00 44 00 41 00 36 00 44 00 32 00 45 00 2d 00 38 00 41 00 42 00 33 00 2d 00 34 00 33 00 34 00 39 00 2d 00 42 00 38 00 39 00 41 00 2d 00 33 00 33 00 45 00 31 00 46 00 30 00 44 00 41 00 42 00 33 00 32 00 42 00))}
		$typelibguid1lo = {((63 37 63 33 36 33 62 61 2d 65 35 62 36 2d 34 65 31 38 2d 39 32 32 34 2d 33 39 62 63 38 64 61 37 33 31 37 32) | (63 00 37 00 63 00 33 00 36 00 33 00 62 00 61 00 2d 00 65 00 35 00 62 00 36 00 2d 00 34 00 65 00 31 00 38 00 2d 00 39 00 32 00 32 00 34 00 2d 00 33 00 39 00 62 00 63 00 38 00 64 00 61 00 37 00 33 00 31 00 37 00 32 00))}
		$typelibguid1up = {((43 37 43 33 36 33 42 41 2d 45 35 42 36 2d 34 45 31 38 2d 39 32 32 34 2d 33 39 42 43 38 44 41 37 33 31 37 32) | (43 00 37 00 43 00 33 00 36 00 33 00 42 00 41 00 2d 00 45 00 35 00 42 00 36 00 2d 00 34 00 45 00 31 00 38 00 2d 00 39 00 32 00 32 00 34 00 2d 00 33 00 39 00 42 00 43 00 38 00 44 00 41 00 37 00 33 00 31 00 37 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpAdidnsdump : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/b4rtik/SharpAdidnsdump"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "51d50b22-4e73-5378-9e0d-ad7730987293"

	strings:
		$typelibguid0lo = {((63 64 62 30 32 62 63 32 2d 35 66 36 32 2d 34 63 38 61 2d 61 66 36 39 2d 61 63 63 33 61 62 38 32 65 37 34 31) | (63 00 64 00 62 00 30 00 32 00 62 00 63 00 32 00 2d 00 35 00 66 00 36 00 32 00 2d 00 34 00 63 00 38 00 61 00 2d 00 61 00 66 00 36 00 39 00 2d 00 61 00 63 00 63 00 33 00 61 00 62 00 38 00 32 00 65 00 37 00 34 00 31 00))}
		$typelibguid0up = {((43 44 42 30 32 42 43 32 2d 35 46 36 32 2d 34 43 38 41 2d 41 46 36 39 2d 41 43 43 33 41 42 38 32 45 37 34 31) | (43 00 44 00 42 00 30 00 32 00 42 00 43 00 32 00 2d 00 35 00 46 00 36 00 32 00 2d 00 34 00 43 00 38 00 41 00 2d 00 41 00 46 00 36 00 39 00 2d 00 41 00 43 00 43 00 33 00 41 00 42 00 38 00 32 00 45 00 37 00 34 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_DotNetToJScript : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tyranid/DotNetToJScript"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "31827074-fc63-5690-b6c7-8e89daacc07f"

	strings:
		$typelibguid0lo = {((37 65 33 66 32 33 31 63 2d 30 64 30 62 2d 34 30 32 35 2d 38 31 32 63 2d 30 65 66 30 39 39 34 30 34 38 36 31) | (37 00 65 00 33 00 66 00 32 00 33 00 31 00 63 00 2d 00 30 00 64 00 30 00 62 00 2d 00 34 00 30 00 32 00 35 00 2d 00 38 00 31 00 32 00 63 00 2d 00 30 00 65 00 66 00 30 00 39 00 39 00 34 00 30 00 34 00 38 00 36 00 31 00))}
		$typelibguid0up = {((37 45 33 46 32 33 31 43 2d 30 44 30 42 2d 34 30 32 35 2d 38 31 32 43 2d 30 45 46 30 39 39 34 30 34 38 36 31) | (37 00 45 00 33 00 46 00 32 00 33 00 31 00 43 00 2d 00 30 00 44 00 30 00 42 00 2d 00 34 00 30 00 32 00 35 00 2d 00 38 00 31 00 32 00 43 00 2d 00 30 00 45 00 46 00 30 00 39 00 39 00 34 00 30 00 34 00 38 00 36 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Inferno : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/LimerBoy/Inferno"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "af2d9832-c7f9-5879-a19b-a3c4d91b8b3f"

	strings:
		$typelibguid0lo = {((32 36 64 34 39 38 66 37 2d 33 37 61 65 2d 34 37 36 63 2d 39 37 62 30 2d 33 37 36 31 65 33 61 39 31 39 66 30) | (32 00 36 00 64 00 34 00 39 00 38 00 66 00 37 00 2d 00 33 00 37 00 61 00 65 00 2d 00 34 00 37 00 36 00 63 00 2d 00 39 00 37 00 62 00 30 00 2d 00 33 00 37 00 36 00 31 00 65 00 33 00 61 00 39 00 31 00 39 00 66 00 30 00))}
		$typelibguid0up = {((32 36 44 34 39 38 46 37 2d 33 37 41 45 2d 34 37 36 43 2d 39 37 42 30 2d 33 37 36 31 45 33 41 39 31 39 46 30) | (32 00 36 00 44 00 34 00 39 00 38 00 46 00 37 00 2d 00 33 00 37 00 41 00 45 00 2d 00 34 00 37 00 36 00 43 00 2d 00 39 00 37 00 42 00 30 00 2d 00 33 00 37 00 36 00 31 00 45 00 33 00 41 00 39 00 31 00 39 00 46 00 30 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpSearch : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/djhohnstein/SharpSearch"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "459d8a34-f311-5459-8257-e7aa519174b5"

	strings:
		$typelibguid0lo = {((39 38 66 65 65 37 34 32 2d 38 34 31 30 2d 34 66 32 30 2d 38 62 32 64 2d 64 37 64 37 38 39 61 62 30 30 33 64) | (39 00 38 00 66 00 65 00 65 00 37 00 34 00 32 00 2d 00 38 00 34 00 31 00 30 00 2d 00 34 00 66 00 32 00 30 00 2d 00 38 00 62 00 32 00 64 00 2d 00 64 00 37 00 64 00 37 00 38 00 39 00 61 00 62 00 30 00 30 00 33 00 64 00))}
		$typelibguid0up = {((39 38 46 45 45 37 34 32 2d 38 34 31 30 2d 34 46 32 30 2d 38 42 32 44 2d 44 37 44 37 38 39 41 42 30 30 33 44) | (39 00 38 00 46 00 45 00 45 00 37 00 34 00 32 00 2d 00 38 00 34 00 31 00 30 00 2d 00 34 00 46 00 32 00 30 00 2d 00 38 00 42 00 32 00 44 00 2d 00 44 00 37 00 44 00 37 00 38 00 39 00 41 00 42 00 30 00 30 00 33 00 44 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpSecDump : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/G0ldenGunSec/SharpSecDump"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "492dfb79-541a-589d-ac69-468e9b2ab9db"

	strings:
		$typelibguid0lo = {((65 32 66 64 64 36 63 63 2d 39 38 38 36 2d 34 35 36 63 2d 39 30 32 31 2d 65 65 32 63 34 37 63 66 36 37 62 37) | (65 00 32 00 66 00 64 00 64 00 36 00 63 00 63 00 2d 00 39 00 38 00 38 00 36 00 2d 00 34 00 35 00 36 00 63 00 2d 00 39 00 30 00 32 00 31 00 2d 00 65 00 65 00 32 00 63 00 34 00 37 00 63 00 66 00 36 00 37 00 62 00 37 00))}
		$typelibguid0up = {((45 32 46 44 44 36 43 43 2d 39 38 38 36 2d 34 35 36 43 2d 39 30 32 31 2d 45 45 32 43 34 37 43 46 36 37 42 37) | (45 00 32 00 46 00 44 00 44 00 36 00 43 00 43 00 2d 00 39 00 38 00 38 00 36 00 2d 00 34 00 35 00 36 00 43 00 2d 00 39 00 30 00 32 00 31 00 2d 00 45 00 45 00 32 00 43 00 34 00 37 00 43 00 46 00 36 00 37 00 42 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Net_GPPPassword : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/outflanknl/Net-GPPPassword"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "a718f9fc-acf5-536e-81d6-d393cebe8f77"

	strings:
		$typelibguid0lo = {((30 30 66 63 66 37 32 63 2d 64 31 34 38 2d 34 64 64 30 2d 39 63 61 34 2d 30 31 38 31 63 34 62 64 35 35 63 33) | (30 00 30 00 66 00 63 00 66 00 37 00 32 00 63 00 2d 00 64 00 31 00 34 00 38 00 2d 00 34 00 64 00 64 00 30 00 2d 00 39 00 63 00 61 00 34 00 2d 00 30 00 31 00 38 00 31 00 63 00 34 00 62 00 64 00 35 00 35 00 63 00 33 00))}
		$typelibguid0up = {((30 30 46 43 46 37 32 43 2d 44 31 34 38 2d 34 44 44 30 2d 39 43 41 34 2d 30 31 38 31 43 34 42 44 35 35 43 33) | (30 00 30 00 46 00 43 00 46 00 37 00 32 00 43 00 2d 00 44 00 31 00 34 00 38 00 2d 00 34 00 44 00 44 00 30 00 2d 00 39 00 43 00 41 00 34 00 2d 00 30 00 31 00 38 00 31 00 43 00 34 00 42 00 44 00 35 00 35 00 43 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_FileSearcher : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NVISO-BE/FileSearcher"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "1b5f1f68-f87b-5e60-94a4-e2556b4e6c5d"

	strings:
		$typelibguid0lo = {((32 63 38 37 39 34 37 39 2d 35 30 32 37 2d 34 63 65 39 2d 61 61 61 63 2d 30 38 34 64 62 30 65 36 64 36 33 30) | (32 00 63 00 38 00 37 00 39 00 34 00 37 00 39 00 2d 00 35 00 30 00 32 00 37 00 2d 00 34 00 63 00 65 00 39 00 2d 00 61 00 61 00 61 00 63 00 2d 00 30 00 38 00 34 00 64 00 62 00 30 00 65 00 36 00 64 00 36 00 33 00 30 00))}
		$typelibguid0up = {((32 43 38 37 39 34 37 39 2d 35 30 32 37 2d 34 43 45 39 2d 41 41 41 43 2d 30 38 34 44 42 30 45 36 44 36 33 30) | (32 00 43 00 38 00 37 00 39 00 34 00 37 00 39 00 2d 00 35 00 30 00 32 00 37 00 2d 00 34 00 43 00 45 00 39 00 2d 00 41 00 41 00 41 00 43 00 2d 00 30 00 38 00 34 00 44 00 42 00 30 00 45 00 36 00 44 00 36 00 33 00 30 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_ADFSDump : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/fireeye/ADFSDump"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "8cb2edcd-3696-5857-90ca-e99b1af54320"

	strings:
		$typelibguid0lo = {((39 65 65 32 37 64 36 33 2d 36 61 63 39 2d 34 30 33 37 2d 38 36 30 62 2d 34 34 65 39 31 62 61 65 37 66 30 64) | (39 00 65 00 65 00 32 00 37 00 64 00 36 00 33 00 2d 00 36 00 61 00 63 00 39 00 2d 00 34 00 30 00 33 00 37 00 2d 00 38 00 36 00 30 00 62 00 2d 00 34 00 34 00 65 00 39 00 31 00 62 00 61 00 65 00 37 00 66 00 30 00 64 00))}
		$typelibguid0up = {((39 45 45 32 37 44 36 33 2d 36 41 43 39 2d 34 30 33 37 2d 38 36 30 42 2d 34 34 45 39 31 42 41 45 37 46 30 44) | (39 00 45 00 45 00 32 00 37 00 44 00 36 00 33 00 2d 00 36 00 41 00 43 00 39 00 2d 00 34 00 30 00 33 00 37 00 2d 00 38 00 36 00 30 00 42 00 2d 00 34 00 34 00 45 00 39 00 31 00 42 00 41 00 45 00 37 00 46 00 30 00 44 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpRDP : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xthirteen/SharpRDP"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "d316ec0b-0313-52bb-923d-512fa08112f9"

	strings:
		$typelibguid0lo = {((66 31 64 66 31 64 30 66 2d 66 66 38 36 2d 34 31 30 36 2d 39 37 61 38 2d 66 39 35 61 61 66 35 32 35 63 35 34) | (66 00 31 00 64 00 66 00 31 00 64 00 30 00 66 00 2d 00 66 00 66 00 38 00 36 00 2d 00 34 00 31 00 30 00 36 00 2d 00 39 00 37 00 61 00 38 00 2d 00 66 00 39 00 35 00 61 00 61 00 66 00 35 00 32 00 35 00 63 00 35 00 34 00))}
		$typelibguid0up = {((46 31 44 46 31 44 30 46 2d 46 46 38 36 2d 34 31 30 36 2d 39 37 41 38 2d 46 39 35 41 41 46 35 32 35 43 35 34) | (46 00 31 00 44 00 46 00 31 00 44 00 30 00 46 00 2d 00 46 00 46 00 38 00 36 00 2d 00 34 00 31 00 30 00 36 00 2d 00 39 00 37 00 41 00 38 00 2d 00 46 00 39 00 35 00 41 00 41 00 46 00 35 00 32 00 35 00 43 00 35 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpCall : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jhalon/SharpCall"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "172415b6-0383-5da4-a88f-8ebe5daf9294"

	strings:
		$typelibguid0lo = {((63 31 62 30 61 39 32 33 2d 30 66 31 37 2d 34 62 63 38 2d 62 61 30 66 2d 63 38 37 61 66 66 34 33 65 37 39 39) | (63 00 31 00 62 00 30 00 61 00 39 00 32 00 33 00 2d 00 30 00 66 00 31 00 37 00 2d 00 34 00 62 00 63 00 38 00 2d 00 62 00 61 00 30 00 66 00 2d 00 63 00 38 00 37 00 61 00 66 00 66 00 34 00 33 00 65 00 37 00 39 00 39 00))}
		$typelibguid0up = {((43 31 42 30 41 39 32 33 2d 30 46 31 37 2d 34 42 43 38 2d 42 41 30 46 2d 43 38 37 41 46 46 34 33 45 37 39 39) | (43 00 31 00 42 00 30 00 41 00 39 00 32 00 33 00 2d 00 30 00 46 00 31 00 37 00 2d 00 34 00 42 00 43 00 38 00 2d 00 42 00 41 00 30 00 46 00 2d 00 43 00 38 00 37 00 41 00 46 00 46 00 34 00 33 00 45 00 37 00 39 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_ysoserial_net : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/pwntester/ysoserial.net"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "80483cd4-76e6-5629-bed7-4ae2e455222c"

	strings:
		$typelibguid0lo = {((65 31 65 38 63 30 32 39 2d 66 37 63 64 2d 34 62 64 31 2d 39 35 32 65 2d 65 38 31 39 62 34 31 35 32 30 66 30) | (65 00 31 00 65 00 38 00 63 00 30 00 32 00 39 00 2d 00 66 00 37 00 63 00 64 00 2d 00 34 00 62 00 64 00 31 00 2d 00 39 00 35 00 32 00 65 00 2d 00 65 00 38 00 31 00 39 00 62 00 34 00 31 00 35 00 32 00 30 00 66 00 30 00))}
		$typelibguid0up = {((45 31 45 38 43 30 32 39 2d 46 37 43 44 2d 34 42 44 31 2d 39 35 32 45 2d 45 38 31 39 42 34 31 35 32 30 46 30) | (45 00 31 00 45 00 38 00 43 00 30 00 32 00 39 00 2d 00 46 00 37 00 43 00 44 00 2d 00 34 00 42 00 44 00 31 00 2d 00 39 00 35 00 32 00 45 00 2d 00 45 00 38 00 31 00 39 00 42 00 34 00 31 00 35 00 32 00 30 00 46 00 30 00))}
		$typelibguid1lo = {((36 62 34 30 66 64 65 37 2d 31 34 65 61 2d 34 66 35 37 2d 38 62 37 62 2d 63 63 32 65 62 34 61 32 35 65 36 63) | (36 00 62 00 34 00 30 00 66 00 64 00 65 00 37 00 2d 00 31 00 34 00 65 00 61 00 2d 00 34 00 66 00 35 00 37 00 2d 00 38 00 62 00 37 00 62 00 2d 00 63 00 63 00 32 00 65 00 62 00 34 00 61 00 32 00 35 00 65 00 36 00 63 00))}
		$typelibguid1up = {((36 42 34 30 46 44 45 37 2d 31 34 45 41 2d 34 46 35 37 2d 38 42 37 42 2d 43 43 32 45 42 34 41 32 35 45 36 43) | (36 00 42 00 34 00 30 00 46 00 44 00 45 00 37 00 2d 00 31 00 34 00 45 00 41 00 2d 00 34 00 46 00 35 00 37 00 2d 00 38 00 42 00 37 00 42 00 2d 00 43 00 43 00 32 00 45 00 42 00 34 00 41 00 32 00 35 00 45 00 36 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_ManagedInjection : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/malcomvetter/ManagedInjection"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "c66e7666-b54f-532d-90e1-870292047aec"

	strings:
		$typelibguid0lo = {((65 35 31 38 32 62 66 66 2d 39 35 36 32 2d 34 30 66 66 2d 62 38 36 34 2d 35 61 36 62 33 30 63 33 62 31 33 62) | (65 00 35 00 31 00 38 00 32 00 62 00 66 00 66 00 2d 00 39 00 35 00 36 00 32 00 2d 00 34 00 30 00 66 00 66 00 2d 00 62 00 38 00 36 00 34 00 2d 00 35 00 61 00 36 00 62 00 33 00 30 00 63 00 33 00 62 00 31 00 33 00 62 00))}
		$typelibguid0up = {((45 35 31 38 32 42 46 46 2d 39 35 36 32 2d 34 30 46 46 2d 42 38 36 34 2d 35 41 36 42 33 30 43 33 42 31 33 42) | (45 00 35 00 31 00 38 00 32 00 42 00 46 00 46 00 2d 00 39 00 35 00 36 00 32 00 2d 00 34 00 30 00 46 00 46 00 2d 00 42 00 38 00 36 00 34 00 2d 00 35 00 41 00 36 00 42 00 33 00 30 00 43 00 33 00 42 00 31 00 33 00 42 00))}
		$typelibguid1lo = {((66 64 65 64 64 65 30 64 2d 65 30 39 35 2d 34 31 63 39 2d 39 33 66 62 2d 63 32 32 31 39 61 64 61 35 35 62 31) | (66 00 64 00 65 00 64 00 64 00 65 00 30 00 64 00 2d 00 65 00 30 00 39 00 35 00 2d 00 34 00 31 00 63 00 39 00 2d 00 39 00 33 00 66 00 62 00 2d 00 63 00 32 00 32 00 31 00 39 00 61 00 64 00 61 00 35 00 35 00 62 00 31 00))}
		$typelibguid1up = {((46 44 45 44 44 45 30 44 2d 45 30 39 35 2d 34 31 43 39 2d 39 33 46 42 2d 43 32 32 31 39 41 44 41 35 35 42 31) | (46 00 44 00 45 00 44 00 44 00 45 00 30 00 44 00 2d 00 45 00 30 00 39 00 35 00 2d 00 34 00 31 00 43 00 39 00 2d 00 39 00 33 00 46 00 42 00 2d 00 43 00 32 00 32 00 31 00 39 00 41 00 44 00 41 00 35 00 35 00 42 00 31 00))}
		$typelibguid2lo = {((30 64 64 30 30 35 36 31 2d 61 66 66 63 2d 34 30 36 36 2d 38 63 34 38 2d 63 65 39 35 30 37 38 38 63 33 63 38) | (30 00 64 00 64 00 30 00 30 00 35 00 36 00 31 00 2d 00 61 00 66 00 66 00 63 00 2d 00 34 00 30 00 36 00 36 00 2d 00 38 00 63 00 34 00 38 00 2d 00 63 00 65 00 39 00 35 00 30 00 37 00 38 00 38 00 63 00 33 00 63 00 38 00))}
		$typelibguid2up = {((30 44 44 30 30 35 36 31 2d 41 46 46 43 2d 34 30 36 36 2d 38 43 34 38 2d 43 45 39 35 30 37 38 38 43 33 43 38) | (30 00 44 00 44 00 30 00 30 00 35 00 36 00 31 00 2d 00 41 00 46 00 46 00 43 00 2d 00 34 00 30 00 36 00 36 00 2d 00 38 00 43 00 34 00 38 00 2d 00 43 00 45 00 39 00 35 00 30 00 37 00 38 00 38 00 43 00 33 00 43 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpSocks : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/nettitude/SharpSocks"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "343061d9-e24e-5d49-939f-b94c295b17ac"

	strings:
		$typelibguid0lo = {((32 66 34 33 39 39 32 65 2d 35 37 30 33 2d 34 34 32 30 2d 61 64 30 62 2d 31 37 63 62 37 64 38 39 63 39 35 36) | (32 00 66 00 34 00 33 00 39 00 39 00 32 00 65 00 2d 00 35 00 37 00 30 00 33 00 2d 00 34 00 34 00 32 00 30 00 2d 00 61 00 64 00 30 00 62 00 2d 00 31 00 37 00 63 00 62 00 37 00 64 00 38 00 39 00 63 00 39 00 35 00 36 00))}
		$typelibguid0up = {((32 46 34 33 39 39 32 45 2d 35 37 30 33 2d 34 34 32 30 2d 41 44 30 42 2d 31 37 43 42 37 44 38 39 43 39 35 36) | (32 00 46 00 34 00 33 00 39 00 39 00 32 00 45 00 2d 00 35 00 37 00 30 00 33 00 2d 00 34 00 34 00 32 00 30 00 2d 00 41 00 44 00 30 00 42 00 2d 00 31 00 37 00 43 00 42 00 37 00 44 00 38 00 39 00 43 00 39 00 35 00 36 00))}
		$typelibguid1lo = {((38 36 64 31 30 61 33 34 2d 63 33 37 34 2d 34 64 65 34 2d 38 65 31 32 2d 34 39 30 65 35 65 36 35 64 64 66 66) | (38 00 36 00 64 00 31 00 30 00 61 00 33 00 34 00 2d 00 63 00 33 00 37 00 34 00 2d 00 34 00 64 00 65 00 34 00 2d 00 38 00 65 00 31 00 32 00 2d 00 34 00 39 00 30 00 65 00 35 00 65 00 36 00 35 00 64 00 64 00 66 00 66 00))}
		$typelibguid1up = {((38 36 44 31 30 41 33 34 2d 43 33 37 34 2d 34 44 45 34 2d 38 45 31 32 2d 34 39 30 45 35 45 36 35 44 44 46 46) | (38 00 36 00 44 00 31 00 30 00 41 00 33 00 34 00 2d 00 43 00 33 00 37 00 34 00 2d 00 34 00 44 00 45 00 34 00 2d 00 38 00 45 00 31 00 32 00 2d 00 34 00 39 00 30 00 45 00 35 00 45 00 36 00 35 00 44 00 44 00 46 00 46 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Sharp_WMIExec : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/checkymander/Sharp-WMIExec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "ae08a5a2-06d5-55fe-803a-7f4696220904"

	strings:
		$typelibguid0lo = {((30 61 36 33 62 30 61 31 2d 37 64 31 61 2d 34 62 38 34 2d 38 31 63 33 2d 62 62 62 66 65 39 39 31 33 30 32 39) | (30 00 61 00 36 00 33 00 62 00 30 00 61 00 31 00 2d 00 37 00 64 00 31 00 61 00 2d 00 34 00 62 00 38 00 34 00 2d 00 38 00 31 00 63 00 33 00 2d 00 62 00 62 00 62 00 66 00 65 00 39 00 39 00 31 00 33 00 30 00 32 00 39 00))}
		$typelibguid0up = {((30 41 36 33 42 30 41 31 2d 37 44 31 41 2d 34 42 38 34 2d 38 31 43 33 2d 42 42 42 46 45 39 39 31 33 30 32 39) | (30 00 41 00 36 00 33 00 42 00 30 00 41 00 31 00 2d 00 37 00 44 00 31 00 41 00 2d 00 34 00 42 00 38 00 34 00 2d 00 38 00 31 00 43 00 33 00 2d 00 42 00 42 00 42 00 46 00 45 00 39 00 39 00 31 00 33 00 30 00 32 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_KeeThief : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/KeeThief"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "71fef0e9-223a-5834-9d1c-f3fb8b66a809"

	strings:
		$typelibguid1lo = {((33 39 61 61 36 66 39 33 2d 61 31 63 39 2d 34 39 37 66 2d 62 61 64 32 2d 63 63 34 32 61 36 31 64 35 37 31 30) | (33 00 39 00 61 00 61 00 36 00 66 00 39 00 33 00 2d 00 61 00 31 00 63 00 39 00 2d 00 34 00 39 00 37 00 66 00 2d 00 62 00 61 00 64 00 32 00 2d 00 63 00 63 00 34 00 32 00 61 00 36 00 31 00 64 00 35 00 37 00 31 00 30 00))}
		$typelibguid1up = {((33 39 41 41 36 46 39 33 2d 41 31 43 39 2d 34 39 37 46 2d 42 41 44 32 2d 43 43 34 32 41 36 31 44 35 37 31 30) | (33 00 39 00 41 00 41 00 36 00 46 00 39 00 33 00 2d 00 41 00 31 00 43 00 39 00 2d 00 34 00 39 00 37 00 46 00 2d 00 42 00 41 00 44 00 32 00 2d 00 43 00 43 00 34 00 32 00 41 00 36 00 31 00 44 00 35 00 37 00 31 00 30 00))}
		$typelibguid3lo = {((33 66 63 61 38 30 31 32 2d 33 62 61 64 2d 34 31 65 34 2d 39 31 66 34 2d 35 33 34 61 61 39 61 34 34 66 39 36) | (33 00 66 00 63 00 61 00 38 00 30 00 31 00 32 00 2d 00 33 00 62 00 61 00 64 00 2d 00 34 00 31 00 65 00 34 00 2d 00 39 00 31 00 66 00 34 00 2d 00 35 00 33 00 34 00 61 00 61 00 39 00 61 00 34 00 34 00 66 00 39 00 36 00))}
		$typelibguid3up = {((33 46 43 41 38 30 31 32 2d 33 42 41 44 2d 34 31 45 34 2d 39 31 46 34 2d 35 33 34 41 41 39 41 34 34 46 39 36) | (33 00 46 00 43 00 41 00 38 00 30 00 31 00 32 00 2d 00 33 00 42 00 41 00 44 00 2d 00 34 00 31 00 45 00 34 00 2d 00 39 00 31 00 46 00 34 00 2d 00 35 00 33 00 34 00 41 00 41 00 39 00 41 00 34 00 34 00 46 00 39 00 36 00))}
		$typelibguid4lo = {((65 61 39 32 66 31 65 36 2d 33 66 33 34 2d 34 38 66 38 2d 38 62 30 61 2d 66 32 62 62 63 31 39 32 32 30 65 66) | (65 00 61 00 39 00 32 00 66 00 31 00 65 00 36 00 2d 00 33 00 66 00 33 00 34 00 2d 00 34 00 38 00 66 00 38 00 2d 00 38 00 62 00 30 00 61 00 2d 00 66 00 32 00 62 00 62 00 63 00 31 00 39 00 32 00 32 00 30 00 65 00 66 00))}
		$typelibguid4up = {((45 41 39 32 46 31 45 36 2d 33 46 33 34 2d 34 38 46 38 2d 38 42 30 41 2d 46 32 42 42 43 31 39 32 32 30 45 46) | (45 00 41 00 39 00 32 00 46 00 31 00 45 00 36 00 2d 00 33 00 46 00 33 00 34 00 2d 00 34 00 38 00 46 00 38 00 2d 00 38 00 42 00 30 00 41 00 2d 00 46 00 32 00 42 00 42 00 43 00 31 00 39 00 32 00 32 00 30 00 45 00 46 00))}
		$typelibguid5lo = {((63 32 33 62 35 31 63 34 2d 32 34 37 35 2d 34 66 63 36 2d 39 62 33 61 2d 32 37 64 30 61 32 62 39 39 62 30 66) | (63 00 32 00 33 00 62 00 35 00 31 00 63 00 34 00 2d 00 32 00 34 00 37 00 35 00 2d 00 34 00 66 00 63 00 36 00 2d 00 39 00 62 00 33 00 61 00 2d 00 32 00 37 00 64 00 30 00 61 00 32 00 62 00 39 00 39 00 62 00 30 00 66 00))}
		$typelibguid5up = {((43 32 33 42 35 31 43 34 2d 32 34 37 35 2d 34 46 43 36 2d 39 42 33 41 2d 32 37 44 30 41 32 42 39 39 42 30 46) | (43 00 32 00 33 00 42 00 35 00 31 00 43 00 34 00 2d 00 32 00 34 00 37 00 35 00 2d 00 34 00 46 00 43 00 36 00 2d 00 39 00 42 00 33 00 41 00 2d 00 32 00 37 00 44 00 30 00 41 00 32 00 42 00 39 00 39 00 42 00 30 00 46 00))}
		$typelibguid7lo = {((38 30 62 61 36 33 61 34 2d 37 64 34 31 2d 34 30 65 39 2d 61 37 32 32 2d 36 64 64 35 38 62 32 38 62 66 37 65) | (38 00 30 00 62 00 61 00 36 00 33 00 61 00 34 00 2d 00 37 00 64 00 34 00 31 00 2d 00 34 00 30 00 65 00 39 00 2d 00 61 00 37 00 32 00 32 00 2d 00 36 00 64 00 64 00 35 00 38 00 62 00 32 00 38 00 62 00 66 00 37 00 65 00))}
		$typelibguid7up = {((38 30 42 41 36 33 41 34 2d 37 44 34 31 2d 34 30 45 39 2d 41 37 32 32 2d 36 44 44 35 38 42 32 38 42 46 37 45) | (38 00 30 00 42 00 41 00 36 00 33 00 41 00 34 00 2d 00 37 00 44 00 34 00 31 00 2d 00 34 00 30 00 45 00 39 00 2d 00 41 00 37 00 32 00 32 00 2d 00 36 00 44 00 44 00 35 00 38 00 42 00 32 00 38 00 42 00 46 00 37 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_fakelogonscreen : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/bitsadmin/fakelogonscreen"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "cc20290c-3f34-5e81-9337-c582f1ee7ade"

	strings:
		$typelibguid0lo = {((64 33 35 61 35 35 62 64 2d 33 31 38 39 2d 34 39 38 62 2d 62 37 32 66 2d 64 63 37 39 38 31 37 32 65 35 30 35) | (64 00 33 00 35 00 61 00 35 00 35 00 62 00 64 00 2d 00 33 00 31 00 38 00 39 00 2d 00 34 00 39 00 38 00 62 00 2d 00 62 00 37 00 32 00 66 00 2d 00 64 00 63 00 37 00 39 00 38 00 31 00 37 00 32 00 65 00 35 00 30 00 35 00))}
		$typelibguid0up = {((44 33 35 41 35 35 42 44 2d 33 31 38 39 2d 34 39 38 42 2d 42 37 32 46 2d 44 43 37 39 38 31 37 32 45 35 30 35) | (44 00 33 00 35 00 41 00 35 00 35 00 42 00 44 00 2d 00 33 00 31 00 38 00 39 00 2d 00 34 00 39 00 38 00 42 00 2d 00 42 00 37 00 32 00 46 00 2d 00 44 00 43 00 37 00 39 00 38 00 31 00 37 00 32 00 45 00 35 00 30 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_PoshSecFramework : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/PoshSec/PoshSecFramework"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "a91620f3-3f21-525a-bc87-94d21cd126be"

	strings:
		$typelibguid0lo = {((62 31 61 63 36 61 61 30 2d 32 66 31 61 2d 34 36 39 36 2d 62 66 34 62 2d 30 65 34 31 63 66 32 66 34 62 36 62) | (62 00 31 00 61 00 63 00 36 00 61 00 61 00 30 00 2d 00 32 00 66 00 31 00 61 00 2d 00 34 00 36 00 39 00 36 00 2d 00 62 00 66 00 34 00 62 00 2d 00 30 00 65 00 34 00 31 00 63 00 66 00 32 00 66 00 34 00 62 00 36 00 62 00))}
		$typelibguid0up = {((42 31 41 43 36 41 41 30 2d 32 46 31 41 2d 34 36 39 36 2d 42 46 34 42 2d 30 45 34 31 43 46 32 46 34 42 36 42) | (42 00 31 00 41 00 43 00 36 00 41 00 41 00 30 00 2d 00 32 00 46 00 31 00 41 00 2d 00 34 00 36 00 39 00 36 00 2d 00 42 00 46 00 34 00 42 00 2d 00 30 00 45 00 34 00 31 00 43 00 46 00 32 00 46 00 34 00 42 00 36 00 42 00))}
		$typelibguid1lo = {((37 38 62 66 63 66 63 32 2d 65 66 31 63 2d 34 35 31 34 2d 62 63 65 36 2d 39 33 34 62 32 35 31 36 36 36 64 32) | (37 00 38 00 62 00 66 00 63 00 66 00 63 00 32 00 2d 00 65 00 66 00 31 00 63 00 2d 00 34 00 35 00 31 00 34 00 2d 00 62 00 63 00 65 00 36 00 2d 00 39 00 33 00 34 00 62 00 32 00 35 00 31 00 36 00 36 00 36 00 64 00 32 00))}
		$typelibguid1up = {((37 38 42 46 43 46 43 32 2d 45 46 31 43 2d 34 35 31 34 2d 42 43 45 36 2d 39 33 34 42 32 35 31 36 36 36 44 32) | (37 00 38 00 42 00 46 00 43 00 46 00 43 00 32 00 2d 00 45 00 46 00 31 00 43 00 2d 00 34 00 35 00 31 00 34 00 2d 00 42 00 43 00 45 00 36 00 2d 00 39 00 33 00 34 00 42 00 32 00 35 00 31 00 36 00 36 00 36 00 44 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpAttack : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jaredhaight/SharpAttack"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "1eb911ab-3fb9-54b7-8afb-66328f30d563"

	strings:
		$typelibguid0lo = {((35 66 30 63 65 63 61 33 2d 35 39 39 37 2d 34 30 36 63 2d 61 64 66 35 2d 36 63 37 66 62 62 36 63 62 61 31 37) | (35 00 66 00 30 00 63 00 65 00 63 00 61 00 33 00 2d 00 35 00 39 00 39 00 37 00 2d 00 34 00 30 00 36 00 63 00 2d 00 61 00 64 00 66 00 35 00 2d 00 36 00 63 00 37 00 66 00 62 00 62 00 36 00 63 00 62 00 61 00 31 00 37 00))}
		$typelibguid0up = {((35 46 30 43 45 43 41 33 2d 35 39 39 37 2d 34 30 36 43 2d 41 44 46 35 2d 36 43 37 46 42 42 36 43 42 41 31 37) | (35 00 46 00 30 00 43 00 45 00 43 00 41 00 33 00 2d 00 35 00 39 00 39 00 37 00 2d 00 34 00 30 00 36 00 43 00 2d 00 41 00 44 00 46 00 35 00 2d 00 36 00 43 00 37 00 46 00 42 00 42 00 36 00 43 00 42 00 41 00 31 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Altman : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/keepwn/Altman"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "21acc8af-9497-5842-90a9-7a9300585d5d"

	strings:
		$typelibguid0lo = {((36 34 63 64 63 64 32 62 2d 37 33 35 36 2d 34 30 37 39 2d 61 66 37 38 2d 65 32 32 32 31 30 65 36 36 31 35 34) | (36 00 34 00 63 00 64 00 63 00 64 00 32 00 62 00 2d 00 37 00 33 00 35 00 36 00 2d 00 34 00 30 00 37 00 39 00 2d 00 61 00 66 00 37 00 38 00 2d 00 65 00 32 00 32 00 32 00 31 00 30 00 65 00 36 00 36 00 31 00 35 00 34 00))}
		$typelibguid0up = {((36 34 43 44 43 44 32 42 2d 37 33 35 36 2d 34 30 37 39 2d 41 46 37 38 2d 45 32 32 32 31 30 45 36 36 31 35 34) | (36 00 34 00 43 00 44 00 43 00 44 00 32 00 42 00 2d 00 37 00 33 00 35 00 36 00 2d 00 34 00 30 00 37 00 39 00 2d 00 41 00 46 00 37 00 38 00 2d 00 45 00 32 00 32 00 32 00 31 00 30 00 45 00 36 00 36 00 31 00 35 00 34 00))}
		$typelibguid1lo = {((66 31 64 65 65 32 39 64 2d 63 61 39 38 2d 34 36 65 61 2d 39 64 31 33 2d 39 33 61 65 31 66 64 61 39 36 65 31) | (66 00 31 00 64 00 65 00 65 00 32 00 39 00 64 00 2d 00 63 00 61 00 39 00 38 00 2d 00 34 00 36 00 65 00 61 00 2d 00 39 00 64 00 31 00 33 00 2d 00 39 00 33 00 61 00 65 00 31 00 66 00 64 00 61 00 39 00 36 00 65 00 31 00))}
		$typelibguid1up = {((46 31 44 45 45 32 39 44 2d 43 41 39 38 2d 34 36 45 41 2d 39 44 31 33 2d 39 33 41 45 31 46 44 41 39 36 45 31) | (46 00 31 00 44 00 45 00 45 00 32 00 39 00 44 00 2d 00 43 00 41 00 39 00 38 00 2d 00 34 00 36 00 45 00 41 00 2d 00 39 00 44 00 31 00 33 00 2d 00 39 00 33 00 41 00 45 00 31 00 46 00 44 00 41 00 39 00 36 00 45 00 31 00))}
		$typelibguid2lo = {((33 33 35 36 38 33 32 30 2d 35 36 65 38 2d 34 61 62 62 2d 38 33 66 38 2d 35 34 38 65 38 64 36 61 64 61 63 32) | (33 00 33 00 35 00 36 00 38 00 33 00 32 00 30 00 2d 00 35 00 36 00 65 00 38 00 2d 00 34 00 61 00 62 00 62 00 2d 00 38 00 33 00 66 00 38 00 2d 00 35 00 34 00 38 00 65 00 38 00 64 00 36 00 61 00 64 00 61 00 63 00 32 00))}
		$typelibguid2up = {((33 33 35 36 38 33 32 30 2d 35 36 45 38 2d 34 41 42 42 2d 38 33 46 38 2d 35 34 38 45 38 44 36 41 44 41 43 32) | (33 00 33 00 35 00 36 00 38 00 33 00 32 00 30 00 2d 00 35 00 36 00 45 00 38 00 2d 00 34 00 41 00 42 00 42 00 2d 00 38 00 33 00 46 00 38 00 2d 00 35 00 34 00 38 00 45 00 38 00 44 00 36 00 41 00 44 00 41 00 43 00 32 00))}
		$typelibguid3lo = {((34 37 30 65 63 39 33 30 2d 37 30 61 33 2d 34 64 37 31 2d 62 34 66 66 2d 38 36 30 66 63 62 39 30 30 65 38 35) | (34 00 37 00 30 00 65 00 63 00 39 00 33 00 30 00 2d 00 37 00 30 00 61 00 33 00 2d 00 34 00 64 00 37 00 31 00 2d 00 62 00 34 00 66 00 66 00 2d 00 38 00 36 00 30 00 66 00 63 00 62 00 39 00 30 00 30 00 65 00 38 00 35 00))}
		$typelibguid3up = {((34 37 30 45 43 39 33 30 2d 37 30 41 33 2d 34 44 37 31 2d 42 34 46 46 2d 38 36 30 46 43 42 39 30 30 45 38 35) | (34 00 37 00 30 00 45 00 43 00 39 00 33 00 30 00 2d 00 37 00 30 00 41 00 33 00 2d 00 34 00 44 00 37 00 31 00 2d 00 42 00 34 00 46 00 46 00 2d 00 38 00 36 00 30 00 46 00 43 00 42 00 39 00 30 00 30 00 45 00 38 00 35 00))}
		$typelibguid4lo = {((39 35 31 34 35 37 34 64 2d 36 38 31 39 2d 34 34 66 32 2d 61 66 66 61 2d 36 31 35 38 61 63 31 31 34 33 62 33) | (39 00 35 00 31 00 34 00 35 00 37 00 34 00 64 00 2d 00 36 00 38 00 31 00 39 00 2d 00 34 00 34 00 66 00 32 00 2d 00 61 00 66 00 66 00 61 00 2d 00 36 00 31 00 35 00 38 00 61 00 63 00 31 00 31 00 34 00 33 00 62 00 33 00))}
		$typelibguid4up = {((39 35 31 34 35 37 34 44 2d 36 38 31 39 2d 34 34 46 32 2d 41 46 46 41 2d 36 31 35 38 41 43 31 31 34 33 42 33) | (39 00 35 00 31 00 34 00 35 00 37 00 34 00 44 00 2d 00 36 00 38 00 31 00 39 00 2d 00 34 00 34 00 46 00 32 00 2d 00 41 00 46 00 46 00 41 00 2d 00 36 00 31 00 35 00 38 00 41 00 43 00 31 00 31 00 34 00 33 00 42 00 33 00))}
		$typelibguid5lo = {((30 66 33 61 39 63 34 66 2d 30 62 31 31 2d 34 33 37 33 2d 61 30 61 36 2d 33 61 36 64 65 38 31 34 65 38 39 31) | (30 00 66 00 33 00 61 00 39 00 63 00 34 00 66 00 2d 00 30 00 62 00 31 00 31 00 2d 00 34 00 33 00 37 00 33 00 2d 00 61 00 30 00 61 00 36 00 2d 00 33 00 61 00 36 00 64 00 65 00 38 00 31 00 34 00 65 00 38 00 39 00 31 00))}
		$typelibguid5up = {((30 46 33 41 39 43 34 46 2d 30 42 31 31 2d 34 33 37 33 2d 41 30 41 36 2d 33 41 36 44 45 38 31 34 45 38 39 31) | (30 00 46 00 33 00 41 00 39 00 43 00 34 00 46 00 2d 00 30 00 42 00 31 00 31 00 2d 00 34 00 33 00 37 00 33 00 2d 00 41 00 30 00 41 00 36 00 2d 00 33 00 41 00 36 00 44 00 45 00 38 00 31 00 34 00 45 00 38 00 39 00 31 00))}
		$typelibguid6lo = {((39 36 32 34 62 37 32 65 2d 39 37 30 32 2d 34 64 37 38 2d 39 39 35 62 2d 31 36 34 32 35 34 33 32 38 31 35 31) | (39 00 36 00 32 00 34 00 62 00 37 00 32 00 65 00 2d 00 39 00 37 00 30 00 32 00 2d 00 34 00 64 00 37 00 38 00 2d 00 39 00 39 00 35 00 62 00 2d 00 31 00 36 00 34 00 32 00 35 00 34 00 33 00 32 00 38 00 31 00 35 00 31 00))}
		$typelibguid6up = {((39 36 32 34 42 37 32 45 2d 39 37 30 32 2d 34 44 37 38 2d 39 39 35 42 2d 31 36 34 32 35 34 33 32 38 31 35 31) | (39 00 36 00 32 00 34 00 42 00 37 00 32 00 45 00 2d 00 39 00 37 00 30 00 32 00 2d 00 34 00 44 00 37 00 38 00 2d 00 39 00 39 00 35 00 42 00 2d 00 31 00 36 00 34 00 32 00 35 00 34 00 33 00 32 00 38 00 31 00 35 00 31 00))}
		$typelibguid7lo = {((66 61 61 65 35 39 61 38 2d 35 35 66 63 2d 34 38 62 31 2d 61 39 62 35 2d 62 31 37 35 39 63 39 63 31 30 31 30) | (66 00 61 00 61 00 65 00 35 00 39 00 61 00 38 00 2d 00 35 00 35 00 66 00 63 00 2d 00 34 00 38 00 62 00 31 00 2d 00 61 00 39 00 62 00 35 00 2d 00 62 00 31 00 37 00 35 00 39 00 63 00 39 00 63 00 31 00 30 00 31 00 30 00))}
		$typelibguid7up = {((46 41 41 45 35 39 41 38 2d 35 35 46 43 2d 34 38 42 31 2d 41 39 42 35 2d 42 31 37 35 39 43 39 43 31 30 31 30) | (46 00 41 00 41 00 45 00 35 00 39 00 41 00 38 00 2d 00 35 00 35 00 46 00 43 00 2d 00 34 00 38 00 42 00 31 00 2d 00 41 00 39 00 42 00 35 00 2d 00 42 00 31 00 37 00 35 00 39 00 43 00 39 00 43 00 31 00 30 00 31 00 30 00))}
		$typelibguid8lo = {((33 37 61 66 34 39 38 38 2d 66 36 66 32 2d 34 66 30 63 2d 61 61 32 62 2d 35 62 32 34 66 37 65 64 33 62 66 33) | (33 00 37 00 61 00 66 00 34 00 39 00 38 00 38 00 2d 00 66 00 36 00 66 00 32 00 2d 00 34 00 66 00 30 00 63 00 2d 00 61 00 61 00 32 00 62 00 2d 00 35 00 62 00 32 00 34 00 66 00 37 00 65 00 64 00 33 00 62 00 66 00 33 00))}
		$typelibguid8up = {((33 37 41 46 34 39 38 38 2d 46 36 46 32 2d 34 46 30 43 2d 41 41 32 42 2d 35 42 32 34 46 37 45 44 33 42 46 33) | (33 00 37 00 41 00 46 00 34 00 39 00 38 00 38 00 2d 00 46 00 36 00 46 00 32 00 2d 00 34 00 46 00 30 00 43 00 2d 00 41 00 41 00 32 00 42 00 2d 00 35 00 42 00 32 00 34 00 46 00 37 00 45 00 44 00 33 00 42 00 46 00 33 00))}
		$typelibguid9lo = {((63 38 32 61 61 32 66 65 2d 33 33 33 32 2d 34 34 31 66 2d 39 36 35 65 2d 36 62 36 35 33 65 30 38 38 61 62 66) | (63 00 38 00 32 00 61 00 61 00 32 00 66 00 65 00 2d 00 33 00 33 00 33 00 32 00 2d 00 34 00 34 00 31 00 66 00 2d 00 39 00 36 00 35 00 65 00 2d 00 36 00 62 00 36 00 35 00 33 00 65 00 30 00 38 00 38 00 61 00 62 00 66 00))}
		$typelibguid9up = {((43 38 32 41 41 32 46 45 2d 33 33 33 32 2d 34 34 31 46 2d 39 36 35 45 2d 36 42 36 35 33 45 30 38 38 41 42 46) | (43 00 38 00 32 00 41 00 41 00 32 00 46 00 45 00 2d 00 33 00 33 00 33 00 32 00 2d 00 34 00 34 00 31 00 46 00 2d 00 39 00 36 00 35 00 45 00 2d 00 36 00 42 00 36 00 35 00 33 00 45 00 30 00 38 00 38 00 41 00 42 00 46 00))}
		$typelibguid10lo = {((36 65 35 33 31 66 36 63 2d 32 63 38 39 2d 34 34 37 66 2d 38 34 36 34 2d 61 61 61 39 36 64 62 63 64 66 66 66) | (36 00 65 00 35 00 33 00 31 00 66 00 36 00 63 00 2d 00 32 00 63 00 38 00 39 00 2d 00 34 00 34 00 37 00 66 00 2d 00 38 00 34 00 36 00 34 00 2d 00 61 00 61 00 61 00 39 00 36 00 64 00 62 00 63 00 64 00 66 00 66 00 66 00))}
		$typelibguid10up = {((36 45 35 33 31 46 36 43 2d 32 43 38 39 2d 34 34 37 46 2d 38 34 36 34 2d 41 41 41 39 36 44 42 43 44 46 46 46) | (36 00 45 00 35 00 33 00 31 00 46 00 36 00 43 00 2d 00 32 00 43 00 38 00 39 00 2d 00 34 00 34 00 37 00 46 00 2d 00 38 00 34 00 36 00 34 00 2d 00 41 00 41 00 41 00 39 00 36 00 44 00 42 00 43 00 44 00 46 00 46 00 46 00))}
		$typelibguid11lo = {((32 33 31 39 38 37 61 31 2d 65 61 33 32 2d 34 30 38 37 2d 38 39 36 33 2d 32 33 32 32 33 33 38 66 31 36 66 36) | (32 00 33 00 31 00 39 00 38 00 37 00 61 00 31 00 2d 00 65 00 61 00 33 00 32 00 2d 00 34 00 30 00 38 00 37 00 2d 00 38 00 39 00 36 00 33 00 2d 00 32 00 33 00 32 00 32 00 33 00 33 00 38 00 66 00 31 00 36 00 66 00 36 00))}
		$typelibguid11up = {((32 33 31 39 38 37 41 31 2d 45 41 33 32 2d 34 30 38 37 2d 38 39 36 33 2d 32 33 32 32 33 33 38 46 31 36 46 36) | (32 00 33 00 31 00 39 00 38 00 37 00 41 00 31 00 2d 00 45 00 41 00 33 00 32 00 2d 00 34 00 30 00 38 00 37 00 2d 00 38 00 39 00 36 00 33 00 2d 00 32 00 33 00 32 00 32 00 33 00 33 00 38 00 46 00 31 00 36 00 46 00 36 00))}
		$typelibguid12lo = {((37 64 61 30 64 39 33 61 2d 61 30 61 65 2d 34 31 61 35 2d 39 33 38 39 2d 34 32 65 66 66 38 35 62 62 30 36 34) | (37 00 64 00 61 00 30 00 64 00 39 00 33 00 61 00 2d 00 61 00 30 00 61 00 65 00 2d 00 34 00 31 00 61 00 35 00 2d 00 39 00 33 00 38 00 39 00 2d 00 34 00 32 00 65 00 66 00 66 00 38 00 35 00 62 00 62 00 30 00 36 00 34 00))}
		$typelibguid12up = {((37 44 41 30 44 39 33 41 2d 41 30 41 45 2d 34 31 41 35 2d 39 33 38 39 2d 34 32 45 46 46 38 35 42 42 30 36 34) | (37 00 44 00 41 00 30 00 44 00 39 00 33 00 41 00 2d 00 41 00 30 00 41 00 45 00 2d 00 34 00 31 00 41 00 35 00 2d 00 39 00 33 00 38 00 39 00 2d 00 34 00 32 00 45 00 46 00 46 00 38 00 35 00 42 00 42 00 30 00 36 00 34 00))}
		$typelibguid13lo = {((61 37 32 39 66 39 63 63 2d 65 64 63 32 2d 34 37 38 35 2d 39 61 37 64 2d 37 62 38 31 62 62 31 32 34 38 34 63) | (61 00 37 00 32 00 39 00 66 00 39 00 63 00 63 00 2d 00 65 00 64 00 63 00 32 00 2d 00 34 00 37 00 38 00 35 00 2d 00 39 00 61 00 37 00 64 00 2d 00 37 00 62 00 38 00 31 00 62 00 62 00 31 00 32 00 34 00 38 00 34 00 63 00))}
		$typelibguid13up = {((41 37 32 39 46 39 43 43 2d 45 44 43 32 2d 34 37 38 35 2d 39 41 37 44 2d 37 42 38 31 42 42 31 32 34 38 34 43) | (41 00 37 00 32 00 39 00 46 00 39 00 43 00 43 00 2d 00 45 00 44 00 43 00 32 00 2d 00 34 00 37 00 38 00 35 00 2d 00 39 00 41 00 37 00 44 00 2d 00 37 00 42 00 38 00 31 00 42 00 42 00 31 00 32 00 34 00 38 00 34 00 43 00))}
		$typelibguid14lo = {((35 35 61 31 66 64 34 33 2d 64 32 33 65 2d 34 64 37 32 2d 61 61 64 62 2d 62 62 64 31 33 34 30 61 36 39 31 33) | (35 00 35 00 61 00 31 00 66 00 64 00 34 00 33 00 2d 00 64 00 32 00 33 00 65 00 2d 00 34 00 64 00 37 00 32 00 2d 00 61 00 61 00 64 00 62 00 2d 00 62 00 62 00 64 00 31 00 33 00 34 00 30 00 61 00 36 00 39 00 31 00 33 00))}
		$typelibguid14up = {((35 35 41 31 46 44 34 33 2d 44 32 33 45 2d 34 44 37 32 2d 41 41 44 42 2d 42 42 44 31 33 34 30 41 36 39 31 33) | (35 00 35 00 41 00 31 00 46 00 44 00 34 00 33 00 2d 00 44 00 32 00 33 00 45 00 2d 00 34 00 44 00 37 00 32 00 2d 00 41 00 41 00 44 00 42 00 2d 00 42 00 42 00 44 00 31 00 33 00 34 00 30 00 41 00 36 00 39 00 31 00 33 00))}
		$typelibguid15lo = {((64 34 33 66 32 34 30 64 2d 65 37 66 35 2d 34 33 63 35 2d 39 62 35 31 2d 64 31 35 36 64 63 37 65 61 32 32 31) | (64 00 34 00 33 00 66 00 32 00 34 00 30 00 64 00 2d 00 65 00 37 00 66 00 35 00 2d 00 34 00 33 00 63 00 35 00 2d 00 39 00 62 00 35 00 31 00 2d 00 64 00 31 00 35 00 36 00 64 00 63 00 37 00 65 00 61 00 32 00 32 00 31 00))}
		$typelibguid15up = {((44 34 33 46 32 34 30 44 2d 45 37 46 35 2d 34 33 43 35 2d 39 42 35 31 2d 44 31 35 36 44 43 37 45 41 32 32 31) | (44 00 34 00 33 00 46 00 32 00 34 00 30 00 44 00 2d 00 45 00 37 00 46 00 35 00 2d 00 34 00 33 00 43 00 35 00 2d 00 39 00 42 00 35 00 31 00 2d 00 44 00 31 00 35 00 36 00 44 00 43 00 37 00 45 00 41 00 32 00 32 00 31 00))}
		$typelibguid16lo = {((63 32 65 36 63 31 61 30 2d 39 33 62 31 2d 34 62 62 63 2d 39 38 65 36 2d 38 65 32 62 33 31 34 35 64 62 38 65) | (63 00 32 00 65 00 36 00 63 00 31 00 61 00 30 00 2d 00 39 00 33 00 62 00 31 00 2d 00 34 00 62 00 62 00 63 00 2d 00 39 00 38 00 65 00 36 00 2d 00 38 00 65 00 32 00 62 00 33 00 31 00 34 00 35 00 64 00 62 00 38 00 65 00))}
		$typelibguid16up = {((43 32 45 36 43 31 41 30 2d 39 33 42 31 2d 34 42 42 43 2d 39 38 45 36 2d 38 45 32 42 33 31 34 35 44 42 38 45) | (43 00 32 00 45 00 36 00 43 00 31 00 41 00 30 00 2d 00 39 00 33 00 42 00 31 00 2d 00 34 00 42 00 42 00 43 00 2d 00 39 00 38 00 45 00 36 00 2d 00 38 00 45 00 32 00 42 00 33 00 31 00 34 00 35 00 44 00 42 00 38 00 45 00))}
		$typelibguid17lo = {((37 31 34 61 65 36 66 33 2d 30 64 30 33 2d 34 30 32 33 2d 62 37 35 33 2d 66 65 64 36 61 33 31 64 39 35 63 37) | (37 00 31 00 34 00 61 00 65 00 36 00 66 00 33 00 2d 00 30 00 64 00 30 00 33 00 2d 00 34 00 30 00 32 00 33 00 2d 00 62 00 37 00 35 00 33 00 2d 00 66 00 65 00 64 00 36 00 61 00 33 00 31 00 64 00 39 00 35 00 63 00 37 00))}
		$typelibguid17up = {((37 31 34 41 45 36 46 33 2d 30 44 30 33 2d 34 30 32 33 2d 42 37 35 33 2d 46 45 44 36 41 33 31 44 39 35 43 37) | (37 00 31 00 34 00 41 00 45 00 36 00 46 00 33 00 2d 00 30 00 44 00 30 00 33 00 2d 00 34 00 30 00 32 00 33 00 2d 00 42 00 37 00 35 00 33 00 2d 00 46 00 45 00 44 00 36 00 41 00 33 00 31 00 44 00 39 00 35 00 43 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_BrowserPass : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jabiel/BrowserPass"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		id = "bad36c36-dbed-527c-a2f5-4dceff1abe4b"

	strings:
		$typelibguid0lo = {((33 63 62 35 39 38 37 31 2d 30 64 63 65 2d 34 35 33 62 2d 38 35 37 61 2d 32 64 31 65 35 31 35 62 30 62 36 36) | (33 00 63 00 62 00 35 00 39 00 38 00 37 00 31 00 2d 00 30 00 64 00 63 00 65 00 2d 00 34 00 35 00 33 00 62 00 2d 00 38 00 35 00 37 00 61 00 2d 00 32 00 64 00 31 00 65 00 35 00 31 00 35 00 62 00 30 00 62 00 36 00 36 00))}
		$typelibguid0up = {((33 43 42 35 39 38 37 31 2d 30 44 43 45 2d 34 35 33 42 2d 38 35 37 41 2d 32 44 31 45 35 31 35 42 30 42 36 36) | (33 00 43 00 42 00 35 00 39 00 38 00 37 00 31 00 2d 00 30 00 44 00 43 00 45 00 2d 00 34 00 35 00 33 00 42 00 2d 00 38 00 35 00 37 00 41 00 2d 00 32 00 44 00 31 00 45 00 35 00 31 00 35 00 42 00 30 00 42 00 36 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Mythic : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/its-a-feature/Mythic"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		id = "44237fac-1526-5587-83a1-61d7a54f7da9"

	strings:
		$typelibguid0lo = {((39 31 66 37 61 39 64 61 2d 66 30 34 35 2d 34 32 33 39 2d 61 31 65 39 2d 34 38 37 66 66 64 64 36 35 39 38 36) | (39 00 31 00 66 00 37 00 61 00 39 00 64 00 61 00 2d 00 66 00 30 00 34 00 35 00 2d 00 34 00 32 00 33 00 39 00 2d 00 61 00 31 00 65 00 39 00 2d 00 34 00 38 00 37 00 66 00 66 00 64 00 64 00 36 00 35 00 39 00 38 00 36 00))}
		$typelibguid0up = {((39 31 46 37 41 39 44 41 2d 46 30 34 35 2d 34 32 33 39 2d 41 31 45 39 2d 34 38 37 46 46 44 44 36 35 39 38 36) | (39 00 31 00 46 00 37 00 41 00 39 00 44 00 41 00 2d 00 46 00 30 00 34 00 35 00 2d 00 34 00 32 00 33 00 39 00 2d 00 41 00 31 00 45 00 39 00 2d 00 34 00 38 00 37 00 46 00 46 00 44 00 44 00 36 00 35 00 39 00 38 00 36 00))}
		$typelibguid1lo = {((30 34 30 35 32 30 35 63 2d 63 32 61 30 2d 34 66 39 61 2d 61 32 32 31 2d 34 38 62 35 63 37 30 64 66 33 62 36) | (30 00 34 00 30 00 35 00 32 00 30 00 35 00 63 00 2d 00 63 00 32 00 61 00 30 00 2d 00 34 00 66 00 39 00 61 00 2d 00 61 00 32 00 32 00 31 00 2d 00 34 00 38 00 62 00 35 00 63 00 37 00 30 00 64 00 66 00 33 00 62 00 36 00))}
		$typelibguid1up = {((30 34 30 35 32 30 35 43 2d 43 32 41 30 2d 34 46 39 41 2d 41 32 32 31 2d 34 38 42 35 43 37 30 44 46 33 42 36) | (30 00 34 00 30 00 35 00 32 00 30 00 35 00 43 00 2d 00 43 00 32 00 41 00 30 00 2d 00 34 00 46 00 39 00 41 00 2d 00 41 00 32 00 32 00 31 00 2d 00 34 00 38 00 42 00 35 00 43 00 37 00 30 00 44 00 46 00 33 00 42 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Nuages : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/p3nt4/Nuages"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		id = "5ad947e2-bd71-50d4-9bbf-4d018c7ff36a"

	strings:
		$typelibguid0lo = {((65 39 65 38 30 61 63 37 2d 34 63 31 33 2d 34 35 62 64 2d 39 62 64 65 2d 63 61 38 39 61 61 64 66 31 32 39 34) | (65 00 39 00 65 00 38 00 30 00 61 00 63 00 37 00 2d 00 34 00 63 00 31 00 33 00 2d 00 34 00 35 00 62 00 64 00 2d 00 39 00 62 00 64 00 65 00 2d 00 63 00 61 00 38 00 39 00 61 00 61 00 64 00 66 00 31 00 32 00 39 00 34 00))}
		$typelibguid0up = {((45 39 45 38 30 41 43 37 2d 34 43 31 33 2d 34 35 42 44 2d 39 42 44 45 2d 43 41 38 39 41 41 44 46 31 32 39 34) | (45 00 39 00 45 00 38 00 30 00 41 00 43 00 37 00 2d 00 34 00 43 00 31 00 33 00 2d 00 34 00 35 00 42 00 44 00 2d 00 39 00 42 00 44 00 45 00 2d 00 43 00 41 00 38 00 39 00 41 00 41 00 44 00 46 00 31 00 32 00 39 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpSniper : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/HunnicCyber/SharpSniper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		id = "14e6a3b8-5e1f-5dd8-9b51-22522ac317e7"

	strings:
		$typelibguid0lo = {((63 38 62 62 38 34 30 63 2d 30 34 63 65 2d 34 62 36 30 2d 61 37 33 34 2d 66 61 66 31 35 61 62 66 37 62 31 38) | (63 00 38 00 62 00 62 00 38 00 34 00 30 00 63 00 2d 00 30 00 34 00 63 00 65 00 2d 00 34 00 62 00 36 00 30 00 2d 00 61 00 37 00 33 00 34 00 2d 00 66 00 61 00 66 00 31 00 35 00 61 00 62 00 66 00 37 00 62 00 31 00 38 00))}
		$typelibguid0up = {((43 38 42 42 38 34 30 43 2d 30 34 43 45 2d 34 42 36 30 2d 41 37 33 34 2d 46 41 46 31 35 41 42 46 37 42 31 38) | (43 00 38 00 42 00 42 00 38 00 34 00 30 00 43 00 2d 00 30 00 34 00 43 00 45 00 2d 00 34 00 42 00 36 00 30 00 2d 00 41 00 37 00 33 00 34 00 2d 00 46 00 41 00 46 00 31 00 35 00 41 00 42 00 46 00 37 00 42 00 31 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpHound3 : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/BloodHoundAD/SharpHound3"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		id = "58001912-88a1-527d-9d3e-d7c376a1fce4"

	strings:
		$typelibguid0lo = {((61 35 31 37 61 38 64 65 2d 35 38 33 34 2d 34 31 31 64 2d 61 62 64 61 2d 32 64 30 65 31 37 36 36 35 33 39 63) | (61 00 35 00 31 00 37 00 61 00 38 00 64 00 65 00 2d 00 35 00 38 00 33 00 34 00 2d 00 34 00 31 00 31 00 64 00 2d 00 61 00 62 00 64 00 61 00 2d 00 32 00 64 00 30 00 65 00 31 00 37 00 36 00 36 00 35 00 33 00 39 00 63 00))}
		$typelibguid0up = {((41 35 31 37 41 38 44 45 2d 35 38 33 34 2d 34 31 31 44 2d 41 42 44 41 2d 32 44 30 45 31 37 36 36 35 33 39 43) | (41 00 35 00 31 00 37 00 41 00 38 00 44 00 45 00 2d 00 35 00 38 00 33 00 34 00 2d 00 34 00 31 00 31 00 44 00 2d 00 41 00 42 00 44 00 41 00 2d 00 32 00 44 00 30 00 45 00 31 00 37 00 36 00 36 00 35 00 33 00 39 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_BlockEtw : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Soledge/BlockEtw"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		id = "c2b72fef-6549-5b53-8ccf-232e8d152e96"

	strings:
		$typelibguid0lo = {((64 61 65 64 66 37 62 33 2d 38 32 36 32 2d 34 38 39 32 2d 61 64 63 34 2d 34 32 35 64 64 35 66 38 35 62 63 61) | (64 00 61 00 65 00 64 00 66 00 37 00 62 00 33 00 2d 00 38 00 32 00 36 00 32 00 2d 00 34 00 38 00 39 00 32 00 2d 00 61 00 64 00 63 00 34 00 2d 00 34 00 32 00 35 00 64 00 64 00 35 00 66 00 38 00 35 00 62 00 63 00 61 00))}
		$typelibguid0up = {((44 41 45 44 46 37 42 33 2d 38 32 36 32 2d 34 38 39 32 2d 41 44 43 34 2d 34 32 35 44 44 35 46 38 35 42 43 41) | (44 00 41 00 45 00 44 00 46 00 37 00 42 00 33 00 2d 00 38 00 32 00 36 00 32 00 2d 00 34 00 38 00 39 00 32 00 2d 00 41 00 44 00 43 00 34 00 2d 00 34 00 32 00 35 00 44 00 44 00 35 00 46 00 38 00 35 00 42 00 43 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpWifiGrabber : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/r3nhat/SharpWifiGrabber"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		id = "1a457672-743c-56f0-a4d7-6c25f9ce2345"

	strings:
		$typelibguid0lo = {((63 30 39 39 37 36 39 38 2d 32 62 37 33 2d 34 39 38 32 2d 62 32 35 62 2d 64 30 35 37 38 64 31 33 32 33 63 32) | (63 00 30 00 39 00 39 00 37 00 36 00 39 00 38 00 2d 00 32 00 62 00 37 00 33 00 2d 00 34 00 39 00 38 00 32 00 2d 00 62 00 32 00 35 00 62 00 2d 00 64 00 30 00 35 00 37 00 38 00 64 00 31 00 33 00 32 00 33 00 63 00 32 00))}
		$typelibguid0up = {((43 30 39 39 37 36 39 38 2d 32 42 37 33 2d 34 39 38 32 2d 42 32 35 42 2d 44 30 35 37 38 44 31 33 32 33 43 32) | (43 00 30 00 39 00 39 00 37 00 36 00 39 00 38 00 2d 00 32 00 42 00 37 00 33 00 2d 00 34 00 39 00 38 00 32 00 2d 00 42 00 32 00 35 00 42 00 2d 00 44 00 30 00 35 00 37 00 38 00 44 00 31 00 33 00 32 00 33 00 43 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpMapExec : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/cube0x0/SharpMapExec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		id = "b4922734-a486-5c4d-9bd7-5146cfecbf01"

	strings:
		$typelibguid0lo = {((62 64 35 32 32 30 66 37 2d 65 31 66 62 2d 34 31 64 32 2d 39 31 65 63 2d 65 34 63 35 30 63 36 65 39 62 39 66) | (62 00 64 00 35 00 32 00 32 00 30 00 66 00 37 00 2d 00 65 00 31 00 66 00 62 00 2d 00 34 00 31 00 64 00 32 00 2d 00 39 00 31 00 65 00 63 00 2d 00 65 00 34 00 63 00 35 00 30 00 63 00 36 00 65 00 39 00 62 00 39 00 66 00))}
		$typelibguid0up = {((42 44 35 32 32 30 46 37 2d 45 31 46 42 2d 34 31 44 32 2d 39 31 45 43 2d 45 34 43 35 30 43 36 45 39 42 39 46) | (42 00 44 00 35 00 32 00 32 00 30 00 46 00 37 00 2d 00 45 00 31 00 46 00 42 00 2d 00 34 00 31 00 44 00 32 00 2d 00 39 00 31 00 45 00 43 00 2d 00 45 00 34 00 43 00 35 00 30 00 43 00 36 00 45 00 39 00 42 00 39 00 46 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_k8fly : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/zzwlpx/k8fly"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		id = "3421e6fb-df65-5e2e-ae46-37f9c763c6a1"

	strings:
		$typelibguid0lo = {((31 33 62 36 63 38 34 33 2d 66 33 64 34 2d 34 35 38 35 2d 62 34 66 33 2d 65 32 36 37 32 61 34 37 39 33 31 65) | (31 00 33 00 62 00 36 00 63 00 38 00 34 00 33 00 2d 00 66 00 33 00 64 00 34 00 2d 00 34 00 35 00 38 00 35 00 2d 00 62 00 34 00 66 00 33 00 2d 00 65 00 32 00 36 00 37 00 32 00 61 00 34 00 37 00 39 00 33 00 31 00 65 00))}
		$typelibguid0up = {((31 33 42 36 43 38 34 33 2d 46 33 44 34 2d 34 35 38 35 2d 42 34 46 33 2d 45 32 36 37 32 41 34 37 39 33 31 45) | (31 00 33 00 42 00 36 00 43 00 38 00 34 00 33 00 2d 00 46 00 33 00 44 00 34 00 2d 00 34 00 35 00 38 00 35 00 2d 00 42 00 34 00 46 00 33 00 2d 00 45 00 32 00 36 00 37 00 32 00 41 00 34 00 37 00 39 00 33 00 31 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Stealer : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/malwares/Stealer"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		id = "c721a0ac-e898-52aa-9bdf-a19bc0bd783d"

	strings:
		$typelibguid0lo = {((38 66 63 64 34 39 33 31 2d 39 31 61 32 2d 34 65 31 38 2d 38 34 39 62 2d 37 30 64 65 33 34 61 62 37 35 64 66) | (38 00 66 00 63 00 64 00 34 00 39 00 33 00 31 00 2d 00 39 00 31 00 61 00 32 00 2d 00 34 00 65 00 31 00 38 00 2d 00 38 00 34 00 39 00 62 00 2d 00 37 00 30 00 64 00 65 00 33 00 34 00 61 00 62 00 37 00 35 00 64 00 66 00))}
		$typelibguid0up = {((38 46 43 44 34 39 33 31 2d 39 31 41 32 2d 34 45 31 38 2d 38 34 39 42 2d 37 30 44 45 33 34 41 42 37 35 44 46) | (38 00 46 00 43 00 44 00 34 00 39 00 33 00 31 00 2d 00 39 00 31 00 41 00 32 00 2d 00 34 00 45 00 31 00 38 00 2d 00 38 00 34 00 39 00 42 00 2d 00 37 00 30 00 44 00 45 00 33 00 34 00 41 00 42 00 37 00 35 00 44 00 46 00))}
		$typelibguid1lo = {((65 34 38 38 31 31 63 61 2d 38 61 66 38 2d 34 65 37 33 2d 38 35 64 64 2d 32 30 34 35 62 39 63 63 61 37 33 61) | (65 00 34 00 38 00 38 00 31 00 31 00 63 00 61 00 2d 00 38 00 61 00 66 00 38 00 2d 00 34 00 65 00 37 00 33 00 2d 00 38 00 35 00 64 00 64 00 2d 00 32 00 30 00 34 00 35 00 62 00 39 00 63 00 63 00 61 00 37 00 33 00 61 00))}
		$typelibguid1up = {((45 34 38 38 31 31 43 41 2d 38 41 46 38 2d 34 45 37 33 2d 38 35 44 44 2d 32 30 34 35 42 39 43 43 41 37 33 41) | (45 00 34 00 38 00 38 00 31 00 31 00 43 00 41 00 2d 00 38 00 41 00 46 00 38 00 2d 00 34 00 45 00 37 00 33 00 2d 00 38 00 35 00 44 00 44 00 2d 00 32 00 30 00 34 00 35 00 42 00 39 00 43 00 43 00 41 00 37 00 33 00 41 00))}
		$typelibguid2lo = {((64 33 64 38 61 31 63 63 2d 65 31 32 33 2d 34 39 30 35 2d 62 33 64 65 2d 33 37 34 37 34 39 31 32 32 66 63 66) | (64 00 33 00 64 00 38 00 61 00 31 00 63 00 63 00 2d 00 65 00 31 00 32 00 33 00 2d 00 34 00 39 00 30 00 35 00 2d 00 62 00 33 00 64 00 65 00 2d 00 33 00 37 00 34 00 37 00 34 00 39 00 31 00 32 00 32 00 66 00 63 00 66 00))}
		$typelibguid2up = {((44 33 44 38 41 31 43 43 2d 45 31 32 33 2d 34 39 30 35 2d 42 33 44 45 2d 33 37 34 37 34 39 31 32 32 46 43 46) | (44 00 33 00 44 00 38 00 41 00 31 00 43 00 43 00 2d 00 45 00 31 00 32 00 33 00 2d 00 34 00 39 00 30 00 35 00 2d 00 42 00 33 00 44 00 45 00 2d 00 33 00 37 00 34 00 37 00 34 00 39 00 31 00 32 00 32 00 46 00 43 00 46 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_PortTran : hardened
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/k8gege/PortTran"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		id = "844e58a2-54f5-51e8-8176-6a478a136603"

	strings:
		$typelibguid0lo = {((33 61 30 37 34 33 37 34 2d 37 37 65 38 2d 34 33 31 32 2d 38 37 34 36 2d 33 37 66 33 63 62 30 30 65 38 32 63) | (33 00 61 00 30 00 37 00 34 00 33 00 37 00 34 00 2d 00 37 00 37 00 65 00 38 00 2d 00 34 00 33 00 31 00 32 00 2d 00 38 00 37 00 34 00 36 00 2d 00 33 00 37 00 66 00 33 00 63 00 62 00 30 00 30 00 65 00 38 00 32 00 63 00))}
		$typelibguid0up = {((33 41 30 37 34 33 37 34 2d 37 37 45 38 2d 34 33 31 32 2d 38 37 34 36 2d 33 37 46 33 43 42 30 30 45 38 32 43) | (33 00 41 00 30 00 37 00 34 00 33 00 37 00 34 00 2d 00 37 00 37 00 45 00 38 00 2d 00 34 00 33 00 31 00 32 00 2d 00 38 00 37 00 34 00 36 00 2d 00 33 00 37 00 46 00 33 00 43 00 42 00 30 00 30 00 45 00 38 00 32 00 43 00))}
		$typelibguid1lo = {((36 37 61 37 33 62 61 63 2d 66 35 39 64 2d 34 32 32 37 2d 39 32 32 30 2d 65 32 30 61 32 65 66 34 32 37 38 32) | (36 00 37 00 61 00 37 00 33 00 62 00 61 00 63 00 2d 00 66 00 35 00 39 00 64 00 2d 00 34 00 32 00 32 00 37 00 2d 00 39 00 32 00 32 00 30 00 2d 00 65 00 32 00 30 00 61 00 32 00 65 00 66 00 34 00 32 00 37 00 38 00 32 00))}
		$typelibguid1up = {((36 37 41 37 33 42 41 43 2d 46 35 39 44 2d 34 32 32 37 2d 39 32 32 30 2d 45 32 30 41 32 45 46 34 32 37 38 32) | (36 00 37 00 41 00 37 00 33 00 42 00 41 00 43 00 2d 00 46 00 35 00 39 00 44 00 2d 00 34 00 32 00 32 00 37 00 2d 00 39 00 32 00 32 00 30 00 2d 00 45 00 32 00 30 00 41 00 32 00 45 00 46 00 34 00 32 00 37 00 38 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_gray_keylogger_2 : hardened
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		reference = "https://github.com/graysuit/gray-keylogger-2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-30"
		modified = "2023-04-06"
		id = "40ab8103-9151-5a5c-8b70-ab3bfd3896f9"

	strings:
		$typelibguid0lo = {((65 39 34 63 61 33 66 66 2d 63 30 65 35 2d 34 64 31 61 2d 61 64 35 65 2d 66 36 65 62 62 65 33 36 35 30 36 37) | (65 00 39 00 34 00 63 00 61 00 33 00 66 00 66 00 2d 00 63 00 30 00 65 00 35 00 2d 00 34 00 64 00 31 00 61 00 2d 00 61 00 64 00 35 00 65 00 2d 00 66 00 36 00 65 00 62 00 62 00 65 00 33 00 36 00 35 00 30 00 36 00 37 00))}
		$typelibguid0up = {((45 39 34 43 41 33 46 46 2d 43 30 45 35 2d 34 44 31 41 2d 41 44 35 45 2d 46 36 45 42 42 45 33 36 35 30 36 37) | (45 00 39 00 34 00 43 00 41 00 33 00 46 00 46 00 2d 00 43 00 30 00 45 00 35 00 2d 00 34 00 44 00 31 00 41 00 2d 00 41 00 44 00 35 00 45 00 2d 00 46 00 36 00 45 00 42 00 42 00 45 00 33 00 36 00 35 00 30 00 36 00 37 00))}
		$typelibguid1lo = {((31 65 64 30 37 35 36 34 2d 62 34 31 31 2d 34 36 32 36 2d 38 38 65 35 2d 65 31 63 64 38 65 63 64 38 36 30 61) | (31 00 65 00 64 00 30 00 37 00 35 00 36 00 34 00 2d 00 62 00 34 00 31 00 31 00 2d 00 34 00 36 00 32 00 36 00 2d 00 38 00 38 00 65 00 35 00 2d 00 65 00 31 00 63 00 64 00 38 00 65 00 63 00 64 00 38 00 36 00 30 00 61 00))}
		$typelibguid1up = {((31 45 44 30 37 35 36 34 2d 42 34 31 31 2d 34 36 32 36 2d 38 38 45 35 2d 45 31 43 44 38 45 43 44 38 36 30 41) | (31 00 45 00 44 00 30 00 37 00 35 00 36 00 34 00 2d 00 42 00 34 00 31 00 31 00 2d 00 34 00 36 00 32 00 36 00 2d 00 38 00 38 00 45 00 35 00 2d 00 45 00 31 00 43 00 44 00 38 00 45 00 43 00 44 00 38 00 36 00 30 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Lime_Miner : hardened
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Lime-Miner"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-30"
		modified = "2023-04-06"
		id = "d0631817-10a2-55bf-a41d-226fa0dcb9f9"

	strings:
		$typelibguid0lo = {((31 33 39 35 38 66 62 39 2d 64 66 63 31 2d 34 65 32 63 2d 38 61 38 64 2d 61 35 65 36 38 61 62 64 62 63 36 36) | (31 00 33 00 39 00 35 00 38 00 66 00 62 00 39 00 2d 00 64 00 66 00 63 00 31 00 2d 00 34 00 65 00 32 00 63 00 2d 00 38 00 61 00 38 00 64 00 2d 00 61 00 35 00 65 00 36 00 38 00 61 00 62 00 64 00 62 00 63 00 36 00 36 00))}
		$typelibguid0up = {((31 33 39 35 38 46 42 39 2d 44 46 43 31 2d 34 45 32 43 2d 38 41 38 44 2d 41 35 45 36 38 41 42 44 42 43 36 36) | (31 00 33 00 39 00 35 00 38 00 46 00 42 00 39 00 2d 00 44 00 46 00 43 00 31 00 2d 00 34 00 45 00 32 00 43 00 2d 00 38 00 41 00 38 00 44 00 2d 00 41 00 35 00 45 00 36 00 38 00 41 00 42 00 44 00 42 00 43 00 36 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_BlackNET : hardened
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		reference = "https://github.com/BlackHacker511/BlackNET"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-30"
		modified = "2023-04-06"
		id = "9fbb3c11-7b11-5910-9c8b-247aeefbaa87"

	strings:
		$typelibguid0lo = {((63 32 62 39 30 38 38 33 2d 61 62 65 65 2d 34 63 66 61 2d 61 66 36 36 2d 64 66 64 39 33 65 63 36 31 37 61 35) | (63 00 32 00 62 00 39 00 30 00 38 00 38 00 33 00 2d 00 61 00 62 00 65 00 65 00 2d 00 34 00 63 00 66 00 61 00 2d 00 61 00 66 00 36 00 36 00 2d 00 64 00 66 00 64 00 39 00 33 00 65 00 63 00 36 00 31 00 37 00 61 00 35 00))}
		$typelibguid0up = {((43 32 42 39 30 38 38 33 2d 41 42 45 45 2d 34 43 46 41 2d 41 46 36 36 2d 44 46 44 39 33 45 43 36 31 37 41 35) | (43 00 32 00 42 00 39 00 30 00 38 00 38 00 33 00 2d 00 41 00 42 00 45 00 45 00 2d 00 34 00 43 00 46 00 41 00 2d 00 41 00 46 00 36 00 36 00 2d 00 44 00 46 00 44 00 39 00 33 00 45 00 43 00 36 00 31 00 37 00 41 00 35 00))}
		$typelibguid1lo = {((38 62 62 36 66 35 62 34 2d 65 37 63 37 2d 34 35 35 34 2d 61 66 64 31 2d 34 38 66 33 36 38 37 37 34 38 33 37) | (38 00 62 00 62 00 36 00 66 00 35 00 62 00 34 00 2d 00 65 00 37 00 63 00 37 00 2d 00 34 00 35 00 35 00 34 00 2d 00 61 00 66 00 64 00 31 00 2d 00 34 00 38 00 66 00 33 00 36 00 38 00 37 00 37 00 34 00 38 00 33 00 37 00))}
		$typelibguid1up = {((38 42 42 36 46 35 42 34 2d 45 37 43 37 2d 34 35 35 34 2d 41 46 44 31 2d 34 38 46 33 36 38 37 37 34 38 33 37) | (38 00 42 00 42 00 36 00 46 00 35 00 42 00 34 00 2d 00 45 00 37 00 43 00 37 00 2d 00 34 00 35 00 35 00 34 00 2d 00 41 00 46 00 44 00 31 00 2d 00 34 00 38 00 46 00 33 00 36 00 38 00 37 00 37 00 34 00 38 00 33 00 37 00))}
		$typelibguid2lo = {((39 38 33 61 65 32 38 63 2d 39 31 63 33 2d 34 30 37 32 2d 38 63 64 66 2d 36 39 38 62 32 66 66 37 61 39 36 37) | (39 00 38 00 33 00 61 00 65 00 32 00 38 00 63 00 2d 00 39 00 31 00 63 00 33 00 2d 00 34 00 30 00 37 00 32 00 2d 00 38 00 63 00 64 00 66 00 2d 00 36 00 39 00 38 00 62 00 32 00 66 00 66 00 37 00 61 00 39 00 36 00 37 00))}
		$typelibguid2up = {((39 38 33 41 45 32 38 43 2d 39 31 43 33 2d 34 30 37 32 2d 38 43 44 46 2d 36 39 38 42 32 46 46 37 41 39 36 37) | (39 00 38 00 33 00 41 00 45 00 32 00 38 00 43 00 2d 00 39 00 31 00 43 00 33 00 2d 00 34 00 30 00 37 00 32 00 2d 00 38 00 43 00 44 00 46 00 2d 00 36 00 39 00 38 00 42 00 32 00 46 00 46 00 37 00 41 00 39 00 36 00 37 00))}
		$typelibguid3lo = {((39 61 63 31 38 63 64 63 2d 33 37 31 31 2d 34 37 31 39 2d 39 63 66 62 2d 35 62 35 66 32 64 35 31 66 64 35 61) | (39 00 61 00 63 00 31 00 38 00 63 00 64 00 63 00 2d 00 33 00 37 00 31 00 31 00 2d 00 34 00 37 00 31 00 39 00 2d 00 39 00 63 00 66 00 62 00 2d 00 35 00 62 00 35 00 66 00 32 00 64 00 35 00 31 00 66 00 64 00 35 00 61 00))}
		$typelibguid3up = {((39 41 43 31 38 43 44 43 2d 33 37 31 31 2d 34 37 31 39 2d 39 43 46 42 2d 35 42 35 46 32 44 35 31 46 44 35 41) | (39 00 41 00 43 00 31 00 38 00 43 00 44 00 43 00 2d 00 33 00 37 00 31 00 31 00 2d 00 34 00 37 00 31 00 39 00 2d 00 39 00 43 00 46 00 42 00 2d 00 35 00 42 00 35 00 46 00 32 00 44 00 35 00 31 00 46 00 44 00 35 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_PlasmaRAT : hardened
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		reference = "https://github.com/mwsrc/PlasmaRAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-30"
		modified = "2023-04-06"
		id = "13362cba-f9b2-50c8-95cc-504e585bdd42"

	strings:
		$typelibguid0lo = {((62 38 61 32 31 34 37 63 2d 30 37 34 63 2d 34 36 65 31 2d 62 62 39 39 2d 63 38 34 33 31 61 36 35 34 36 63 65) | (62 00 38 00 61 00 32 00 31 00 34 00 37 00 63 00 2d 00 30 00 37 00 34 00 63 00 2d 00 34 00 36 00 65 00 31 00 2d 00 62 00 62 00 39 00 39 00 2d 00 63 00 38 00 34 00 33 00 31 00 61 00 36 00 35 00 34 00 36 00 63 00 65 00))}
		$typelibguid0up = {((42 38 41 32 31 34 37 43 2d 30 37 34 43 2d 34 36 45 31 2d 42 42 39 39 2d 43 38 34 33 31 41 36 35 34 36 43 45) | (42 00 38 00 41 00 32 00 31 00 34 00 37 00 43 00 2d 00 30 00 37 00 34 00 43 00 2d 00 34 00 36 00 45 00 31 00 2d 00 42 00 42 00 39 00 39 00 2d 00 43 00 38 00 34 00 33 00 31 00 41 00 36 00 35 00 34 00 36 00 43 00 45 00))}
		$typelibguid1lo = {((30 66 63 66 64 65 33 33 2d 32 31 33 66 2d 34 66 62 36 2d 61 63 31 35 2d 65 66 62 32 30 33 39 33 64 34 66 33) | (30 00 66 00 63 00 66 00 64 00 65 00 33 00 33 00 2d 00 32 00 31 00 33 00 66 00 2d 00 34 00 66 00 62 00 36 00 2d 00 61 00 63 00 31 00 35 00 2d 00 65 00 66 00 62 00 32 00 30 00 33 00 39 00 33 00 64 00 34 00 66 00 33 00))}
		$typelibguid1up = {((30 46 43 46 44 45 33 33 2d 32 31 33 46 2d 34 46 42 36 2d 41 43 31 35 2d 45 46 42 32 30 33 39 33 44 34 46 33) | (30 00 46 00 43 00 46 00 44 00 45 00 33 00 33 00 2d 00 32 00 31 00 33 00 46 00 2d 00 34 00 46 00 42 00 36 00 2d 00 41 00 43 00 31 00 35 00 2d 00 45 00 46 00 42 00 32 00 30 00 33 00 39 00 33 00 44 00 34 00 46 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Lime_RAT : hardened
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Lime-RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-30"
		modified = "2023-04-06"
		id = "31a0e9ca-9da1-557a-bcc5-1351fa90a0e1"

	strings:
		$typelibguid0lo = {((65 35 38 61 63 34 34 37 2d 61 62 30 37 2d 34 30 32 61 2d 39 63 39 36 2d 39 35 65 32 38 34 61 37 36 61 38 64) | (65 00 35 00 38 00 61 00 63 00 34 00 34 00 37 00 2d 00 61 00 62 00 30 00 37 00 2d 00 34 00 30 00 32 00 61 00 2d 00 39 00 63 00 39 00 36 00 2d 00 39 00 35 00 65 00 32 00 38 00 34 00 61 00 37 00 36 00 61 00 38 00 64 00))}
		$typelibguid0up = {((45 35 38 41 43 34 34 37 2d 41 42 30 37 2d 34 30 32 41 2d 39 43 39 36 2d 39 35 45 32 38 34 41 37 36 41 38 44) | (45 00 35 00 38 00 41 00 43 00 34 00 34 00 37 00 2d 00 41 00 42 00 30 00 37 00 2d 00 34 00 30 00 32 00 41 00 2d 00 39 00 43 00 39 00 36 00 2d 00 39 00 35 00 45 00 32 00 38 00 34 00 41 00 37 00 36 00 41 00 38 00 44 00))}
		$typelibguid1lo = {((38 66 62 33 35 64 61 62 2d 37 33 63 64 2d 34 31 36 33 2d 38 38 36 38 2d 63 34 64 62 63 62 64 66 30 63 31 37) | (38 00 66 00 62 00 33 00 35 00 64 00 61 00 62 00 2d 00 37 00 33 00 63 00 64 00 2d 00 34 00 31 00 36 00 33 00 2d 00 38 00 38 00 36 00 38 00 2d 00 63 00 34 00 64 00 62 00 63 00 62 00 64 00 66 00 30 00 63 00 31 00 37 00))}
		$typelibguid1up = {((38 46 42 33 35 44 41 42 2d 37 33 43 44 2d 34 31 36 33 2d 38 38 36 38 2d 43 34 44 42 43 42 44 46 30 43 31 37) | (38 00 46 00 42 00 33 00 35 00 44 00 41 00 42 00 2d 00 37 00 33 00 43 00 44 00 2d 00 34 00 31 00 36 00 33 00 2d 00 38 00 38 00 36 00 38 00 2d 00 43 00 34 00 44 00 42 00 43 00 42 00 44 00 46 00 30 00 43 00 31 00 37 00))}
		$typelibguid2lo = {((33 37 38 34 35 66 35 62 2d 33 35 66 65 2d 34 64 63 65 2d 62 62 65 63 2d 32 64 30 37 63 37 39 30 34 66 62 30) | (33 00 37 00 38 00 34 00 35 00 66 00 35 00 62 00 2d 00 33 00 35 00 66 00 65 00 2d 00 34 00 64 00 63 00 65 00 2d 00 62 00 62 00 65 00 63 00 2d 00 32 00 64 00 30 00 37 00 63 00 37 00 39 00 30 00 34 00 66 00 62 00 30 00))}
		$typelibguid2up = {((33 37 38 34 35 46 35 42 2d 33 35 46 45 2d 34 44 43 45 2d 42 42 45 43 2d 32 44 30 37 43 37 39 30 34 46 42 30) | (33 00 37 00 38 00 34 00 35 00 46 00 35 00 42 00 2d 00 33 00 35 00 46 00 45 00 2d 00 34 00 44 00 43 00 45 00 2d 00 42 00 42 00 45 00 43 00 2d 00 32 00 44 00 30 00 37 00 43 00 37 00 39 00 30 00 34 00 46 00 42 00 30 00))}
		$typelibguid3lo = {((38 33 63 34 35 33 63 66 2d 30 64 32 39 2d 34 36 39 30 2d 62 39 64 63 2d 35 36 37 66 32 30 65 36 33 38 39 34) | (38 00 33 00 63 00 34 00 35 00 33 00 63 00 66 00 2d 00 30 00 64 00 32 00 39 00 2d 00 34 00 36 00 39 00 30 00 2d 00 62 00 39 00 64 00 63 00 2d 00 35 00 36 00 37 00 66 00 32 00 30 00 65 00 36 00 33 00 38 00 39 00 34 00))}
		$typelibguid3up = {((38 33 43 34 35 33 43 46 2d 30 44 32 39 2d 34 36 39 30 2d 42 39 44 43 2d 35 36 37 46 32 30 45 36 33 38 39 34) | (38 00 33 00 43 00 34 00 35 00 33 00 43 00 46 00 2d 00 30 00 44 00 32 00 39 00 2d 00 34 00 36 00 39 00 30 00 2d 00 42 00 39 00 44 00 43 00 2d 00 35 00 36 00 37 00 46 00 32 00 30 00 45 00 36 00 33 00 38 00 39 00 34 00))}
		$typelibguid4lo = {((38 62 31 66 30 61 36 39 2d 61 39 33 30 2d 34 32 65 33 2d 39 63 31 33 2d 37 64 65 30 64 30 34 61 34 61 64 64) | (38 00 62 00 31 00 66 00 30 00 61 00 36 00 39 00 2d 00 61 00 39 00 33 00 30 00 2d 00 34 00 32 00 65 00 33 00 2d 00 39 00 63 00 31 00 33 00 2d 00 37 00 64 00 65 00 30 00 64 00 30 00 34 00 61 00 34 00 61 00 64 00 64 00))}
		$typelibguid4up = {((38 42 31 46 30 41 36 39 2d 41 39 33 30 2d 34 32 45 33 2d 39 43 31 33 2d 37 44 45 30 44 30 34 41 34 41 44 44) | (38 00 42 00 31 00 46 00 30 00 41 00 36 00 39 00 2d 00 41 00 39 00 33 00 30 00 2d 00 34 00 32 00 45 00 33 00 2d 00 39 00 43 00 31 00 33 00 2d 00 37 00 44 00 45 00 30 00 44 00 30 00 34 00 41 00 34 00 41 00 44 00 44 00))}
		$typelibguid5lo = {((65 61 61 65 63 63 66 36 2d 37 35 64 32 2d 34 36 31 36 2d 62 30 34 35 2d 33 36 65 65 61 30 39 63 38 62 32 38) | (65 00 61 00 61 00 65 00 63 00 63 00 66 00 36 00 2d 00 37 00 35 00 64 00 32 00 2d 00 34 00 36 00 31 00 36 00 2d 00 62 00 30 00 34 00 35 00 2d 00 33 00 36 00 65 00 65 00 61 00 30 00 39 00 63 00 38 00 62 00 32 00 38 00))}
		$typelibguid5up = {((45 41 41 45 43 43 46 36 2d 37 35 44 32 2d 34 36 31 36 2d 42 30 34 35 2d 33 36 45 45 41 30 39 43 38 42 32 38) | (45 00 41 00 41 00 45 00 43 00 43 00 46 00 36 00 2d 00 37 00 35 00 44 00 32 00 2d 00 34 00 36 00 31 00 36 00 2d 00 42 00 30 00 34 00 35 00 2d 00 33 00 36 00 45 00 45 00 41 00 30 00 39 00 43 00 38 00 42 00 32 00 38 00))}
		$typelibguid6lo = {((35 62 32 65 63 36 37 34 2d 30 61 61 34 2d 34 32 30 39 2d 39 34 64 66 2d 62 36 63 39 39 35 61 64 35 39 63 34) | (35 00 62 00 32 00 65 00 63 00 36 00 37 00 34 00 2d 00 30 00 61 00 61 00 34 00 2d 00 34 00 32 00 30 00 39 00 2d 00 39 00 34 00 64 00 66 00 2d 00 62 00 36 00 63 00 39 00 39 00 35 00 61 00 64 00 35 00 39 00 63 00 34 00))}
		$typelibguid6up = {((35 42 32 45 43 36 37 34 2d 30 41 41 34 2d 34 32 30 39 2d 39 34 44 46 2d 42 36 43 39 39 35 41 44 35 39 43 34) | (35 00 42 00 32 00 45 00 43 00 36 00 37 00 34 00 2d 00 30 00 41 00 41 00 34 00 2d 00 34 00 32 00 30 00 39 00 2d 00 39 00 34 00 44 00 46 00 2d 00 42 00 36 00 43 00 39 00 39 00 35 00 41 00 44 00 35 00 39 00 43 00 34 00))}
		$typelibguid7lo = {((65 32 63 63 37 31 35 38 2d 61 65 65 36 2d 34 34 36 33 2d 39 35 62 66 2d 66 62 35 32 39 35 65 39 65 33 37 61) | (65 00 32 00 63 00 63 00 37 00 31 00 35 00 38 00 2d 00 61 00 65 00 65 00 36 00 2d 00 34 00 34 00 36 00 33 00 2d 00 39 00 35 00 62 00 66 00 2d 00 66 00 62 00 35 00 32 00 39 00 35 00 65 00 39 00 65 00 33 00 37 00 61 00))}
		$typelibguid7up = {((45 32 43 43 37 31 35 38 2d 41 45 45 36 2d 34 34 36 33 2d 39 35 42 46 2d 46 42 35 32 39 35 45 39 45 33 37 41) | (45 00 32 00 43 00 43 00 37 00 31 00 35 00 38 00 2d 00 41 00 45 00 45 00 36 00 2d 00 34 00 34 00 36 00 33 00 2d 00 39 00 35 00 42 00 46 00 2d 00 46 00 42 00 35 00 32 00 39 00 35 00 45 00 39 00 45 00 33 00 37 00 41 00))}
		$typelibguid8lo = {((64 30 34 65 63 66 36 32 2d 36 64 61 39 2d 34 33 30 38 2d 38 30 34 61 2d 65 37 38 39 62 61 61 35 63 63 33 38) | (64 00 30 00 34 00 65 00 63 00 66 00 36 00 32 00 2d 00 36 00 64 00 61 00 39 00 2d 00 34 00 33 00 30 00 38 00 2d 00 38 00 30 00 34 00 61 00 2d 00 65 00 37 00 38 00 39 00 62 00 61 00 61 00 35 00 63 00 63 00 33 00 38 00))}
		$typelibguid8up = {((44 30 34 45 43 46 36 32 2d 36 44 41 39 2d 34 33 30 38 2d 38 30 34 41 2d 45 37 38 39 42 41 41 35 43 43 33 38) | (44 00 30 00 34 00 45 00 43 00 46 00 36 00 32 00 2d 00 36 00 44 00 41 00 39 00 2d 00 34 00 33 00 30 00 38 00 2d 00 38 00 30 00 34 00 41 00 2d 00 45 00 37 00 38 00 39 00 42 00 41 00 41 00 35 00 43 00 43 00 33 00 38 00))}
		$typelibguid9lo = {((38 30 32 36 32 36 31 66 2d 61 63 36 38 2d 34 63 63 66 2d 39 37 62 32 2d 33 62 35 35 62 37 64 36 36 38 34 64) | (38 00 30 00 32 00 36 00 32 00 36 00 31 00 66 00 2d 00 61 00 63 00 36 00 38 00 2d 00 34 00 63 00 63 00 66 00 2d 00 39 00 37 00 62 00 32 00 2d 00 33 00 62 00 35 00 35 00 62 00 37 00 64 00 36 00 36 00 38 00 34 00 64 00))}
		$typelibguid9up = {((38 30 32 36 32 36 31 46 2d 41 43 36 38 2d 34 43 43 46 2d 39 37 42 32 2d 33 42 35 35 42 37 44 36 36 38 34 44) | (38 00 30 00 32 00 36 00 32 00 36 00 31 00 46 00 2d 00 41 00 43 00 36 00 38 00 2d 00 34 00 43 00 43 00 46 00 2d 00 39 00 37 00 42 00 32 00 2d 00 33 00 42 00 35 00 35 00 42 00 37 00 44 00 36 00 36 00 38 00 34 00 44 00))}
		$typelibguid10lo = {((32 31 32 63 64 66 61 63 2d 35 31 66 31 2d 34 30 34 35 2d 61 35 63 30 2d 36 65 36 33 38 66 38 39 66 63 65 30) | (32 00 31 00 32 00 63 00 64 00 66 00 61 00 63 00 2d 00 35 00 31 00 66 00 31 00 2d 00 34 00 30 00 34 00 35 00 2d 00 61 00 35 00 63 00 30 00 2d 00 36 00 65 00 36 00 33 00 38 00 66 00 38 00 39 00 66 00 63 00 65 00 30 00))}
		$typelibguid10up = {((32 31 32 43 44 46 41 43 2d 35 31 46 31 2d 34 30 34 35 2d 41 35 43 30 2d 36 45 36 33 38 46 38 39 46 43 45 30) | (32 00 31 00 32 00 43 00 44 00 46 00 41 00 43 00 2d 00 35 00 31 00 46 00 31 00 2d 00 34 00 30 00 34 00 35 00 2d 00 41 00 35 00 43 00 30 00 2d 00 36 00 45 00 36 00 33 00 38 00 46 00 38 00 39 00 46 00 43 00 45 00 30 00))}
		$typelibguid11lo = {((63 31 62 36 30 38 62 62 2d 37 61 65 64 2d 34 38 38 64 2d 61 61 33 62 2d 30 63 39 36 36 32 35 64 32 36 63 30) | (63 00 31 00 62 00 36 00 30 00 38 00 62 00 62 00 2d 00 37 00 61 00 65 00 64 00 2d 00 34 00 38 00 38 00 64 00 2d 00 61 00 61 00 33 00 62 00 2d 00 30 00 63 00 39 00 36 00 36 00 32 00 35 00 64 00 32 00 36 00 63 00 30 00))}
		$typelibguid11up = {((43 31 42 36 30 38 42 42 2d 37 41 45 44 2d 34 38 38 44 2d 41 41 33 42 2d 30 43 39 36 36 32 35 44 32 36 43 30) | (43 00 31 00 42 00 36 00 30 00 38 00 42 00 42 00 2d 00 37 00 41 00 45 00 44 00 2d 00 34 00 38 00 38 00 44 00 2d 00 41 00 41 00 33 00 42 00 2d 00 30 00 43 00 39 00 36 00 36 00 32 00 35 00 44 00 32 00 36 00 43 00 30 00))}
		$typelibguid12lo = {((34 63 38 34 65 37 65 63 2d 66 31 39 37 2d 34 33 32 31 2d 38 38 36 32 2d 64 35 64 31 38 37 38 33 65 32 66 65) | (34 00 63 00 38 00 34 00 65 00 37 00 65 00 63 00 2d 00 66 00 31 00 39 00 37 00 2d 00 34 00 33 00 32 00 31 00 2d 00 38 00 38 00 36 00 32 00 2d 00 64 00 35 00 64 00 31 00 38 00 37 00 38 00 33 00 65 00 32 00 66 00 65 00))}
		$typelibguid12up = {((34 43 38 34 45 37 45 43 2d 46 31 39 37 2d 34 33 32 31 2d 38 38 36 32 2d 44 35 44 31 38 37 38 33 45 32 46 45) | (34 00 43 00 38 00 34 00 45 00 37 00 45 00 43 00 2d 00 46 00 31 00 39 00 37 00 2d 00 34 00 33 00 32 00 31 00 2d 00 38 00 38 00 36 00 32 00 2d 00 44 00 35 00 44 00 31 00 38 00 37 00 38 00 33 00 45 00 32 00 46 00 45 00))}
		$typelibguid13lo = {((33 66 63 31 37 61 64 62 2d 36 37 64 34 2d 34 61 38 64 2d 38 37 37 30 2d 65 63 66 64 38 31 35 66 37 33 65 65) | (33 00 66 00 63 00 31 00 37 00 61 00 64 00 62 00 2d 00 36 00 37 00 64 00 34 00 2d 00 34 00 61 00 38 00 64 00 2d 00 38 00 37 00 37 00 30 00 2d 00 65 00 63 00 66 00 64 00 38 00 31 00 35 00 66 00 37 00 33 00 65 00 65 00))}
		$typelibguid13up = {((33 46 43 31 37 41 44 42 2d 36 37 44 34 2d 34 41 38 44 2d 38 37 37 30 2d 45 43 46 44 38 31 35 46 37 33 45 45) | (33 00 46 00 43 00 31 00 37 00 41 00 44 00 42 00 2d 00 36 00 37 00 44 00 34 00 2d 00 34 00 41 00 38 00 44 00 2d 00 38 00 37 00 37 00 30 00 2d 00 45 00 43 00 46 00 44 00 38 00 31 00 35 00 46 00 37 00 33 00 45 00 45 00))}
		$typelibguid14lo = {((66 31 61 62 38 35 34 62 2d 36 32 38 32 2d 34 62 64 66 2d 38 62 38 62 2d 66 32 39 31 31 61 30 30 38 39 34 38) | (66 00 31 00 61 00 62 00 38 00 35 00 34 00 62 00 2d 00 36 00 32 00 38 00 32 00 2d 00 34 00 62 00 64 00 66 00 2d 00 38 00 62 00 38 00 62 00 2d 00 66 00 32 00 39 00 31 00 31 00 61 00 30 00 30 00 38 00 39 00 34 00 38 00))}
		$typelibguid14up = {((46 31 41 42 38 35 34 42 2d 36 32 38 32 2d 34 42 44 46 2d 38 42 38 42 2d 46 32 39 31 31 41 30 30 38 39 34 38) | (46 00 31 00 41 00 42 00 38 00 35 00 34 00 42 00 2d 00 36 00 32 00 38 00 32 00 2d 00 34 00 42 00 44 00 46 00 2d 00 38 00 42 00 38 00 42 00 2d 00 46 00 32 00 39 00 31 00 31 00 41 00 30 00 30 00 38 00 39 00 34 00 38 00))}
		$typelibguid15lo = {((61 65 66 36 35 34 37 65 2d 33 38 32 32 2d 34 66 39 36 2d 39 37 30 38 2d 62 63 66 30 30 38 31 32 39 62 32 62) | (61 00 65 00 66 00 36 00 35 00 34 00 37 00 65 00 2d 00 33 00 38 00 32 00 32 00 2d 00 34 00 66 00 39 00 36 00 2d 00 39 00 37 00 30 00 38 00 2d 00 62 00 63 00 66 00 30 00 30 00 38 00 31 00 32 00 39 00 62 00 32 00 62 00))}
		$typelibguid15up = {((41 45 46 36 35 34 37 45 2d 33 38 32 32 2d 34 46 39 36 2d 39 37 30 38 2d 42 43 46 30 30 38 31 32 39 42 32 42) | (41 00 45 00 46 00 36 00 35 00 34 00 37 00 45 00 2d 00 33 00 38 00 32 00 32 00 2d 00 34 00 46 00 39 00 36 00 2d 00 39 00 37 00 30 00 38 00 2d 00 42 00 43 00 46 00 30 00 30 00 38 00 31 00 32 00 39 00 42 00 32 00 42 00))}
		$typelibguid16lo = {((61 33 33 36 66 35 31 37 2d 62 63 61 39 2d 34 36 35 66 2d 38 66 66 38 2d 32 37 35 36 63 66 64 30 63 61 64 39) | (61 00 33 00 33 00 36 00 66 00 35 00 31 00 37 00 2d 00 62 00 63 00 61 00 39 00 2d 00 34 00 36 00 35 00 66 00 2d 00 38 00 66 00 66 00 38 00 2d 00 32 00 37 00 35 00 36 00 63 00 66 00 64 00 30 00 63 00 61 00 64 00 39 00))}
		$typelibguid16up = {((41 33 33 36 46 35 31 37 2d 42 43 41 39 2d 34 36 35 46 2d 38 46 46 38 2d 32 37 35 36 43 46 44 30 43 41 44 39) | (41 00 33 00 33 00 36 00 46 00 35 00 31 00 37 00 2d 00 42 00 43 00 41 00 39 00 2d 00 34 00 36 00 35 00 46 00 2d 00 38 00 46 00 46 00 38 00 2d 00 32 00 37 00 35 00 36 00 43 00 46 00 44 00 30 00 43 00 41 00 44 00 39 00))}
		$typelibguid17lo = {((35 64 65 30 31 38 62 64 2d 39 34 31 64 2d 34 61 35 64 2d 62 65 64 35 2d 66 62 64 64 31 31 31 61 62 61 37 36) | (35 00 64 00 65 00 30 00 31 00 38 00 62 00 64 00 2d 00 39 00 34 00 31 00 64 00 2d 00 34 00 61 00 35 00 64 00 2d 00 62 00 65 00 64 00 35 00 2d 00 66 00 62 00 64 00 64 00 31 00 31 00 31 00 61 00 62 00 61 00 37 00 36 00))}
		$typelibguid17up = {((35 44 45 30 31 38 42 44 2d 39 34 31 44 2d 34 41 35 44 2d 42 45 44 35 2d 46 42 44 44 31 31 31 41 42 41 37 36) | (35 00 44 00 45 00 30 00 31 00 38 00 42 00 44 00 2d 00 39 00 34 00 31 00 44 00 2d 00 34 00 41 00 35 00 44 00 2d 00 42 00 45 00 44 00 35 00 2d 00 46 00 42 00 44 00 44 00 31 00 31 00 31 00 41 00 42 00 41 00 37 00 36 00))}
		$typelibguid18lo = {((62 62 66 61 63 31 66 39 2d 63 64 34 66 2d 34 63 34 34 2d 61 66 39 34 2d 31 31 33 30 31 36 38 34 39 34 64 30) | (62 00 62 00 66 00 61 00 63 00 31 00 66 00 39 00 2d 00 63 00 64 00 34 00 66 00 2d 00 34 00 63 00 34 00 34 00 2d 00 61 00 66 00 39 00 34 00 2d 00 31 00 31 00 33 00 30 00 31 00 36 00 38 00 34 00 39 00 34 00 64 00 30 00))}
		$typelibguid18up = {((42 42 46 41 43 31 46 39 2d 43 44 34 46 2d 34 43 34 34 2d 41 46 39 34 2d 31 31 33 30 31 36 38 34 39 34 44 30) | (42 00 42 00 46 00 41 00 43 00 31 00 46 00 39 00 2d 00 43 00 44 00 34 00 46 00 2d 00 34 00 43 00 34 00 34 00 2d 00 41 00 46 00 39 00 34 00 2d 00 31 00 31 00 33 00 30 00 31 00 36 00 38 00 34 00 39 00 34 00 44 00 30 00))}
		$typelibguid19lo = {((31 63 37 39 63 65 61 31 2d 65 62 66 33 2d 34 39 34 63 2d 39 30 61 38 2d 35 31 36 39 31 64 66 34 31 62 38 36) | (31 00 63 00 37 00 39 00 63 00 65 00 61 00 31 00 2d 00 65 00 62 00 66 00 33 00 2d 00 34 00 39 00 34 00 63 00 2d 00 39 00 30 00 61 00 38 00 2d 00 35 00 31 00 36 00 39 00 31 00 64 00 66 00 34 00 31 00 62 00 38 00 36 00))}
		$typelibguid19up = {((31 43 37 39 43 45 41 31 2d 45 42 46 33 2d 34 39 34 43 2d 39 30 41 38 2d 35 31 36 39 31 44 46 34 31 42 38 36) | (31 00 43 00 37 00 39 00 43 00 45 00 41 00 31 00 2d 00 45 00 42 00 46 00 33 00 2d 00 34 00 39 00 34 00 43 00 2d 00 39 00 30 00 41 00 38 00 2d 00 35 00 31 00 36 00 39 00 31 00 44 00 46 00 34 00 31 00 42 00 38 00 36 00))}
		$typelibguid20lo = {((39 32 37 31 30 34 65 31 2d 61 61 31 37 2d 34 31 36 37 2d 38 31 37 63 2d 37 36 37 33 66 65 32 36 64 34 36 65) | (39 00 32 00 37 00 31 00 30 00 34 00 65 00 31 00 2d 00 61 00 61 00 31 00 37 00 2d 00 34 00 31 00 36 00 37 00 2d 00 38 00 31 00 37 00 63 00 2d 00 37 00 36 00 37 00 33 00 66 00 65 00 32 00 36 00 64 00 34 00 36 00 65 00))}
		$typelibguid20up = {((39 32 37 31 30 34 45 31 2d 41 41 31 37 2d 34 31 36 37 2d 38 31 37 43 2d 37 36 37 33 46 45 32 36 44 34 36 45) | (39 00 32 00 37 00 31 00 30 00 34 00 45 00 31 00 2d 00 41 00 41 00 31 00 37 00 2d 00 34 00 31 00 36 00 37 00 2d 00 38 00 31 00 37 00 43 00 2d 00 37 00 36 00 37 00 33 00 46 00 45 00 32 00 36 00 44 00 34 00 36 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_njRAT : hardened
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		reference = "https://github.com/mwsrc/njRAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-30"
		modified = "2023-04-06"
		id = "2140d69e-fb15-50a2-ba85-b7c8293003fb"

	strings:
		$typelibguid0lo = {((35 61 35 34 32 63 31 62 2d 32 64 33 36 2d 34 63 33 31 2d 62 30 33 39 2d 32 36 61 38 38 64 33 39 36 37 64 61) | (35 00 61 00 35 00 34 00 32 00 63 00 31 00 62 00 2d 00 32 00 64 00 33 00 36 00 2d 00 34 00 63 00 33 00 31 00 2d 00 62 00 30 00 33 00 39 00 2d 00 32 00 36 00 61 00 38 00 38 00 64 00 33 00 39 00 36 00 37 00 64 00 61 00))}
		$typelibguid0up = {((35 41 35 34 32 43 31 42 2d 32 44 33 36 2d 34 43 33 31 2d 42 30 33 39 2d 32 36 41 38 38 44 33 39 36 37 44 41) | (35 00 41 00 35 00 34 00 32 00 43 00 31 00 42 00 2d 00 32 00 44 00 33 00 36 00 2d 00 34 00 43 00 33 00 31 00 2d 00 42 00 30 00 33 00 39 00 2d 00 32 00 36 00 41 00 38 00 38 00 44 00 33 00 39 00 36 00 37 00 44 00 41 00))}
		$typelibguid1lo = {((36 62 30 37 30 38 32 61 2d 39 32 35 36 2d 34 32 63 33 2d 39 39 39 61 2d 36 36 35 65 39 64 65 34 39 66 33 33) | (36 00 62 00 30 00 37 00 30 00 38 00 32 00 61 00 2d 00 39 00 32 00 35 00 36 00 2d 00 34 00 32 00 63 00 33 00 2d 00 39 00 39 00 39 00 61 00 2d 00 36 00 36 00 35 00 65 00 39 00 64 00 65 00 34 00 39 00 66 00 33 00 33 00))}
		$typelibguid1up = {((36 42 30 37 30 38 32 41 2d 39 32 35 36 2d 34 32 43 33 2d 39 39 39 41 2d 36 36 35 45 39 44 45 34 39 46 33 33) | (36 00 42 00 30 00 37 00 30 00 38 00 32 00 41 00 2d 00 39 00 32 00 35 00 36 00 2d 00 34 00 32 00 43 00 33 00 2d 00 39 00 39 00 39 00 41 00 2d 00 36 00 36 00 35 00 45 00 39 00 44 00 45 00 34 00 39 00 46 00 33 00 33 00))}
		$typelibguid2lo = {((63 30 61 39 61 37 30 66 2d 36 33 65 38 2d 34 32 63 61 2d 39 36 35 64 2d 37 33 61 31 62 63 39 30 33 65 36 32) | (63 00 30 00 61 00 39 00 61 00 37 00 30 00 66 00 2d 00 36 00 33 00 65 00 38 00 2d 00 34 00 32 00 63 00 61 00 2d 00 39 00 36 00 35 00 64 00 2d 00 37 00 33 00 61 00 31 00 62 00 63 00 39 00 30 00 33 00 65 00 36 00 32 00))}
		$typelibguid2up = {((43 30 41 39 41 37 30 46 2d 36 33 45 38 2d 34 32 43 41 2d 39 36 35 44 2d 37 33 41 31 42 43 39 30 33 45 36 32) | (43 00 30 00 41 00 39 00 41 00 37 00 30 00 46 00 2d 00 36 00 33 00 45 00 38 00 2d 00 34 00 32 00 43 00 41 00 2d 00 39 00 36 00 35 00 44 00 2d 00 37 00 33 00 41 00 31 00 42 00 43 00 39 00 30 00 33 00 45 00 36 00 32 00))}
		$typelibguid3lo = {((37 30 62 64 31 31 64 65 2d 37 64 61 31 2d 34 61 38 39 2d 62 34 35 39 2d 38 64 61 61 63 63 39 33 30 63 32 30) | (37 00 30 00 62 00 64 00 31 00 31 00 64 00 65 00 2d 00 37 00 64 00 61 00 31 00 2d 00 34 00 61 00 38 00 39 00 2d 00 62 00 34 00 35 00 39 00 2d 00 38 00 64 00 61 00 61 00 63 00 63 00 39 00 33 00 30 00 63 00 32 00 30 00))}
		$typelibguid3up = {((37 30 42 44 31 31 44 45 2d 37 44 41 31 2d 34 41 38 39 2d 42 34 35 39 2d 38 44 41 41 43 43 39 33 30 43 32 30) | (37 00 30 00 42 00 44 00 31 00 31 00 44 00 45 00 2d 00 37 00 44 00 41 00 31 00 2d 00 34 00 41 00 38 00 39 00 2d 00 42 00 34 00 35 00 39 00 2d 00 38 00 44 00 41 00 41 00 43 00 43 00 39 00 33 00 30 00 43 00 32 00 30 00))}
		$typelibguid4lo = {((66 63 37 39 30 65 65 35 2d 31 36 33 61 2d 34 30 66 39 2d 61 31 65 32 2d 39 38 36 33 63 32 39 30 66 66 38 62) | (66 00 63 00 37 00 39 00 30 00 65 00 65 00 35 00 2d 00 31 00 36 00 33 00 61 00 2d 00 34 00 30 00 66 00 39 00 2d 00 61 00 31 00 65 00 32 00 2d 00 39 00 38 00 36 00 33 00 63 00 32 00 39 00 30 00 66 00 66 00 38 00 62 00))}
		$typelibguid4up = {((46 43 37 39 30 45 45 35 2d 31 36 33 41 2d 34 30 46 39 2d 41 31 45 32 2d 39 38 36 33 43 32 39 30 46 46 38 42) | (46 00 43 00 37 00 39 00 30 00 45 00 45 00 35 00 2d 00 31 00 36 00 33 00 41 00 2d 00 34 00 30 00 46 00 39 00 2d 00 41 00 31 00 45 00 32 00 2d 00 39 00 38 00 36 00 33 00 43 00 32 00 39 00 30 00 46 00 46 00 38 00 42 00))}
		$typelibguid5lo = {((63 62 33 63 32 38 62 32 2d 32 61 34 66 2d 34 31 31 34 2d 39 34 31 63 2d 63 65 39 32 39 66 65 63 39 34 64 33) | (63 00 62 00 33 00 63 00 32 00 38 00 62 00 32 00 2d 00 32 00 61 00 34 00 66 00 2d 00 34 00 31 00 31 00 34 00 2d 00 39 00 34 00 31 00 63 00 2d 00 63 00 65 00 39 00 32 00 39 00 66 00 65 00 63 00 39 00 34 00 64 00 33 00))}
		$typelibguid5up = {((43 42 33 43 32 38 42 32 2d 32 41 34 46 2d 34 31 31 34 2d 39 34 31 43 2d 43 45 39 32 39 46 45 43 39 34 44 33) | (43 00 42 00 33 00 43 00 32 00 38 00 42 00 32 00 2d 00 32 00 41 00 34 00 46 00 2d 00 34 00 31 00 31 00 34 00 2d 00 39 00 34 00 31 00 43 00 2d 00 43 00 45 00 39 00 32 00 39 00 46 00 45 00 43 00 39 00 34 00 44 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Manager : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/TheWover/Manager"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "eef65d2c-ddbc-50c3-a6a0-e7032a55e92d"

	strings:
		$typelibguid0lo = {((64 64 61 37 33 65 65 39 2d 30 66 34 31 2d 34 63 30 39 2d 39 63 61 64 2d 38 32 31 35 61 62 64 36 30 62 33 33) | (64 00 64 00 61 00 37 00 33 00 65 00 65 00 39 00 2d 00 30 00 66 00 34 00 31 00 2d 00 34 00 63 00 30 00 39 00 2d 00 39 00 63 00 61 00 64 00 2d 00 38 00 32 00 31 00 35 00 61 00 62 00 64 00 36 00 30 00 62 00 33 00 33 00))}
		$typelibguid0up = {((44 44 41 37 33 45 45 39 2d 30 46 34 31 2d 34 43 30 39 2d 39 43 41 44 2d 38 32 31 35 41 42 44 36 30 42 33 33) | (44 00 44 00 41 00 37 00 33 00 45 00 45 00 39 00 2d 00 30 00 46 00 34 00 31 00 2d 00 34 00 43 00 30 00 39 00 2d 00 39 00 43 00 41 00 44 00 2d 00 38 00 32 00 31 00 35 00 41 00 42 00 44 00 36 00 30 00 42 00 33 00 33 00))}
		$typelibguid1lo = {((36 61 30 66 32 34 32 32 2d 64 34 64 31 2d 34 62 37 65 2d 38 34 61 64 2d 35 36 64 63 30 66 64 32 64 66 63 35) | (36 00 61 00 30 00 66 00 32 00 34 00 32 00 32 00 2d 00 64 00 34 00 64 00 31 00 2d 00 34 00 62 00 37 00 65 00 2d 00 38 00 34 00 61 00 64 00 2d 00 35 00 36 00 64 00 63 00 30 00 66 00 64 00 32 00 64 00 66 00 63 00 35 00))}
		$typelibguid1up = {((36 41 30 46 32 34 32 32 2d 44 34 44 31 2d 34 42 37 45 2d 38 34 41 44 2d 35 36 44 43 30 46 44 32 44 46 43 35) | (36 00 41 00 30 00 46 00 32 00 34 00 32 00 32 00 2d 00 44 00 34 00 44 00 31 00 2d 00 34 00 42 00 37 00 45 00 2d 00 38 00 34 00 41 00 44 00 2d 00 35 00 36 00 44 00 43 00 30 00 46 00 44 00 32 00 44 00 46 00 43 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_neo_ConfuserEx : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/XenocodeRCE/neo-ConfuserEx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "d73117a6-4512-5545-a4f4-72d8cf708340"

	strings:
		$typelibguid0lo = {((65 39 38 34 39 30 62 62 2d 36 33 65 35 2d 34 39 32 64 2d 62 31 34 65 2d 33 30 34 64 65 39 32 38 66 38 31 61) | (65 00 39 00 38 00 34 00 39 00 30 00 62 00 62 00 2d 00 36 00 33 00 65 00 35 00 2d 00 34 00 39 00 32 00 64 00 2d 00 62 00 31 00 34 00 65 00 2d 00 33 00 30 00 34 00 64 00 65 00 39 00 32 00 38 00 66 00 38 00 31 00 61 00))}
		$typelibguid0up = {((45 39 38 34 39 30 42 42 2d 36 33 45 35 2d 34 39 32 44 2d 42 31 34 45 2d 33 30 34 44 45 39 32 38 46 38 31 41) | (45 00 39 00 38 00 34 00 39 00 30 00 42 00 42 00 2d 00 36 00 33 00 45 00 35 00 2d 00 34 00 39 00 32 00 44 00 2d 00 42 00 31 00 34 00 45 00 2d 00 33 00 30 00 34 00 44 00 45 00 39 00 32 00 38 00 46 00 38 00 31 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpAllowedToAct : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/pkb1s/SharpAllowedToAct"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "13b7f5e0-4d34-533d-a182-b3fe7c93ca43"

	strings:
		$typelibguid0lo = {((64 61 63 35 34 34 38 61 2d 34 61 64 31 2d 34 39 30 61 2d 38 34 36 61 2d 31 38 65 34 65 33 65 30 63 66 39 61) | (64 00 61 00 63 00 35 00 34 00 34 00 38 00 61 00 2d 00 34 00 61 00 64 00 31 00 2d 00 34 00 39 00 30 00 61 00 2d 00 38 00 34 00 36 00 61 00 2d 00 31 00 38 00 65 00 34 00 65 00 33 00 65 00 30 00 63 00 66 00 39 00 61 00))}
		$typelibguid0up = {((44 41 43 35 34 34 38 41 2d 34 41 44 31 2d 34 39 30 41 2d 38 34 36 41 2d 31 38 45 34 45 33 45 30 43 46 39 41) | (44 00 41 00 43 00 35 00 34 00 34 00 38 00 41 00 2d 00 34 00 41 00 44 00 31 00 2d 00 34 00 39 00 30 00 41 00 2d 00 38 00 34 00 36 00 41 00 2d 00 31 00 38 00 45 00 34 00 45 00 33 00 45 00 30 00 43 00 46 00 39 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SuperSQLInjectionV1 : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/shack2/SuperSQLInjectionV1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "247bef0d-7873-51c7-97b8-1be6dfe7708d"

	strings:
		$typelibguid0lo = {((64 35 36 38 38 30 36 38 2d 66 63 38 39 2d 34 36 37 64 2d 39 31 33 66 2d 30 33 37 61 37 38 35 63 61 63 61 37) | (64 00 35 00 36 00 38 00 38 00 30 00 36 00 38 00 2d 00 66 00 63 00 38 00 39 00 2d 00 34 00 36 00 37 00 64 00 2d 00 39 00 31 00 33 00 66 00 2d 00 30 00 33 00 37 00 61 00 37 00 38 00 35 00 63 00 61 00 63 00 61 00 37 00))}
		$typelibguid0up = {((44 35 36 38 38 30 36 38 2d 46 43 38 39 2d 34 36 37 44 2d 39 31 33 46 2d 30 33 37 41 37 38 35 43 41 43 41 37) | (44 00 35 00 36 00 38 00 38 00 30 00 36 00 38 00 2d 00 46 00 43 00 38 00 39 00 2d 00 34 00 36 00 37 00 44 00 2d 00 39 00 31 00 33 00 46 00 2d 00 30 00 33 00 37 00 41 00 37 00 38 00 35 00 43 00 41 00 43 00 41 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_ADSearch : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/tomcarver16/ADSearch"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "399ea06d-b36a-542b-bccc-8e8f935a35c6"

	strings:
		$typelibguid0lo = {((34 64 61 35 66 31 62 37 2d 38 39 33 36 2d 34 34 31 33 2d 39 31 66 37 2d 35 37 64 36 65 30 37 32 62 34 61 37) | (34 00 64 00 61 00 35 00 66 00 31 00 62 00 37 00 2d 00 38 00 39 00 33 00 36 00 2d 00 34 00 34 00 31 00 33 00 2d 00 39 00 31 00 66 00 37 00 2d 00 35 00 37 00 64 00 36 00 65 00 30 00 37 00 32 00 62 00 34 00 61 00 37 00))}
		$typelibguid0up = {((34 44 41 35 46 31 42 37 2d 38 39 33 36 2d 34 34 31 33 2d 39 31 46 37 2d 35 37 44 36 45 30 37 32 42 34 41 37) | (34 00 44 00 41 00 35 00 46 00 31 00 42 00 37 00 2d 00 38 00 39 00 33 00 36 00 2d 00 34 00 34 00 31 00 33 00 2d 00 39 00 31 00 46 00 37 00 2d 00 35 00 37 00 44 00 36 00 45 00 30 00 37 00 32 00 42 00 34 00 41 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_privilege_escalation_awesome_scripts_suite : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "fa218dfa-4b56-5a62-b149-63394bd0b604"

	strings:
		$typelibguid0lo = {((31 39 32 38 33 35 38 65 2d 61 36 34 62 2d 34 39 33 66 2d 61 37 34 31 2d 61 65 38 65 33 64 30 32 39 33 37 34) | (31 00 39 00 32 00 38 00 33 00 35 00 38 00 65 00 2d 00 61 00 36 00 34 00 62 00 2d 00 34 00 39 00 33 00 66 00 2d 00 61 00 37 00 34 00 31 00 2d 00 61 00 65 00 38 00 65 00 33 00 64 00 30 00 32 00 39 00 33 00 37 00 34 00))}
		$typelibguid0up = {((31 39 32 38 33 35 38 45 2d 41 36 34 42 2d 34 39 33 46 2d 41 37 34 31 2d 41 45 38 45 33 44 30 32 39 33 37 34) | (31 00 39 00 32 00 38 00 33 00 35 00 38 00 45 00 2d 00 41 00 36 00 34 00 42 00 2d 00 34 00 39 00 33 00 46 00 2d 00 41 00 37 00 34 00 31 00 2d 00 41 00 45 00 38 00 45 00 33 00 44 00 30 00 32 00 39 00 33 00 37 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_CVE_2020_1206_POC : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/ZecOps/CVE-2020-1206-POC"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "d70472f3-b19f-5097-bd70-99a7e7812ac4"

	strings:
		$typelibguid0lo = {((33 35 32 33 63 61 30 34 2d 61 31 32 64 2d 34 62 34 30 2d 38 38 33 37 2d 31 61 31 64 32 38 65 66 39 36 64 65) | (33 00 35 00 32 00 33 00 63 00 61 00 30 00 34 00 2d 00 61 00 31 00 32 00 64 00 2d 00 34 00 62 00 34 00 30 00 2d 00 38 00 38 00 33 00 37 00 2d 00 31 00 61 00 31 00 64 00 32 00 38 00 65 00 66 00 39 00 36 00 64 00 65 00))}
		$typelibguid0up = {((33 35 32 33 43 41 30 34 2d 41 31 32 44 2d 34 42 34 30 2d 38 38 33 37 2d 31 41 31 44 32 38 45 46 39 36 44 45) | (33 00 35 00 32 00 33 00 43 00 41 00 30 00 34 00 2d 00 41 00 31 00 32 00 44 00 2d 00 34 00 42 00 34 00 30 00 2d 00 38 00 38 00 33 00 37 00 2d 00 31 00 41 00 31 00 44 00 32 00 38 00 45 00 46 00 39 00 36 00 44 00 45 00))}
		$typelibguid1lo = {((64 33 61 32 66 32 34 61 2d 64 64 63 36 2d 34 35 34 38 2d 39 62 33 64 2d 34 37 30 65 37 30 64 62 63 61 61 62) | (64 00 33 00 61 00 32 00 66 00 32 00 34 00 61 00 2d 00 64 00 64 00 63 00 36 00 2d 00 34 00 35 00 34 00 38 00 2d 00 39 00 62 00 33 00 64 00 2d 00 34 00 37 00 30 00 65 00 37 00 30 00 64 00 62 00 63 00 61 00 61 00 62 00))}
		$typelibguid1up = {((44 33 41 32 46 32 34 41 2d 44 44 43 36 2d 34 35 34 38 2d 39 42 33 44 2d 34 37 30 45 37 30 44 42 43 41 41 42) | (44 00 33 00 41 00 32 00 46 00 32 00 34 00 41 00 2d 00 44 00 44 00 43 00 36 00 2d 00 34 00 35 00 34 00 38 00 2d 00 39 00 42 00 33 00 44 00 2d 00 34 00 37 00 30 00 45 00 37 00 30 00 44 00 42 00 43 00 41 00 41 00 42 00))}
		$typelibguid2lo = {((66 62 33 30 65 65 30 35 2d 34 61 33 35 2d 34 35 66 37 2d 39 61 30 61 2d 38 32 39 61 65 63 37 65 34 37 64 39) | (66 00 62 00 33 00 30 00 65 00 65 00 30 00 35 00 2d 00 34 00 61 00 33 00 35 00 2d 00 34 00 35 00 66 00 37 00 2d 00 39 00 61 00 30 00 61 00 2d 00 38 00 32 00 39 00 61 00 65 00 63 00 37 00 65 00 34 00 37 00 64 00 39 00))}
		$typelibguid2up = {((46 42 33 30 45 45 30 35 2d 34 41 33 35 2d 34 35 46 37 2d 39 41 30 41 2d 38 32 39 41 45 43 37 45 34 37 44 39) | (46 00 42 00 33 00 30 00 45 00 45 00 30 00 35 00 2d 00 34 00 41 00 33 00 35 00 2d 00 34 00 35 00 46 00 37 00 2d 00 39 00 41 00 30 00 41 00 2d 00 38 00 32 00 39 00 41 00 45 00 43 00 37 00 45 00 34 00 37 00 44 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_DInvoke : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/TheWover/DInvoke"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "f3b0ef47-a92c-5c5d-a9e2-09579fcb438e"
		score = 75

	strings:
		$typelibguid0lo = {((62 37 37 66 64 61 62 35 2d 32 30 37 63 2d 34 63 64 62 2d 62 31 61 61 2d 33 34 38 35 30 35 63 35 34 32 32 39) | (62 00 37 00 37 00 66 00 64 00 61 00 62 00 35 00 2d 00 32 00 30 00 37 00 63 00 2d 00 34 00 63 00 64 00 62 00 2d 00 62 00 31 00 61 00 61 00 2d 00 33 00 34 00 38 00 35 00 30 00 35 00 63 00 35 00 34 00 32 00 32 00 39 00))}
		$typelibguid0up = {((42 37 37 46 44 41 42 35 2d 32 30 37 43 2d 34 43 44 42 2d 42 31 41 41 2d 33 34 38 35 30 35 43 35 34 32 32 39) | (42 00 37 00 37 00 46 00 44 00 41 00 42 00 35 00 2d 00 32 00 30 00 37 00 43 00 2d 00 34 00 43 00 44 00 42 00 2d 00 42 00 31 00 41 00 41 00 2d 00 33 00 34 00 38 00 35 00 30 00 35 00 43 00 35 00 34 00 32 00 32 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpChisel : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/shantanu561993/SharpChisel"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "3b7e6703-ebe8-5a98-839f-7d0349ab483f"

	strings:
		$typelibguid0lo = {((66 35 66 32 31 65 32 64 2d 65 62 37 65 2d 34 31 34 36 2d 61 37 65 31 2d 33 37 31 66 64 30 38 64 36 37 36 32) | (66 00 35 00 66 00 32 00 31 00 65 00 32 00 64 00 2d 00 65 00 62 00 37 00 65 00 2d 00 34 00 31 00 34 00 36 00 2d 00 61 00 37 00 65 00 31 00 2d 00 33 00 37 00 31 00 66 00 64 00 30 00 38 00 64 00 36 00 37 00 36 00 32 00))}
		$typelibguid0up = {((46 35 46 32 31 45 32 44 2d 45 42 37 45 2d 34 31 34 36 2d 41 37 45 31 2d 33 37 31 46 44 30 38 44 36 37 36 32) | (46 00 35 00 46 00 32 00 31 00 45 00 32 00 44 00 2d 00 45 00 42 00 37 00 45 00 2d 00 34 00 31 00 34 00 36 00 2d 00 41 00 37 00 45 00 31 00 2d 00 33 00 37 00 31 00 46 00 44 00 30 00 38 00 44 00 36 00 37 00 36 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpScribbles : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/V1V1/SharpScribbles"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "47125b76-9388-5372-8810-d198f623367a"

	strings:
		$typelibguid0lo = {((61 61 36 31 61 31 36 36 2d 33 31 65 66 2d 34 32 39 64 2d 61 39 37 31 2d 63 61 36 35 34 63 64 31 38 63 33 62) | (61 00 61 00 36 00 31 00 61 00 31 00 36 00 36 00 2d 00 33 00 31 00 65 00 66 00 2d 00 34 00 32 00 39 00 64 00 2d 00 61 00 39 00 37 00 31 00 2d 00 63 00 61 00 36 00 35 00 34 00 63 00 64 00 31 00 38 00 63 00 33 00 62 00))}
		$typelibguid0up = {((41 41 36 31 41 31 36 36 2d 33 31 45 46 2d 34 32 39 44 2d 41 39 37 31 2d 43 41 36 35 34 43 44 31 38 43 33 42) | (41 00 41 00 36 00 31 00 41 00 31 00 36 00 36 00 2d 00 33 00 31 00 45 00 46 00 2d 00 34 00 32 00 39 00 44 00 2d 00 41 00 39 00 37 00 31 00 2d 00 43 00 41 00 36 00 35 00 34 00 43 00 44 00 31 00 38 00 43 00 33 00 42 00))}
		$typelibguid1lo = {((30 64 63 31 62 38 32 34 2d 63 36 65 37 2d 34 38 38 31 2d 38 37 38 38 2d 33 35 61 65 63 62 33 34 64 32 32 37) | (30 00 64 00 63 00 31 00 62 00 38 00 32 00 34 00 2d 00 63 00 36 00 65 00 37 00 2d 00 34 00 38 00 38 00 31 00 2d 00 38 00 37 00 38 00 38 00 2d 00 33 00 35 00 61 00 65 00 63 00 62 00 33 00 34 00 64 00 32 00 32 00 37 00))}
		$typelibguid1up = {((30 44 43 31 42 38 32 34 2d 43 36 45 37 2d 34 38 38 31 2d 38 37 38 38 2d 33 35 41 45 43 42 33 34 44 32 32 37) | (30 00 44 00 43 00 31 00 42 00 38 00 32 00 34 00 2d 00 43 00 36 00 45 00 37 00 2d 00 34 00 38 00 38 00 31 00 2d 00 38 00 37 00 38 00 38 00 2d 00 33 00 35 00 41 00 45 00 43 00 42 00 33 00 34 00 44 00 32 00 32 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpReg : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/jnqpblc/SharpReg"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "d89b07b0-bb29-5c77-888b-322e439b4c82"

	strings:
		$typelibguid0lo = {((38 65 66 32 35 62 30 30 2d 65 64 36 61 2d 34 34 36 34 2d 62 64 65 63 2d 31 37 32 38 31 61 34 61 61 35 32 66) | (38 00 65 00 66 00 32 00 35 00 62 00 30 00 30 00 2d 00 65 00 64 00 36 00 61 00 2d 00 34 00 34 00 36 00 34 00 2d 00 62 00 64 00 65 00 63 00 2d 00 31 00 37 00 32 00 38 00 31 00 61 00 34 00 61 00 61 00 35 00 32 00 66 00))}
		$typelibguid0up = {((38 45 46 32 35 42 30 30 2d 45 44 36 41 2d 34 34 36 34 2d 42 44 45 43 2d 31 37 32 38 31 41 34 41 41 35 32 46) | (38 00 45 00 46 00 32 00 35 00 42 00 30 00 30 00 2d 00 45 00 44 00 36 00 41 00 2d 00 34 00 34 00 36 00 34 00 2d 00 42 00 44 00 45 00 43 00 2d 00 31 00 37 00 32 00 38 00 31 00 41 00 34 00 41 00 41 00 35 00 32 00 46 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_MemeVM : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/TobitoFatitoRE/MemeVM"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "c98d84d5-4b0a-53df-b8d4-0b360930eb0c"

	strings:
		$typelibguid0lo = {((65 66 31 38 66 37 66 32 2d 31 66 30 33 2d 34 38 31 63 2d 39 38 66 39 2d 34 61 31 38 61 32 66 31 32 63 31 31) | (65 00 66 00 31 00 38 00 66 00 37 00 66 00 32 00 2d 00 31 00 66 00 30 00 33 00 2d 00 34 00 38 00 31 00 63 00 2d 00 39 00 38 00 66 00 39 00 2d 00 34 00 61 00 31 00 38 00 61 00 32 00 66 00 31 00 32 00 63 00 31 00 31 00))}
		$typelibguid0up = {((45 46 31 38 46 37 46 32 2d 31 46 30 33 2d 34 38 31 43 2d 39 38 46 39 2d 34 41 31 38 41 32 46 31 32 43 31 31) | (45 00 46 00 31 00 38 00 46 00 37 00 46 00 32 00 2d 00 31 00 46 00 30 00 33 00 2d 00 34 00 38 00 31 00 43 00 2d 00 39 00 38 00 46 00 39 00 2d 00 34 00 41 00 31 00 38 00 41 00 32 00 46 00 31 00 32 00 43 00 31 00 31 00))}
		$typelibguid1lo = {((37 37 62 32 63 38 33 62 2d 63 61 33 34 2d 34 37 33 38 2d 39 33 38 34 2d 63 35 32 66 30 31 32 31 36 34 37 63) | (37 00 37 00 62 00 32 00 63 00 38 00 33 00 62 00 2d 00 63 00 61 00 33 00 34 00 2d 00 34 00 37 00 33 00 38 00 2d 00 39 00 33 00 38 00 34 00 2d 00 63 00 35 00 32 00 66 00 30 00 31 00 32 00 31 00 36 00 34 00 37 00 63 00))}
		$typelibguid1up = {((37 37 42 32 43 38 33 42 2d 43 41 33 34 2d 34 37 33 38 2d 39 33 38 34 2d 43 35 32 46 30 31 32 31 36 34 37 43) | (37 00 37 00 42 00 32 00 43 00 38 00 33 00 42 00 2d 00 43 00 41 00 33 00 34 00 2d 00 34 00 37 00 33 00 38 00 2d 00 39 00 33 00 38 00 34 00 2d 00 43 00 35 00 32 00 46 00 30 00 31 00 32 00 31 00 36 00 34 00 37 00 43 00))}
		$typelibguid2lo = {((31 34 64 35 64 31 32 65 2d 39 61 33 32 2d 34 35 31 36 2d 39 30 34 65 2d 64 66 33 33 39 33 36 32 36 33 31 37) | (31 00 34 00 64 00 35 00 64 00 31 00 32 00 65 00 2d 00 39 00 61 00 33 00 32 00 2d 00 34 00 35 00 31 00 36 00 2d 00 39 00 30 00 34 00 65 00 2d 00 64 00 66 00 33 00 33 00 39 00 33 00 36 00 32 00 36 00 33 00 31 00 37 00))}
		$typelibguid2up = {((31 34 44 35 44 31 32 45 2d 39 41 33 32 2d 34 35 31 36 2d 39 30 34 45 2d 44 46 33 33 39 33 36 32 36 33 31 37) | (31 00 34 00 44 00 35 00 44 00 31 00 32 00 45 00 2d 00 39 00 41 00 33 00 32 00 2d 00 34 00 35 00 31 00 36 00 2d 00 39 00 30 00 34 00 45 00 2d 00 44 00 46 00 33 00 33 00 39 00 33 00 36 00 32 00 36 00 33 00 31 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpDir : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/jnqpblc/SharpDir"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "f64ed564-d198-59e8-9abe-b2814b95c85f"

	strings:
		$typelibguid0lo = {((63 37 61 30 37 35 33 32 2d 31 32 61 33 2d 34 66 36 61 2d 61 33 34 32 2d 31 36 31 62 62 30 36 30 62 37 38 39) | (63 00 37 00 61 00 30 00 37 00 35 00 33 00 32 00 2d 00 31 00 32 00 61 00 33 00 2d 00 34 00 66 00 36 00 61 00 2d 00 61 00 33 00 34 00 32 00 2d 00 31 00 36 00 31 00 62 00 62 00 30 00 36 00 30 00 62 00 37 00 38 00 39 00))}
		$typelibguid0up = {((43 37 41 30 37 35 33 32 2d 31 32 41 33 2d 34 46 36 41 2d 41 33 34 32 2d 31 36 31 42 42 30 36 30 42 37 38 39) | (43 00 37 00 41 00 30 00 37 00 35 00 33 00 32 00 2d 00 31 00 32 00 41 00 33 00 2d 00 34 00 46 00 36 00 41 00 2d 00 41 00 33 00 34 00 32 00 2d 00 31 00 36 00 31 00 42 00 42 00 30 00 36 00 30 00 42 00 37 00 38 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_AtYourService : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/mitchmoser/AtYourService"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "3077dd0c-6936-5340-8da9-e8643de4d864"

	strings:
		$typelibguid0lo = {((62 63 37 32 33 38 36 66 2d 38 62 34 63 2d 34 34 64 65 2d 39 39 62 37 2d 62 30 36 61 38 64 65 33 63 65 33 66) | (62 00 63 00 37 00 32 00 33 00 38 00 36 00 66 00 2d 00 38 00 62 00 34 00 63 00 2d 00 34 00 34 00 64 00 65 00 2d 00 39 00 39 00 62 00 37 00 2d 00 62 00 30 00 36 00 61 00 38 00 64 00 65 00 33 00 63 00 65 00 33 00 66 00))}
		$typelibguid0up = {((42 43 37 32 33 38 36 46 2d 38 42 34 43 2d 34 34 44 45 2d 39 39 42 37 2d 42 30 36 41 38 44 45 33 43 45 33 46) | (42 00 43 00 37 00 32 00 33 00 38 00 36 00 46 00 2d 00 38 00 42 00 34 00 43 00 2d 00 34 00 34 00 44 00 45 00 2d 00 39 00 39 00 42 00 37 00 2d 00 42 00 30 00 36 00 41 00 38 00 44 00 45 00 33 00 43 00 45 00 33 00 46 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_LockLess : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/LockLess"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "f9b31f57-d721-5b6c-be63-b8309cba788a"

	strings:
		$typelibguid0lo = {((61 39 31 34 32 31 63 62 2d 37 39 30 39 2d 34 33 38 33 2d 62 61 34 33 2d 63 32 39 39 32 62 62 62 61 63 32 32) | (61 00 39 00 31 00 34 00 32 00 31 00 63 00 62 00 2d 00 37 00 39 00 30 00 39 00 2d 00 34 00 33 00 38 00 33 00 2d 00 62 00 61 00 34 00 33 00 2d 00 63 00 32 00 39 00 39 00 32 00 62 00 62 00 62 00 61 00 63 00 32 00 32 00))}
		$typelibguid0up = {((41 39 31 34 32 31 43 42 2d 37 39 30 39 2d 34 33 38 33 2d 42 41 34 33 2d 43 32 39 39 32 42 42 42 41 43 32 32) | (41 00 39 00 31 00 34 00 32 00 31 00 43 00 42 00 2d 00 37 00 39 00 30 00 39 00 2d 00 34 00 33 00 38 00 33 00 2d 00 42 00 41 00 34 00 33 00 2d 00 43 00 32 00 39 00 39 00 32 00 42 00 42 00 42 00 41 00 43 00 32 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_EasyNet : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/TheWover/EasyNet"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "8408a057-4910-5d7b-80bc-78df17c95bf7"

	strings:
		$typelibguid0lo = {((33 30 39 37 64 38 35 36 2d 32 35 63 32 2d 34 32 63 39 2d 38 64 35 39 2d 32 63 64 61 64 38 65 38 65 61 31 32) | (33 00 30 00 39 00 37 00 64 00 38 00 35 00 36 00 2d 00 32 00 35 00 63 00 32 00 2d 00 34 00 32 00 63 00 39 00 2d 00 38 00 64 00 35 00 39 00 2d 00 32 00 63 00 64 00 61 00 64 00 38 00 65 00 38 00 65 00 61 00 31 00 32 00))}
		$typelibguid0up = {((33 30 39 37 44 38 35 36 2d 32 35 43 32 2d 34 32 43 39 2d 38 44 35 39 2d 32 43 44 41 44 38 45 38 45 41 31 32) | (33 00 30 00 39 00 37 00 44 00 38 00 35 00 36 00 2d 00 32 00 35 00 43 00 32 00 2d 00 34 00 32 00 43 00 39 00 2d 00 38 00 44 00 35 00 39 00 2d 00 32 00 43 00 44 00 41 00 44 00 38 00 45 00 38 00 45 00 41 00 31 00 32 00))}
		$typelibguid1lo = {((62 61 33 33 66 37 31 36 2d 39 31 65 30 2d 34 63 66 37 2d 62 39 62 64 2d 62 34 64 35 35 38 66 39 61 31 37 33) | (62 00 61 00 33 00 33 00 66 00 37 00 31 00 36 00 2d 00 39 00 31 00 65 00 30 00 2d 00 34 00 63 00 66 00 37 00 2d 00 62 00 39 00 62 00 64 00 2d 00 62 00 34 00 64 00 35 00 35 00 38 00 66 00 39 00 61 00 31 00 37 00 33 00))}
		$typelibguid1up = {((42 41 33 33 46 37 31 36 2d 39 31 45 30 2d 34 43 46 37 2d 42 39 42 44 2d 42 34 44 35 35 38 46 39 41 31 37 33) | (42 00 41 00 33 00 33 00 46 00 37 00 31 00 36 00 2d 00 39 00 31 00 45 00 30 00 2d 00 34 00 43 00 46 00 37 00 2d 00 42 00 39 00 42 00 44 00 2d 00 42 00 34 00 44 00 35 00 35 00 38 00 46 00 39 00 41 00 31 00 37 00 33 00))}
		$typelibguid2lo = {((33 37 64 36 64 64 33 66 2d 35 34 35 37 2d 34 64 38 62 2d 61 32 65 31 2d 63 37 62 31 35 36 62 31 37 36 65 35) | (33 00 37 00 64 00 36 00 64 00 64 00 33 00 66 00 2d 00 35 00 34 00 35 00 37 00 2d 00 34 00 64 00 38 00 62 00 2d 00 61 00 32 00 65 00 31 00 2d 00 63 00 37 00 62 00 31 00 35 00 36 00 62 00 31 00 37 00 36 00 65 00 35 00))}
		$typelibguid2up = {((33 37 44 36 44 44 33 46 2d 35 34 35 37 2d 34 44 38 42 2d 41 32 45 31 2d 43 37 42 31 35 36 42 31 37 36 45 35) | (33 00 37 00 44 00 36 00 44 00 44 00 33 00 46 00 2d 00 35 00 34 00 35 00 37 00 2d 00 34 00 44 00 38 00 42 00 2d 00 41 00 32 00 45 00 31 00 2d 00 43 00 37 00 42 00 31 00 35 00 36 00 42 00 31 00 37 00 36 00 45 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpByeBear : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/S3cur3Th1sSh1t/SharpByeBear"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "4a7f2514-2519-5fd5-9d17-110a67f829e7"

	strings:
		$typelibguid0lo = {((61 36 62 38 34 65 33 35 2d 32 31 31 32 2d 34 64 66 32 2d 61 33 31 62 2d 35 30 66 64 65 34 34 35 38 63 35 65) | (61 00 36 00 62 00 38 00 34 00 65 00 33 00 35 00 2d 00 32 00 31 00 31 00 32 00 2d 00 34 00 64 00 66 00 32 00 2d 00 61 00 33 00 31 00 62 00 2d 00 35 00 30 00 66 00 64 00 65 00 34 00 34 00 35 00 38 00 63 00 35 00 65 00))}
		$typelibguid0up = {((41 36 42 38 34 45 33 35 2d 32 31 31 32 2d 34 44 46 32 2d 41 33 31 42 2d 35 30 46 44 45 34 34 35 38 43 35 45) | (41 00 36 00 42 00 38 00 34 00 45 00 33 00 35 00 2d 00 32 00 31 00 31 00 32 00 2d 00 34 00 44 00 46 00 32 00 2d 00 41 00 33 00 31 00 42 00 2d 00 35 00 30 00 46 00 44 00 45 00 34 00 34 00 35 00 38 00 43 00 35 00 45 00))}
		$typelibguid1lo = {((33 65 38 32 66 35 33 38 2d 36 33 33 36 2d 34 66 66 66 2d 61 65 65 63 2d 65 37 37 34 36 37 36 32 30 35 64 61) | (33 00 65 00 38 00 32 00 66 00 35 00 33 00 38 00 2d 00 36 00 33 00 33 00 36 00 2d 00 34 00 66 00 66 00 66 00 2d 00 61 00 65 00 65 00 63 00 2d 00 65 00 37 00 37 00 34 00 36 00 37 00 36 00 32 00 30 00 35 00 64 00 61 00))}
		$typelibguid1up = {((33 45 38 32 46 35 33 38 2d 36 33 33 36 2d 34 46 46 46 2d 41 45 45 43 2d 45 37 37 34 36 37 36 32 30 35 44 41) | (33 00 45 00 38 00 32 00 46 00 35 00 33 00 38 00 2d 00 36 00 33 00 33 00 36 00 2d 00 34 00 46 00 46 00 46 00 2d 00 41 00 45 00 45 00 43 00 2d 00 45 00 37 00 37 00 34 00 36 00 37 00 36 00 32 00 30 00 35 00 44 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpHide : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/outflanknl/SharpHide"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "928e00c1-549a-58f5-9e7e-982a4319691a"

	strings:
		$typelibguid0lo = {((34 34 33 64 38 63 62 66 2d 38 39 39 63 2d 34 63 32 32 2d 62 34 66 36 2d 62 37 61 63 32 30 32 64 34 65 33 37) | (34 00 34 00 33 00 64 00 38 00 63 00 62 00 66 00 2d 00 38 00 39 00 39 00 63 00 2d 00 34 00 63 00 32 00 32 00 2d 00 62 00 34 00 66 00 36 00 2d 00 62 00 37 00 61 00 63 00 32 00 30 00 32 00 64 00 34 00 65 00 33 00 37 00))}
		$typelibguid0up = {((34 34 33 44 38 43 42 46 2d 38 39 39 43 2d 34 43 32 32 2d 42 34 46 36 2d 42 37 41 43 32 30 32 44 34 45 33 37) | (34 00 34 00 33 00 44 00 38 00 43 00 42 00 46 00 2d 00 38 00 39 00 39 00 43 00 2d 00 34 00 43 00 32 00 32 00 2d 00 42 00 34 00 46 00 36 00 2d 00 42 00 37 00 41 00 43 00 32 00 30 00 32 00 44 00 34 00 45 00 33 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpSvc : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/jnqpblc/SharpSvc"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "cbc1d7d4-f3b4-5d02-84ae-621398cb7b51"

	strings:
		$typelibguid0lo = {((35 32 38 35 36 62 30 33 2d 35 61 63 64 2d 34 35 65 30 2d 38 32 38 65 2d 31 33 63 63 62 31 36 39 34 32 64 31) | (35 00 32 00 38 00 35 00 36 00 62 00 30 00 33 00 2d 00 35 00 61 00 63 00 64 00 2d 00 34 00 35 00 65 00 30 00 2d 00 38 00 32 00 38 00 65 00 2d 00 31 00 33 00 63 00 63 00 62 00 31 00 36 00 39 00 34 00 32 00 64 00 31 00))}
		$typelibguid0up = {((35 32 38 35 36 42 30 33 2d 35 41 43 44 2d 34 35 45 30 2d 38 32 38 45 2d 31 33 43 43 42 31 36 39 34 32 44 31) | (35 00 32 00 38 00 35 00 36 00 42 00 30 00 33 00 2d 00 35 00 41 00 43 00 44 00 2d 00 34 00 35 00 45 00 30 00 2d 00 38 00 32 00 38 00 45 00 2d 00 31 00 33 00 43 00 43 00 42 00 31 00 36 00 39 00 34 00 32 00 44 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpCrashEventLog : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/slyd0g/SharpCrashEventLog"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "85d31989-ad96-5005-a747-8a19a67fdd80"

	strings:
		$typelibguid0lo = {((39 38 63 62 34 39 35 66 2d 34 64 34 37 2d 34 37 32 32 2d 62 30 38 66 2d 63 65 66 61 62 32 32 38 32 62 31 38) | (39 00 38 00 63 00 62 00 34 00 39 00 35 00 66 00 2d 00 34 00 64 00 34 00 37 00 2d 00 34 00 37 00 32 00 32 00 2d 00 62 00 30 00 38 00 66 00 2d 00 63 00 65 00 66 00 61 00 62 00 32 00 32 00 38 00 32 00 62 00 31 00 38 00))}
		$typelibguid0up = {((39 38 43 42 34 39 35 46 2d 34 44 34 37 2d 34 37 32 32 2d 42 30 38 46 2d 43 45 46 41 42 32 32 38 32 42 31 38) | (39 00 38 00 43 00 42 00 34 00 39 00 35 00 46 00 2d 00 34 00 44 00 34 00 37 00 2d 00 34 00 37 00 32 00 32 00 2d 00 42 00 30 00 38 00 46 00 2d 00 43 00 45 00 46 00 41 00 42 00 32 00 32 00 38 00 32 00 42 00 31 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_DotNetToJScript_LanguageModeBreakout : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/FuzzySecurity/DotNetToJScript-LanguageModeBreakout"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "8c8cf79f-8e69-5293-b27a-1f8593061627"

	strings:
		$typelibguid0lo = {((64 65 61 64 62 33 33 66 2d 66 61 39 34 2d 34 31 62 35 2d 38 31 33 64 2d 65 37 32 64 38 36 37 37 61 30 63 66) | (64 00 65 00 61 00 64 00 62 00 33 00 33 00 66 00 2d 00 66 00 61 00 39 00 34 00 2d 00 34 00 31 00 62 00 35 00 2d 00 38 00 31 00 33 00 64 00 2d 00 65 00 37 00 32 00 64 00 38 00 36 00 37 00 37 00 61 00 30 00 63 00 66 00))}
		$typelibguid0up = {((44 45 41 44 42 33 33 46 2d 46 41 39 34 2d 34 31 42 35 2d 38 31 33 44 2d 45 37 32 44 38 36 37 37 41 30 43 46) | (44 00 45 00 41 00 44 00 42 00 33 00 33 00 46 00 2d 00 46 00 41 00 39 00 34 00 2d 00 34 00 31 00 42 00 35 00 2d 00 38 00 31 00 33 00 44 00 2d 00 45 00 37 00 32 00 44 00 38 00 36 00 37 00 37 00 41 00 30 00 43 00 46 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharPermission : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/mitchmoser/SharPermission"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "d5027f51-f3ca-53cd-96d7-c355b5c2e6fa"

	strings:
		$typelibguid0lo = {((38 34 64 32 62 36 36 31 2d 33 32 36 37 2d 34 39 63 38 2d 39 66 35 31 2d 38 66 37 32 66 32 31 61 65 61 34 37) | (38 00 34 00 64 00 32 00 62 00 36 00 36 00 31 00 2d 00 33 00 32 00 36 00 37 00 2d 00 34 00 39 00 63 00 38 00 2d 00 39 00 66 00 35 00 31 00 2d 00 38 00 66 00 37 00 32 00 66 00 32 00 31 00 61 00 65 00 61 00 34 00 37 00))}
		$typelibguid0up = {((38 34 44 32 42 36 36 31 2d 33 32 36 37 2d 34 39 43 38 2d 39 46 35 31 2d 38 46 37 32 46 32 31 41 45 41 34 37) | (38 00 34 00 44 00 32 00 42 00 36 00 36 00 31 00 2d 00 33 00 32 00 36 00 37 00 2d 00 34 00 39 00 43 00 38 00 2d 00 39 00 46 00 35 00 31 00 2d 00 38 00 46 00 37 00 32 00 46 00 32 00 31 00 41 00 45 00 41 00 34 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_RegistryStrikesBack : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/mdsecactivebreach/RegistryStrikesBack"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "1577ed24-0e17-54f9-bc29-bb209acf9645"

	strings:
		$typelibguid0lo = {((39 30 65 62 64 34 36 39 2d 64 37 38 30 2d 34 34 33 31 2d 39 62 64 38 2d 30 31 34 62 30 30 30 35 37 36 36 35) | (39 00 30 00 65 00 62 00 64 00 34 00 36 00 39 00 2d 00 64 00 37 00 38 00 30 00 2d 00 34 00 34 00 33 00 31 00 2d 00 39 00 62 00 64 00 38 00 2d 00 30 00 31 00 34 00 62 00 30 00 30 00 30 00 35 00 37 00 36 00 36 00 35 00))}
		$typelibguid0up = {((39 30 45 42 44 34 36 39 2d 44 37 38 30 2d 34 34 33 31 2d 39 42 44 38 2d 30 31 34 42 30 30 30 35 37 36 36 35) | (39 00 30 00 45 00 42 00 44 00 34 00 36 00 39 00 2d 00 44 00 37 00 38 00 30 00 2d 00 34 00 34 00 33 00 31 00 2d 00 39 00 42 00 44 00 38 00 2d 00 30 00 31 00 34 00 42 00 30 00 30 00 30 00 35 00 37 00 36 00 36 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_CloneVault : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/mdsecactivebreach/CloneVault"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "3340a095-d926-5c85-b7ed-03151712538d"

	strings:
		$typelibguid0lo = {((30 61 33 34 34 66 35 32 2d 36 37 38 30 2d 34 64 31 30 2d 39 61 34 61 2d 63 62 39 34 33 39 66 39 64 33 64 65) | (30 00 61 00 33 00 34 00 34 00 66 00 35 00 32 00 2d 00 36 00 37 00 38 00 30 00 2d 00 34 00 64 00 31 00 30 00 2d 00 39 00 61 00 34 00 61 00 2d 00 63 00 62 00 39 00 34 00 33 00 39 00 66 00 39 00 64 00 33 00 64 00 65 00))}
		$typelibguid0up = {((30 41 33 34 34 46 35 32 2d 36 37 38 30 2d 34 44 31 30 2d 39 41 34 41 2d 43 42 39 34 33 39 46 39 44 33 44 45) | (30 00 41 00 33 00 34 00 34 00 46 00 35 00 32 00 2d 00 36 00 37 00 38 00 30 00 2d 00 34 00 44 00 31 00 30 00 2d 00 39 00 41 00 34 00 41 00 2d 00 43 00 42 00 39 00 34 00 33 00 39 00 46 00 39 00 44 00 33 00 44 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_donut : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/TheWover/donut"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "564dfd0a-af9b-505f-a6f0-de2a5c5c63f3"

	strings:
		$typelibguid0lo = {((39 38 63 61 37 34 63 37 2d 61 30 37 34 2d 34 33 34 64 2d 39 37 37 32 2d 37 35 38 39 36 65 37 33 63 65 61 61) | (39 00 38 00 63 00 61 00 37 00 34 00 63 00 37 00 2d 00 61 00 30 00 37 00 34 00 2d 00 34 00 33 00 34 00 64 00 2d 00 39 00 37 00 37 00 32 00 2d 00 37 00 35 00 38 00 39 00 36 00 65 00 37 00 33 00 63 00 65 00 61 00 61 00))}
		$typelibguid0up = {((39 38 43 41 37 34 43 37 2d 41 30 37 34 2d 34 33 34 44 2d 39 37 37 32 2d 37 35 38 39 36 45 37 33 43 45 41 41) | (39 00 38 00 43 00 41 00 37 00 34 00 43 00 37 00 2d 00 41 00 30 00 37 00 34 00 2d 00 34 00 33 00 34 00 44 00 2d 00 39 00 37 00 37 00 32 00 2d 00 37 00 35 00 38 00 39 00 36 00 45 00 37 00 33 00 43 00 45 00 41 00 41 00))}
		$typelibguid1lo = {((33 63 39 61 36 62 38 38 2d 62 65 64 32 2d 34 62 61 38 2d 39 36 34 63 2d 37 37 65 63 32 39 62 66 31 38 34 36) | (33 00 63 00 39 00 61 00 36 00 62 00 38 00 38 00 2d 00 62 00 65 00 64 00 32 00 2d 00 34 00 62 00 61 00 38 00 2d 00 39 00 36 00 34 00 63 00 2d 00 37 00 37 00 65 00 63 00 32 00 39 00 62 00 66 00 31 00 38 00 34 00 36 00))}
		$typelibguid1up = {((33 43 39 41 36 42 38 38 2d 42 45 44 32 2d 34 42 41 38 2d 39 36 34 43 2d 37 37 45 43 32 39 42 46 31 38 34 36) | (33 00 43 00 39 00 41 00 36 00 42 00 38 00 38 00 2d 00 42 00 45 00 44 00 32 00 2d 00 34 00 42 00 41 00 38 00 2d 00 39 00 36 00 34 00 43 00 2d 00 37 00 37 00 45 00 43 00 32 00 39 00 42 00 46 00 31 00 38 00 34 00 36 00))}
		$typelibguid2lo = {((34 66 63 64 66 33 61 33 2d 61 65 65 66 2d 34 33 65 61 2d 39 32 39 37 2d 30 64 33 62 64 65 33 62 64 61 64 32) | (34 00 66 00 63 00 64 00 66 00 33 00 61 00 33 00 2d 00 61 00 65 00 65 00 66 00 2d 00 34 00 33 00 65 00 61 00 2d 00 39 00 32 00 39 00 37 00 2d 00 30 00 64 00 33 00 62 00 64 00 65 00 33 00 62 00 64 00 61 00 64 00 32 00))}
		$typelibguid2up = {((34 46 43 44 46 33 41 33 2d 41 45 45 46 2d 34 33 45 41 2d 39 32 39 37 2d 30 44 33 42 44 45 33 42 44 41 44 32) | (34 00 46 00 43 00 44 00 46 00 33 00 41 00 33 00 2d 00 41 00 45 00 45 00 46 00 2d 00 34 00 33 00 45 00 41 00 2d 00 39 00 32 00 39 00 37 00 2d 00 30 00 44 00 33 00 42 00 44 00 45 00 33 00 42 00 44 00 41 00 44 00 32 00))}
		$typelibguid3lo = {((33 36 31 63 36 39 66 35 2d 37 38 38 35 2d 34 39 33 31 2d 39 34 39 61 2d 62 39 31 65 65 61 62 31 37 30 65 33) | (33 00 36 00 31 00 63 00 36 00 39 00 66 00 35 00 2d 00 37 00 38 00 38 00 35 00 2d 00 34 00 39 00 33 00 31 00 2d 00 39 00 34 00 39 00 61 00 2d 00 62 00 39 00 31 00 65 00 65 00 61 00 62 00 31 00 37 00 30 00 65 00 33 00))}
		$typelibguid3up = {((33 36 31 43 36 39 46 35 2d 37 38 38 35 2d 34 39 33 31 2d 39 34 39 41 2d 42 39 31 45 45 41 42 31 37 30 45 33) | (33 00 36 00 31 00 43 00 36 00 39 00 46 00 35 00 2d 00 37 00 38 00 38 00 35 00 2d 00 34 00 39 00 33 00 31 00 2d 00 39 00 34 00 39 00 41 00 2d 00 42 00 39 00 31 00 45 00 45 00 41 00 42 00 31 00 37 00 30 00 45 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpHandler : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/jfmaes/SharpHandler"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "b71198a9-4d00-5d75-bc36-7c40655c84a3"

	strings:
		$typelibguid0lo = {((34 36 65 33 39 61 65 64 2d 30 63 66 66 2d 34 37 63 36 2d 38 61 36 33 2d 36 38 32 36 66 31 34 37 64 37 62 64) | (34 00 36 00 65 00 33 00 39 00 61 00 65 00 64 00 2d 00 30 00 63 00 66 00 66 00 2d 00 34 00 37 00 63 00 36 00 2d 00 38 00 61 00 36 00 33 00 2d 00 36 00 38 00 32 00 36 00 66 00 31 00 34 00 37 00 64 00 37 00 62 00 64 00))}
		$typelibguid0up = {((34 36 45 33 39 41 45 44 2d 30 43 46 46 2d 34 37 43 36 2d 38 41 36 33 2d 36 38 32 36 46 31 34 37 44 37 42 44) | (34 00 36 00 45 00 33 00 39 00 41 00 45 00 44 00 2d 00 30 00 43 00 46 00 46 00 2d 00 34 00 37 00 43 00 36 00 2d 00 38 00 41 00 36 00 33 00 2d 00 36 00 38 00 32 00 36 00 46 00 31 00 34 00 37 00 44 00 37 00 42 00 44 00))}
		$typelibguid1lo = {((31 31 64 63 38 33 63 36 2d 38 31 38 36 2d 34 38 38 37 2d 62 32 32 38 2d 39 64 63 34 66 64 32 38 31 61 32 33) | (31 00 31 00 64 00 63 00 38 00 33 00 63 00 36 00 2d 00 38 00 31 00 38 00 36 00 2d 00 34 00 38 00 38 00 37 00 2d 00 62 00 32 00 32 00 38 00 2d 00 39 00 64 00 63 00 34 00 66 00 64 00 32 00 38 00 31 00 61 00 32 00 33 00))}
		$typelibguid1up = {((31 31 44 43 38 33 43 36 2d 38 31 38 36 2d 34 38 38 37 2d 42 32 32 38 2d 39 44 43 34 46 44 32 38 31 41 32 33) | (31 00 31 00 44 00 43 00 38 00 33 00 43 00 36 00 2d 00 38 00 31 00 38 00 36 00 2d 00 34 00 38 00 38 00 37 00 2d 00 42 00 32 00 32 00 38 00 2d 00 39 00 44 00 43 00 34 00 46 00 44 00 32 00 38 00 31 00 41 00 32 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Driver_Template : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/FuzzySecurity/Driver-Template"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "539f88c5-e779-55e0-98df-299a9068de9b"

	strings:
		$typelibguid0lo = {((62 64 62 37 39 61 64 36 2d 36 33 39 66 2d 34 64 63 32 2d 38 62 38 61 2d 63 64 39 31 30 37 64 61 33 64 36 39) | (62 00 64 00 62 00 37 00 39 00 61 00 64 00 36 00 2d 00 36 00 33 00 39 00 66 00 2d 00 34 00 64 00 63 00 32 00 2d 00 38 00 62 00 38 00 61 00 2d 00 63 00 64 00 39 00 31 00 30 00 37 00 64 00 61 00 33 00 64 00 36 00 39 00))}
		$typelibguid0up = {((42 44 42 37 39 41 44 36 2d 36 33 39 46 2d 34 44 43 32 2d 38 42 38 41 2d 43 44 39 31 30 37 44 41 33 44 36 39) | (42 00 44 00 42 00 37 00 39 00 41 00 44 00 36 00 2d 00 36 00 33 00 39 00 46 00 2d 00 34 00 44 00 43 00 32 00 2d 00 38 00 42 00 38 00 41 00 2d 00 43 00 44 00 39 00 31 00 30 00 37 00 44 00 41 00 33 00 44 00 36 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_NashaVM : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/Mrakovic-ORG/NashaVM"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		id = "3abbf636-01f4-547a-98c0-d7bfec07e31a"

	strings:
		$typelibguid0lo = {((66 39 65 36 33 34 39 38 2d 36 65 39 32 2d 34 61 66 64 2d 38 63 31 33 2d 34 66 36 33 61 33 64 39 36 34 63 33) | (66 00 39 00 65 00 36 00 33 00 34 00 39 00 38 00 2d 00 36 00 65 00 39 00 32 00 2d 00 34 00 61 00 66 00 64 00 2d 00 38 00 63 00 31 00 33 00 2d 00 34 00 66 00 36 00 33 00 61 00 33 00 64 00 39 00 36 00 34 00 63 00 33 00))}
		$typelibguid0up = {((46 39 45 36 33 34 39 38 2d 36 45 39 32 2d 34 41 46 44 2d 38 43 31 33 2d 34 46 36 33 41 33 44 39 36 34 43 33) | (46 00 39 00 45 00 36 00 33 00 34 00 39 00 38 00 2d 00 36 00 45 00 39 00 32 00 2d 00 34 00 41 00 46 00 44 00 2d 00 38 00 43 00 31 00 33 00 2d 00 34 00 46 00 36 00 33 00 41 00 33 00 44 00 39 00 36 00 34 00 43 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpSQLPwn : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/lefayjey/SharpSQLPwn.git"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2022-11-21"
		modified = "2023-04-06"
		id = "b533d61a-8693-5c3c-8b31-2117262cad4e"

	strings:
		$typelibguid0lo = {((63 34 34 32 65 61 36 61 2d 39 61 61 31 2d 34 64 39 63 2d 39 63 39 64 2d 37 35 36 30 61 33 32 37 30 38 39 63) | (63 00 34 00 34 00 32 00 65 00 61 00 36 00 61 00 2d 00 39 00 61 00 61 00 31 00 2d 00 34 00 64 00 39 00 63 00 2d 00 39 00 63 00 39 00 64 00 2d 00 37 00 35 00 36 00 30 00 61 00 33 00 32 00 37 00 30 00 38 00 39 00 63 00))}
		$typelibguid0up = {((43 34 34 32 45 41 36 41 2d 39 41 41 31 2d 34 44 39 43 2d 39 43 39 44 2d 37 35 36 30 41 33 32 37 30 38 39 43) | (43 00 34 00 34 00 32 00 45 00 41 00 36 00 41 00 2d 00 39 00 41 00 41 00 31 00 2d 00 34 00 44 00 39 00 43 00 2d 00 39 00 43 00 39 00 44 00 2d 00 37 00 35 00 36 00 30 00 41 00 33 00 32 00 37 00 30 00 38 00 39 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Group3r : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/Group3r/Group3r.git"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2022-11-21"
		modified = "2023-04-06"
		id = "0571d71e-50ca-5c1b-b750-34acc2d06687"

	strings:
		$typelibguid0lo = {((38 36 38 61 36 63 37 36 2d 63 39 30 33 2d 34 61 39 34 2d 39 36 66 64 2d 61 32 63 36 62 61 37 35 36 39 31 63) | (38 00 36 00 38 00 61 00 36 00 63 00 37 00 36 00 2d 00 63 00 39 00 30 00 33 00 2d 00 34 00 61 00 39 00 34 00 2d 00 39 00 36 00 66 00 64 00 2d 00 61 00 32 00 63 00 36 00 62 00 61 00 37 00 35 00 36 00 39 00 31 00 63 00))}
		$typelibguid0up = {((38 36 38 41 36 43 37 36 2d 43 39 30 33 2d 34 41 39 34 2d 39 36 46 44 2d 41 32 43 36 42 41 37 35 36 39 31 43) | (38 00 36 00 38 00 41 00 36 00 43 00 37 00 36 00 2d 00 43 00 39 00 30 00 33 00 2d 00 34 00 41 00 39 00 34 00 2d 00 39 00 36 00 46 00 44 00 2d 00 41 00 32 00 43 00 36 00 42 00 41 00 37 00 35 00 36 00 39 00 31 00 43 00))}
		$typelibguid1lo = {((63 61 61 37 61 62 39 37 2d 66 38 33 62 2d 34 33 32 63 2d 38 66 39 63 2d 63 35 66 31 35 33 30 66 35 39 66 37) | (63 00 61 00 61 00 37 00 61 00 62 00 39 00 37 00 2d 00 66 00 38 00 33 00 62 00 2d 00 34 00 33 00 32 00 63 00 2d 00 38 00 66 00 39 00 63 00 2d 00 63 00 35 00 66 00 31 00 35 00 33 00 30 00 66 00 35 00 39 00 66 00 37 00))}
		$typelibguid1up = {((43 41 41 37 41 42 39 37 2d 46 38 33 42 2d 34 33 32 43 2d 38 46 39 43 2d 43 35 46 31 35 33 30 46 35 39 46 37) | (43 00 41 00 41 00 37 00 41 00 42 00 39 00 37 00 2d 00 46 00 38 00 33 00 42 00 2d 00 34 00 33 00 32 00 43 00 2d 00 38 00 46 00 39 00 43 00 2d 00 43 00 35 00 46 00 31 00 35 00 33 00 30 00 46 00 35 00 39 00 46 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_TokenStomp : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/MartinIngesen/TokenStomp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2022-11-21"
		modified = "2023-04-06"
		id = "e4266969-ab03-50dc-b5b1-f4bb1c9846f4"

	strings:
		$typelibguid0lo = {((38 61 61 63 32 37 31 66 2d 39 62 30 62 2d 34 64 63 33 2d 38 61 61 36 2d 38 31 32 62 62 37 61 35 37 65 37 62) | (38 00 61 00 61 00 63 00 32 00 37 00 31 00 66 00 2d 00 39 00 62 00 30 00 62 00 2d 00 34 00 64 00 63 00 33 00 2d 00 38 00 61 00 61 00 36 00 2d 00 38 00 31 00 32 00 62 00 62 00 37 00 61 00 35 00 37 00 65 00 37 00 62 00))}
		$typelibguid0up = {((38 41 41 43 32 37 31 46 2d 39 42 30 42 2d 34 44 43 33 2d 38 41 41 36 2d 38 31 32 42 42 37 41 35 37 45 37 42) | (38 00 41 00 41 00 43 00 32 00 37 00 31 00 46 00 2d 00 39 00 42 00 30 00 42 00 2d 00 34 00 44 00 43 00 33 00 2d 00 38 00 41 00 41 00 36 00 2d 00 38 00 31 00 32 00 42 00 42 00 37 00 41 00 35 00 37 00 45 00 37 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_KrbRelay : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/cube0x0/KrbRelay"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2022-11-21"
		modified = "2023-04-06"
		id = "3f59986c-8bd8-5e70-b3eb-038247d1ccd7"

	strings:
		$typelibguid0lo = {((65 64 38 33 39 31 35 34 2d 39 30 64 38 2d 34 39 64 62 2d 38 63 64 64 2d 39 37 32 64 31 61 36 62 32 63 66 64) | (65 00 64 00 38 00 33 00 39 00 31 00 35 00 34 00 2d 00 39 00 30 00 64 00 38 00 2d 00 34 00 39 00 64 00 62 00 2d 00 38 00 63 00 64 00 64 00 2d 00 39 00 37 00 32 00 64 00 31 00 61 00 36 00 62 00 32 00 63 00 66 00 64 00))}
		$typelibguid0up = {((45 44 38 33 39 31 35 34 2d 39 30 44 38 2d 34 39 44 42 2d 38 43 44 44 2d 39 37 32 44 31 41 36 42 32 43 46 44) | (45 00 44 00 38 00 33 00 39 00 31 00 35 00 34 00 2d 00 39 00 30 00 44 00 38 00 2d 00 34 00 39 00 44 00 42 00 2d 00 38 00 43 00 44 00 44 00 2d 00 39 00 37 00 32 00 44 00 31 00 41 00 36 00 42 00 32 00 43 00 46 00 44 00))}
		$typelibguid1lo = {((33 62 34 37 65 65 62 63 2d 30 64 33 33 2d 34 65 30 62 2d 62 61 62 35 2d 37 38 32 64 32 64 33 36 38 30 61 66) | (33 00 62 00 34 00 37 00 65 00 65 00 62 00 63 00 2d 00 30 00 64 00 33 00 33 00 2d 00 34 00 65 00 30 00 62 00 2d 00 62 00 61 00 62 00 35 00 2d 00 37 00 38 00 32 00 64 00 32 00 64 00 33 00 36 00 38 00 30 00 61 00 66 00))}
		$typelibguid1up = {((33 42 34 37 45 45 42 43 2d 30 44 33 33 2d 34 45 30 42 2d 42 41 42 35 2d 37 38 32 44 32 44 33 36 38 30 41 46) | (33 00 42 00 34 00 37 00 45 00 45 00 42 00 43 00 2d 00 30 00 44 00 33 00 33 00 2d 00 34 00 45 00 30 00 42 00 2d 00 42 00 41 00 42 00 35 00 2d 00 37 00 38 00 32 00 44 00 32 00 44 00 33 00 36 00 38 00 30 00 41 00 46 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SQLRecon : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/skahwah/SQLRecon"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-01-20"
		modified = "2023-04-06"
		id = "f9ea5283-0a5c-5bde-966c-80869ee25888"

	strings:
		$typelibguid0lo = {((36 31 32 63 37 63 38 32 2d 64 35 30 31 2d 34 31 37 61 2d 62 38 64 62 2d 37 33 32 30 34 66 64 66 64 61 30 36) | (36 00 31 00 32 00 63 00 37 00 63 00 38 00 32 00 2d 00 64 00 35 00 30 00 31 00 2d 00 34 00 31 00 37 00 61 00 2d 00 62 00 38 00 64 00 62 00 2d 00 37 00 33 00 32 00 30 00 34 00 66 00 64 00 66 00 64 00 61 00 30 00 36 00))}
		$typelibguid0up = {((36 31 32 43 37 43 38 32 2d 44 35 30 31 2d 34 31 37 41 2d 42 38 44 42 2d 37 33 32 30 34 46 44 46 44 41 30 36) | (36 00 31 00 32 00 43 00 37 00 43 00 38 00 32 00 2d 00 44 00 35 00 30 00 31 00 2d 00 34 00 31 00 37 00 41 00 2d 00 42 00 38 00 44 00 42 00 2d 00 37 00 33 00 32 00 30 00 34 00 46 00 44 00 46 00 44 00 41 00 30 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Certify : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/Certify"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-06"
		modified = "2023-04-06"
		hash = "da585a8d4985082873cb86204d546d3f53668e034c61e42d247b11e92b5e8fc3"
		id = "69f120fe-bd4d-59ba-b1b9-528ab300e450"

	strings:
		$typelibguid0lo = {((36 34 35 32 34 63 61 35 2d 65 34 64 30 2d 34 31 62 33 2d 61 63 63 33 2d 33 62 64 62 65 66 64 34 30 63 39 37) | (36 00 34 00 35 00 32 00 34 00 63 00 61 00 35 00 2d 00 65 00 34 00 64 00 30 00 2d 00 34 00 31 00 62 00 33 00 2d 00 61 00 63 00 63 00 33 00 2d 00 33 00 62 00 64 00 62 00 65 00 66 00 64 00 34 00 30 00 63 00 39 00 37 00))}
		$typelibguid0up = {((36 34 35 32 34 43 41 35 2d 45 34 44 30 2d 34 31 42 33 2d 41 43 43 33 2d 33 42 44 42 45 46 44 34 30 43 39 37) | (36 00 34 00 35 00 32 00 34 00 43 00 41 00 35 00 2d 00 45 00 34 00 44 00 30 00 2d 00 34 00 31 00 42 00 33 00 2d 00 41 00 43 00 43 00 33 00 2d 00 33 00 42 00 44 00 42 00 45 00 46 00 44 00 34 00 30 00 43 00 39 00 37 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Aladdin : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/nettitude/Aladdin"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-13"
		modified = "2023-04-06"
		id = "3f0a954c-f3b3-5e5d-a71d-11f60b026a48"

	strings:
		$typelibguid0lo = {((62 32 62 33 61 64 62 30 2d 31 36 36 39 2d 34 62 39 34 2d 38 36 63 62 2d 36 64 64 36 38 32 64 64 62 65 61 33) | (62 00 32 00 62 00 33 00 61 00 64 00 62 00 30 00 2d 00 31 00 36 00 36 00 39 00 2d 00 34 00 62 00 39 00 34 00 2d 00 38 00 36 00 63 00 62 00 2d 00 36 00 64 00 64 00 36 00 38 00 32 00 64 00 64 00 62 00 65 00 61 00 33 00))}
		$typelibguid0up = {((42 32 42 33 41 44 42 30 2d 31 36 36 39 2d 34 42 39 34 2d 38 36 43 42 2d 36 44 44 36 38 32 44 44 42 45 41 33) | (42 00 32 00 42 00 33 00 41 00 44 00 42 00 30 00 2d 00 31 00 36 00 36 00 39 00 2d 00 34 00 42 00 39 00 34 00 2d 00 38 00 36 00 43 00 42 00 2d 00 36 00 44 00 44 00 36 00 38 00 32 00 44 00 44 00 42 00 45 00 41 00 33 00))}
		$typelibguid1lo = {((63 34 37 65 34 64 36 34 2d 63 63 37 66 2d 34 39 30 65 2d 38 66 30 39 2d 30 35 35 65 30 30 39 66 33 33 62 61) | (63 00 34 00 37 00 65 00 34 00 64 00 36 00 34 00 2d 00 63 00 63 00 37 00 66 00 2d 00 34 00 39 00 30 00 65 00 2d 00 38 00 66 00 30 00 39 00 2d 00 30 00 35 00 35 00 65 00 30 00 30 00 39 00 66 00 33 00 33 00 62 00 61 00))}
		$typelibguid1up = {((43 34 37 45 34 44 36 34 2d 43 43 37 46 2d 34 39 30 45 2d 38 46 30 39 2d 30 35 35 45 30 30 39 46 33 33 42 41) | (43 00 34 00 37 00 45 00 34 00 44 00 36 00 34 00 2d 00 43 00 43 00 37 00 46 00 2d 00 34 00 39 00 30 00 45 00 2d 00 38 00 46 00 30 00 39 00 2d 00 30 00 35 00 35 00 45 00 30 00 30 00 39 00 46 00 33 00 33 00 42 00 41 00))}
		$typelibguid2lo = {((33 32 61 39 31 62 30 66 2d 33 30 63 64 2d 34 63 37 35 2d 62 65 37 39 2d 63 63 62 64 36 33 34 35 64 65 39 39) | (33 00 32 00 61 00 39 00 31 00 62 00 30 00 66 00 2d 00 33 00 30 00 63 00 64 00 2d 00 34 00 63 00 37 00 35 00 2d 00 62 00 65 00 37 00 39 00 2d 00 63 00 63 00 62 00 64 00 36 00 33 00 34 00 35 00 64 00 65 00 39 00 39 00))}
		$typelibguid2up = {((33 32 41 39 31 42 30 46 2d 33 30 43 44 2d 34 43 37 35 2d 42 45 37 39 2d 43 43 42 44 36 33 34 35 44 45 39 39) | (33 00 32 00 41 00 39 00 31 00 42 00 30 00 46 00 2d 00 33 00 30 00 43 00 44 00 2d 00 34 00 43 00 37 00 35 00 2d 00 42 00 45 00 37 00 39 00 2d 00 43 00 43 00 42 00 44 00 36 00 33 00 34 00 35 00 44 00 45 00 39 00 39 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpLdapRelayScan : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/klezVirus/SharpLdapRelayScan"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-15"
		modified = "2023-04-06"
		id = "554a5487-ac53-512f-8f6f-ad8186144715"

	strings:
		$typelibguid0lo = {((61 39 33 65 65 37 30 36 2d 61 37 31 63 2d 34 63 63 31 2d 62 66 33 37 2d 66 32 36 63 32 37 38 32 35 62 36 38) | (61 00 39 00 33 00 65 00 65 00 37 00 30 00 36 00 2d 00 61 00 37 00 31 00 63 00 2d 00 34 00 63 00 63 00 31 00 2d 00 62 00 66 00 33 00 37 00 2d 00 66 00 32 00 36 00 63 00 32 00 37 00 38 00 32 00 35 00 62 00 36 00 38 00))}
		$typelibguid0up = {((41 39 33 45 45 37 30 36 2d 41 37 31 43 2d 34 43 43 31 2d 42 46 33 37 2d 46 32 36 43 32 37 38 32 35 42 36 38) | (41 00 39 00 33 00 45 00 45 00 37 00 30 00 36 00 2d 00 41 00 37 00 31 00 43 00 2d 00 34 00 43 00 43 00 31 00 2d 00 42 00 46 00 33 00 37 00 2d 00 46 00 32 00 36 00 43 00 32 00 37 00 38 00 32 00 35 00 42 00 36 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_LdapSignCheck : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/cube0x0/LdapSignCheck"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-15"
		modified = "2023-04-06"
		id = "a8b902f0-61a5-509e-8307-79bf557e5f61"

	strings:
		$typelibguid0lo = {((32 31 66 33 39 38 61 39 2d 62 63 33 35 2d 34 62 64 32 2d 62 39 30 36 2d 38 36 36 66 32 31 34 30 39 37 34 34) | (32 00 31 00 66 00 33 00 39 00 38 00 61 00 39 00 2d 00 62 00 63 00 33 00 35 00 2d 00 34 00 62 00 64 00 32 00 2d 00 62 00 39 00 30 00 36 00 2d 00 38 00 36 00 36 00 66 00 32 00 31 00 34 00 30 00 39 00 37 00 34 00 34 00))}
		$typelibguid0up = {((32 31 46 33 39 38 41 39 2d 42 43 33 35 2d 34 42 44 32 2d 42 39 30 36 2d 38 36 36 46 32 31 34 30 39 37 34 34) | (32 00 31 00 46 00 33 00 39 00 38 00 41 00 39 00 2d 00 42 00 43 00 33 00 35 00 2d 00 34 00 42 00 44 00 32 00 2d 00 42 00 39 00 30 00 36 00 2d 00 38 00 36 00 36 00 46 00 32 00 31 00 34 00 30 00 39 00 37 00 34 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpSCCM : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/Mayyhem/SharpSCCM"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-15"
		modified = "2023-04-06"
		id = "276269b1-e3b3-5774-a86a-1c3a8bca8209"

	strings:
		$typelibguid0lo = {((30 33 36 35 32 38 33 36 2d 38 39 38 65 2d 34 61 39 66 2d 62 37 38 31 2d 62 37 64 38 36 65 37 35 30 66 36 30) | (30 00 33 00 36 00 35 00 32 00 38 00 33 00 36 00 2d 00 38 00 39 00 38 00 65 00 2d 00 34 00 61 00 39 00 66 00 2d 00 62 00 37 00 38 00 31 00 2d 00 62 00 37 00 64 00 38 00 36 00 65 00 37 00 35 00 30 00 66 00 36 00 30 00))}
		$typelibguid0up = {((30 33 36 35 32 38 33 36 2d 38 39 38 45 2d 34 41 39 46 2d 42 37 38 31 2d 42 37 44 38 36 45 37 35 30 46 36 30) | (30 00 33 00 36 00 35 00 32 00 38 00 33 00 36 00 2d 00 38 00 39 00 38 00 45 00 2d 00 34 00 41 00 39 00 46 00 2d 00 42 00 37 00 38 00 31 00 2d 00 42 00 37 00 44 00 38 00 36 00 45 00 37 00 35 00 30 00 46 00 36 00 30 00))}
		$typelibguid1lo = {((65 34 64 39 65 66 33 39 2d 30 66 63 65 2d 34 35 37 33 2d 39 37 38 62 2d 61 62 66 38 64 66 36 61 65 63 32 33) | (65 00 34 00 64 00 39 00 65 00 66 00 33 00 39 00 2d 00 30 00 66 00 63 00 65 00 2d 00 34 00 35 00 37 00 33 00 2d 00 39 00 37 00 38 00 62 00 2d 00 61 00 62 00 66 00 38 00 64 00 66 00 36 00 61 00 65 00 63 00 32 00 33 00))}
		$typelibguid1up = {((45 34 44 39 45 46 33 39 2d 30 46 43 45 2d 34 35 37 33 2d 39 37 38 42 2d 41 42 46 38 44 46 36 41 45 43 32 33) | (45 00 34 00 44 00 39 00 45 00 46 00 33 00 39 00 2d 00 30 00 46 00 43 00 45 00 2d 00 34 00 35 00 37 00 33 00 2d 00 39 00 37 00 38 00 42 00 2d 00 41 00 42 00 46 00 38 00 44 00 46 00 36 00 41 00 45 00 43 00 32 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Koh : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/Koh"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-18"
		modified = "2023-04-06"
		id = "9702526c-b10d-553d-a803-47e352533858"

	strings:
		$typelibguid0lo = {((34 64 35 33 35 30 63 38 2d 37 66 38 63 2d 34 37 63 66 2d 38 63 64 65 2d 63 37 35 32 30 31 38 61 66 31 37 65) | (34 00 64 00 35 00 33 00 35 00 30 00 63 00 38 00 2d 00 37 00 66 00 38 00 63 00 2d 00 34 00 37 00 63 00 66 00 2d 00 38 00 63 00 64 00 65 00 2d 00 63 00 37 00 35 00 32 00 30 00 31 00 38 00 61 00 66 00 31 00 37 00 65 00))}
		$typelibguid0up = {((34 44 35 33 35 30 43 38 2d 37 46 38 43 2d 34 37 43 46 2d 38 43 44 45 2d 43 37 35 32 30 31 38 41 46 31 37 45) | (34 00 44 00 35 00 33 00 35 00 30 00 43 00 38 00 2d 00 37 00 46 00 38 00 43 00 2d 00 34 00 37 00 43 00 46 00 2d 00 38 00 43 00 44 00 45 00 2d 00 43 00 37 00 35 00 32 00 30 00 31 00 38 00 41 00 46 00 31 00 37 00 45 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_ForgeCert : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/ForgeCert"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-18"
		modified = "2023-04-06"
		id = "06b3ffbb-5a76-50a0-86dc-b9658bf2d7ec"

	strings:
		$typelibguid0lo = {((62 64 33 34 36 36 38 39 2d 38 65 65 36 2d 34 30 62 33 2d 38 35 38 62 2d 34 65 64 39 34 66 30 38 64 34 30 61) | (62 00 64 00 33 00 34 00 36 00 36 00 38 00 39 00 2d 00 38 00 65 00 65 00 36 00 2d 00 34 00 30 00 62 00 33 00 2d 00 38 00 35 00 38 00 62 00 2d 00 34 00 65 00 64 00 39 00 34 00 66 00 30 00 38 00 64 00 34 00 30 00 61 00))}
		$typelibguid0up = {((42 44 33 34 36 36 38 39 2d 38 45 45 36 2d 34 30 42 33 2d 38 35 38 42 2d 34 45 44 39 34 46 30 38 44 34 30 41) | (42 00 44 00 33 00 34 00 36 00 36 00 38 00 39 00 2d 00 38 00 45 00 45 00 36 00 2d 00 34 00 30 00 42 00 33 00 2d 00 38 00 35 00 38 00 42 00 2d 00 34 00 45 00 44 00 39 00 34 00 46 00 30 00 38 00 44 00 34 00 30 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Crassus : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/vu-ls/Crassus"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-18"
		modified = "2023-04-06"
		id = "d4f94aa3-0431-5ac1-8718-0f0526c3714f"

	strings:
		$typelibguid0lo = {((37 65 39 37 32 39 61 61 2d 34 63 66 32 2d 34 64 30 61 2d 38 31 38 33 2d 37 66 62 37 63 65 37 61 35 62 31 61) | (37 00 65 00 39 00 37 00 32 00 39 00 61 00 61 00 2d 00 34 00 63 00 66 00 32 00 2d 00 34 00 64 00 30 00 61 00 2d 00 38 00 31 00 38 00 33 00 2d 00 37 00 66 00 62 00 37 00 63 00 65 00 37 00 61 00 35 00 62 00 31 00 61 00))}
		$typelibguid0up = {((37 45 39 37 32 39 41 41 2d 34 43 46 32 2d 34 44 30 41 2d 38 31 38 33 2d 37 46 42 37 43 45 37 41 35 42 31 41) | (37 00 45 00 39 00 37 00 32 00 39 00 41 00 41 00 2d 00 34 00 43 00 46 00 32 00 2d 00 34 00 44 00 30 00 41 00 2d 00 38 00 31 00 38 00 33 00 2d 00 37 00 46 00 42 00 37 00 43 00 45 00 37 00 41 00 35 00 42 00 31 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_RestrictedAdmin : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/RestrictedAdmin"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-18"
		modified = "2023-04-06"
		id = "1b3572a5-bb21-58bb-91f9-963a0a17d699"

	strings:
		$typelibguid0lo = {((37 39 66 31 31 66 63 30 2d 61 62 66 66 2d 34 65 31 66 2d 62 30 37 63 2d 35 64 36 35 36 35 33 64 38 39 35 32) | (37 00 39 00 66 00 31 00 31 00 66 00 63 00 30 00 2d 00 61 00 62 00 66 00 66 00 2d 00 34 00 65 00 31 00 66 00 2d 00 62 00 30 00 37 00 63 00 2d 00 35 00 64 00 36 00 35 00 36 00 35 00 33 00 64 00 38 00 39 00 35 00 32 00))}
		$typelibguid0up = {((37 39 46 31 31 46 43 30 2d 41 42 46 46 2d 34 45 31 46 2d 42 30 37 43 2d 35 44 36 35 36 35 33 44 38 39 35 32) | (37 00 39 00 46 00 31 00 31 00 46 00 43 00 30 00 2d 00 41 00 42 00 46 00 46 00 2d 00 34 00 45 00 31 00 46 00 2d 00 42 00 30 00 37 00 43 00 2d 00 35 00 44 00 36 00 35 00 36 00 35 00 33 00 44 00 38 00 39 00 35 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_p2p : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid (p2p Remote Desktop is dual use but 100% flagged as malicious on VT)"
		reference = "https://github.com/miroslavpejic85/p2p"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-19"
		modified = "2023-04-06"
		id = "e7b2b4bd-f1e1-5062-9b36-5df44ae374ea"

	strings:
		$typelibguid0lo = {((33 33 34 35 36 65 37 32 2d 66 38 65 38 2d 34 33 38 34 2d 38 38 63 34 2d 37 30 30 38 36 37 64 66 31 32 65 32) | (33 00 33 00 34 00 35 00 36 00 65 00 37 00 32 00 2d 00 66 00 38 00 65 00 38 00 2d 00 34 00 33 00 38 00 34 00 2d 00 38 00 38 00 63 00 34 00 2d 00 37 00 30 00 30 00 38 00 36 00 37 00 64 00 66 00 31 00 32 00 65 00 32 00))}
		$typelibguid0up = {((33 33 34 35 36 45 37 32 2d 46 38 45 38 2d 34 33 38 34 2d 38 38 43 34 2d 37 30 30 38 36 37 44 46 31 32 45 32) | (33 00 33 00 34 00 35 00 36 00 45 00 37 00 32 00 2d 00 46 00 38 00 45 00 38 00 2d 00 34 00 33 00 38 00 34 00 2d 00 38 00 38 00 43 00 34 00 2d 00 37 00 30 00 30 00 38 00 36 00 37 00 44 00 46 00 31 00 32 00 45 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpWSUS : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/nettitude/SharpWSUS"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		id = "f020eea9-4ff4-5242-b9b2-53284505dab4"

	strings:
		$typelibguid0lo = {((34 32 63 61 62 62 37 34 2d 31 31 39 39 2d 34 30 66 31 2d 39 33 35 34 2d 36 32 39 34 62 62 61 38 64 33 61 34) | (34 00 32 00 63 00 61 00 62 00 62 00 37 00 34 00 2d 00 31 00 31 00 39 00 39 00 2d 00 34 00 30 00 66 00 31 00 2d 00 39 00 33 00 35 00 34 00 2d 00 36 00 32 00 39 00 34 00 62 00 62 00 61 00 38 00 64 00 33 00 61 00 34 00))}
		$typelibguid0up = {((34 32 43 41 42 42 37 34 2d 31 31 39 39 2d 34 30 46 31 2d 39 33 35 34 2d 36 32 39 34 42 42 41 38 44 33 41 34) | (34 00 32 00 43 00 41 00 42 00 42 00 37 00 34 00 2d 00 31 00 31 00 39 00 39 00 2d 00 34 00 30 00 46 00 31 00 2d 00 39 00 33 00 35 00 34 00 2d 00 36 00 32 00 39 00 34 00 42 00 42 00 41 00 38 00 44 00 33 00 41 00 34 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpImpersonation : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/S3cur3Th1sSh1t/SharpImpersonation"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		id = "5815c5bd-e3e8-5f2f-b03e-8a05fb4f6e91"

	strings:
		$typelibguid0lo = {((32 37 61 38 35 32 36 32 2d 38 63 38 37 2d 34 31 34 37 2d 61 39 30 38 2d 34 36 37 32 38 61 62 37 66 63 37 33) | (32 00 37 00 61 00 38 00 35 00 32 00 36 00 32 00 2d 00 38 00 63 00 38 00 37 00 2d 00 34 00 31 00 34 00 37 00 2d 00 61 00 39 00 30 00 38 00 2d 00 34 00 36 00 37 00 32 00 38 00 61 00 62 00 37 00 66 00 63 00 37 00 33 00))}
		$typelibguid0up = {((32 37 41 38 35 32 36 32 2d 38 43 38 37 2d 34 31 34 37 2d 41 39 30 38 2d 34 36 37 32 38 41 42 37 46 43 37 33) | (32 00 37 00 41 00 38 00 35 00 32 00 36 00 32 00 2d 00 38 00 43 00 38 00 37 00 2d 00 34 00 31 00 34 00 37 00 2d 00 41 00 39 00 30 00 38 00 2d 00 34 00 36 00 37 00 32 00 38 00 41 00 42 00 37 00 46 00 43 00 37 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpCloud : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/chrismaddalena/SharpCloud"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		id = "048b0239-ea13-58ff-af35-fd505b4c977a"

	strings:
		$typelibguid0lo = {((63 61 34 65 32 35 37 65 2d 36 39 63 31 2d 34 35 63 35 2d 39 33 37 35 2d 62 61 37 38 37 34 33 37 31 38 39 32) | (63 00 61 00 34 00 65 00 32 00 35 00 37 00 65 00 2d 00 36 00 39 00 63 00 31 00 2d 00 34 00 35 00 63 00 35 00 2d 00 39 00 33 00 37 00 35 00 2d 00 62 00 61 00 37 00 38 00 37 00 34 00 33 00 37 00 31 00 38 00 39 00 32 00))}
		$typelibguid0up = {((43 41 34 45 32 35 37 45 2d 36 39 43 31 2d 34 35 43 35 2d 39 33 37 35 2d 42 41 37 38 37 34 33 37 31 38 39 32) | (43 00 41 00 34 00 45 00 32 00 35 00 37 00 45 00 2d 00 36 00 39 00 43 00 31 00 2d 00 34 00 35 00 43 00 35 00 2d 00 39 00 33 00 37 00 35 00 2d 00 42 00 41 00 37 00 38 00 37 00 34 00 33 00 37 00 31 00 38 00 39 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpSSDP : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/rvrsh3ll/SharpSSDP"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		id = "8441e940-ab7c-5467-9db8-35f71bd57580"

	strings:
		$typelibguid0lo = {((36 65 33 38 33 64 65 34 2d 64 65 38 39 2d 34 32 34 37 2d 61 34 31 61 2d 37 39 64 62 31 64 63 30 33 61 61 61) | (36 00 65 00 33 00 38 00 33 00 64 00 65 00 34 00 2d 00 64 00 65 00 38 00 39 00 2d 00 34 00 32 00 34 00 37 00 2d 00 61 00 34 00 31 00 61 00 2d 00 37 00 39 00 64 00 62 00 31 00 64 00 63 00 30 00 33 00 61 00 61 00 61 00))}
		$typelibguid0up = {((36 45 33 38 33 44 45 34 2d 44 45 38 39 2d 34 32 34 37 2d 41 34 31 41 2d 37 39 44 42 31 44 43 30 33 41 41 41) | (36 00 45 00 33 00 38 00 33 00 44 00 45 00 34 00 2d 00 44 00 45 00 38 00 39 00 2d 00 34 00 32 00 34 00 37 00 2d 00 41 00 34 00 31 00 41 00 2d 00 37 00 39 00 44 00 42 00 31 00 44 00 43 00 30 00 33 00 41 00 41 00 41 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_WireTap : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/djhohnstein/WireTap"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		id = "5513a295-8907-5a9c-adca-760b33004229"

	strings:
		$typelibguid0lo = {((62 35 30 36 37 34 36 38 2d 66 36 35 36 2d 34 35 30 61 2d 62 32 39 63 2d 31 63 38 34 63 66 65 38 64 64 65 35) | (62 00 35 00 30 00 36 00 37 00 34 00 36 00 38 00 2d 00 66 00 36 00 35 00 36 00 2d 00 34 00 35 00 30 00 61 00 2d 00 62 00 32 00 39 00 63 00 2d 00 31 00 63 00 38 00 34 00 63 00 66 00 65 00 38 00 64 00 64 00 65 00 35 00))}
		$typelibguid0up = {((42 35 30 36 37 34 36 38 2d 46 36 35 36 2d 34 35 30 41 2d 42 32 39 43 2d 31 43 38 34 43 46 45 38 44 44 45 35) | (42 00 35 00 30 00 36 00 37 00 34 00 36 00 38 00 2d 00 46 00 36 00 35 00 36 00 2d 00 34 00 35 00 30 00 41 00 2d 00 42 00 32 00 39 00 43 00 2d 00 31 00 43 00 38 00 34 00 43 00 46 00 45 00 38 00 44 00 44 00 45 00 35 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_KittyLitter : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/djhohnstein/KittyLitter"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		id = "f457b91f-4adb-5be6-b9c2-f6cc39d4bdaf"

	strings:
		$typelibguid0lo = {((34 34 39 63 66 32 36 39 2d 34 37 39 38 2d 34 32 36 38 2d 39 61 30 64 2d 39 61 31 37 61 30 38 38 36 39 62 61) | (34 00 34 00 39 00 63 00 66 00 32 00 36 00 39 00 2d 00 34 00 37 00 39 00 38 00 2d 00 34 00 32 00 36 00 38 00 2d 00 39 00 61 00 30 00 64 00 2d 00 39 00 61 00 31 00 37 00 61 00 30 00 38 00 38 00 36 00 39 00 62 00 61 00))}
		$typelibguid0up = {((34 34 39 43 46 32 36 39 2d 34 37 39 38 2d 34 32 36 38 2d 39 41 30 44 2d 39 41 31 37 41 30 38 38 36 39 42 41) | (34 00 34 00 39 00 43 00 46 00 32 00 36 00 39 00 2d 00 34 00 37 00 39 00 38 00 2d 00 34 00 32 00 36 00 38 00 2d 00 39 00 41 00 30 00 44 00 2d 00 39 00 41 00 31 00 37 00 41 00 30 00 38 00 38 00 36 00 39 00 42 00 41 00))}
		$typelibguid1lo = {((65 37 61 35 30 39 61 34 2d 32 64 34 34 2d 34 65 31 30 2d 39 35 62 66 2d 62 38 36 63 62 37 37 36 37 63 32 63) | (65 00 37 00 61 00 35 00 30 00 39 00 61 00 34 00 2d 00 32 00 64 00 34 00 34 00 2d 00 34 00 65 00 31 00 30 00 2d 00 39 00 35 00 62 00 66 00 2d 00 62 00 38 00 36 00 63 00 62 00 37 00 37 00 36 00 37 00 63 00 32 00 63 00))}
		$typelibguid1up = {((45 37 41 35 30 39 41 34 2d 32 44 34 34 2d 34 45 31 30 2d 39 35 42 46 2d 42 38 36 43 42 37 37 36 37 43 32 43) | (45 00 37 00 41 00 35 00 30 00 39 00 41 00 34 00 2d 00 32 00 44 00 34 00 34 00 2d 00 34 00 45 00 31 00 30 00 2d 00 39 00 35 00 42 00 46 00 2d 00 42 00 38 00 36 00 43 00 42 00 37 00 37 00 36 00 37 00 43 00 32 00 43 00))}
		$typelibguid2lo = {((62 32 62 38 64 64 34 66 2d 65 62 61 36 2d 34 32 61 31 2d 61 35 33 64 2d 39 61 30 30 66 65 37 38 35 64 36 36) | (62 00 32 00 62 00 38 00 64 00 64 00 34 00 66 00 2d 00 65 00 62 00 61 00 36 00 2d 00 34 00 32 00 61 00 31 00 2d 00 61 00 35 00 33 00 64 00 2d 00 39 00 61 00 30 00 30 00 66 00 65 00 37 00 38 00 35 00 64 00 36 00 36 00))}
		$typelibguid2up = {((42 32 42 38 44 44 34 46 2d 45 42 41 36 2d 34 32 41 31 2d 41 35 33 44 2d 39 41 30 30 46 45 37 38 35 44 36 36) | (42 00 32 00 42 00 38 00 44 00 44 00 34 00 46 00 2d 00 45 00 42 00 41 00 36 00 2d 00 34 00 32 00 41 00 31 00 2d 00 41 00 35 00 33 00 44 00 2d 00 39 00 41 00 30 00 30 00 46 00 45 00 37 00 38 00 35 00 44 00 36 00 36 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpView : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/tevora-threat/SharpView"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		id = "2ae1bc26-c137-55ce-ae2e-3204ff07f671"

	strings:
		$typelibguid0lo = {((32 32 61 31 35 36 65 61 2d 32 36 32 33 2d 34 35 63 37 2d 38 65 35 30 2d 65 38 36 34 64 39 66 63 34 34 64 33) | (32 00 32 00 61 00 31 00 35 00 36 00 65 00 61 00 2d 00 32 00 36 00 32 00 33 00 2d 00 34 00 35 00 63 00 37 00 2d 00 38 00 65 00 35 00 30 00 2d 00 65 00 38 00 36 00 34 00 64 00 39 00 66 00 63 00 34 00 34 00 64 00 33 00))}
		$typelibguid0up = {((32 32 41 31 35 36 45 41 2d 32 36 32 33 2d 34 35 43 37 2d 38 45 35 30 2d 45 38 36 34 44 39 46 43 34 34 44 33) | (32 00 32 00 41 00 31 00 35 00 36 00 45 00 41 00 2d 00 32 00 36 00 32 00 33 00 2d 00 34 00 35 00 43 00 37 00 2d 00 38 00 45 00 35 00 30 00 2d 00 45 00 38 00 36 00 34 00 44 00 39 00 46 00 43 00 34 00 34 00 44 00 33 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Farmer : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/mdsecactivebreach/Farmer"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		id = "f69745b9-4ebd-547a-9af3-bc340b076e5d"

	strings:
		$typelibguid0lo = {((33 37 64 61 32 35 37 33 2d 64 39 62 35 2d 34 66 63 32 2d 61 65 31 31 2d 63 63 62 36 31 33 30 63 65 61 39 66) | (33 00 37 00 64 00 61 00 32 00 35 00 37 00 33 00 2d 00 64 00 39 00 62 00 35 00 2d 00 34 00 66 00 63 00 32 00 2d 00 61 00 65 00 31 00 31 00 2d 00 63 00 63 00 62 00 36 00 31 00 33 00 30 00 63 00 65 00 61 00 39 00 66 00))}
		$typelibguid0up = {((33 37 44 41 32 35 37 33 2d 44 39 42 35 2d 34 46 43 32 2d 41 45 31 31 2d 43 43 42 36 31 33 30 43 45 41 39 46) | (33 00 37 00 44 00 41 00 32 00 35 00 37 00 33 00 2d 00 44 00 39 00 42 00 35 00 2d 00 34 00 46 00 43 00 32 00 2d 00 41 00 45 00 31 00 31 00 2d 00 43 00 43 00 42 00 36 00 31 00 33 00 30 00 43 00 45 00 41 00 39 00 46 00))}
		$typelibguid1lo = {((34 39 61 63 66 38 36 31 2d 31 63 31 30 2d 34 39 61 31 2d 62 66 32 36 2d 31 33 39 61 33 62 33 61 39 32 32 37) | (34 00 39 00 61 00 63 00 66 00 38 00 36 00 31 00 2d 00 31 00 63 00 31 00 30 00 2d 00 34 00 39 00 61 00 31 00 2d 00 62 00 66 00 32 00 36 00 2d 00 31 00 33 00 39 00 61 00 33 00 62 00 33 00 61 00 39 00 32 00 32 00 37 00))}
		$typelibguid1up = {((34 39 41 43 46 38 36 31 2d 31 43 31 30 2d 34 39 41 31 2d 42 46 32 36 2d 31 33 39 41 33 42 33 41 39 32 32 37) | (34 00 39 00 41 00 43 00 46 00 38 00 36 00 31 00 2d 00 31 00 43 00 31 00 30 00 2d 00 34 00 39 00 41 00 31 00 2d 00 42 00 46 00 32 00 36 00 2d 00 31 00 33 00 39 00 41 00 33 00 42 00 33 00 41 00 39 00 32 00 32 00 37 00))}
		$typelibguid2lo = {((39 61 36 63 30 32 38 66 2d 34 32 33 66 2d 34 63 32 63 2d 38 64 62 33 2d 62 33 34 39 39 31 33 39 62 38 32 32) | (39 00 61 00 36 00 63 00 30 00 32 00 38 00 66 00 2d 00 34 00 32 00 33 00 66 00 2d 00 34 00 63 00 32 00 63 00 2d 00 38 00 64 00 62 00 33 00 2d 00 62 00 33 00 34 00 39 00 39 00 31 00 33 00 39 00 62 00 38 00 32 00 32 00))}
		$typelibguid2up = {((39 41 36 43 30 32 38 46 2d 34 32 33 46 2d 34 43 32 43 2d 38 44 42 33 2d 42 33 34 39 39 31 33 39 42 38 32 32) | (39 00 41 00 36 00 43 00 30 00 32 00 38 00 46 00 2d 00 34 00 32 00 33 00 46 00 2d 00 34 00 43 00 32 00 43 00 2d 00 38 00 44 00 42 00 33 00 2d 00 42 00 33 00 34 00 39 00 39 00 31 00 33 00 39 00 42 00 38 00 32 00 32 00))}
		$typelibguid3lo = {((31 63 38 39 36 38 33 37 2d 65 37 32 39 2d 34 36 61 39 2d 39 32 62 39 2d 33 62 62 65 37 61 63 32 63 39 30 64) | (31 00 63 00 38 00 39 00 36 00 38 00 33 00 37 00 2d 00 65 00 37 00 32 00 39 00 2d 00 34 00 36 00 61 00 39 00 2d 00 39 00 32 00 62 00 39 00 2d 00 33 00 62 00 62 00 65 00 37 00 61 00 63 00 32 00 63 00 39 00 30 00 64 00))}
		$typelibguid3up = {((31 43 38 39 36 38 33 37 2d 45 37 32 39 2d 34 36 41 39 2d 39 32 42 39 2d 33 42 42 45 37 41 43 32 43 39 30 44) | (31 00 43 00 38 00 39 00 36 00 38 00 33 00 37 00 2d 00 45 00 37 00 32 00 39 00 2d 00 34 00 36 00 41 00 39 00 2d 00 39 00 32 00 42 00 39 00 2d 00 33 00 42 00 42 00 45 00 37 00 41 00 43 00 32 00 43 00 39 00 30 00 44 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_AESShellCodeInjector : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/san3ncrypt3d/AESShellCodeInjector"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		id = "6253e30b-7c92-5237-a706-e93403a7c0b6"

	strings:
		$typelibguid0lo = {((62 30 31 36 64 61 39 65 2d 31 32 61 31 2d 34 66 31 64 2d 39 31 61 31 2d 64 36 38 31 61 65 35 34 65 39 32 63) | (62 00 30 00 31 00 36 00 64 00 61 00 39 00 65 00 2d 00 31 00 32 00 61 00 31 00 2d 00 34 00 66 00 31 00 64 00 2d 00 39 00 31 00 61 00 31 00 2d 00 64 00 36 00 38 00 31 00 61 00 65 00 35 00 34 00 65 00 39 00 32 00 63 00))}
		$typelibguid0up = {((42 30 31 36 44 41 39 45 2d 31 32 41 31 2d 34 46 31 44 2d 39 31 41 31 2d 44 36 38 31 41 45 35 34 45 39 32 43) | (42 00 30 00 31 00 36 00 44 00 41 00 39 00 45 00 2d 00 31 00 32 00 41 00 31 00 2d 00 34 00 46 00 31 00 44 00 2d 00 39 00 31 00 41 00 31 00 2d 00 44 00 36 00 38 00 31 00 41 00 45 00 35 00 34 00 45 00 39 00 32 00 43 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpChromium : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/djhohnstein/SharpChromium"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		id = "5364956a-e199-556a-8055-0e7b9a7b14c8"

	strings:
		$typelibguid0lo = {((32 31 33 33 63 36 33 34 2d 34 31 33 39 2d 34 36 36 65 2d 38 39 38 33 2d 39 61 32 33 65 63 39 39 65 30 31 62) | (32 00 31 00 33 00 33 00 63 00 36 00 33 00 34 00 2d 00 34 00 31 00 33 00 39 00 2d 00 34 00 36 00 36 00 65 00 2d 00 38 00 39 00 38 00 33 00 2d 00 39 00 61 00 32 00 33 00 65 00 63 00 39 00 39 00 65 00 30 00 31 00 62 00))}
		$typelibguid0up = {((32 31 33 33 43 36 33 34 2d 34 31 33 39 2d 34 36 36 45 2d 38 39 38 33 2d 39 41 32 33 45 43 39 39 45 30 31 42) | (32 00 31 00 33 00 33 00 43 00 36 00 33 00 34 00 2d 00 34 00 31 00 33 00 39 00 2d 00 34 00 36 00 36 00 45 00 2d 00 38 00 39 00 38 00 33 00 2d 00 39 00 41 00 32 00 33 00 45 00 43 00 39 00 39 00 45 00 30 00 31 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Get_RBCD_Threaded : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/FatRodzianko/Get-RBCD-Threaded"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		id = "fdef6dc3-da1a-5a98-a822-94e443981fdd"

	strings:
		$typelibguid0lo = {((65 32 30 64 63 32 65 64 2d 36 34 35 35 2d 34 31 30 31 2d 39 64 37 38 2d 66 63 63 61 63 31 63 62 37 61 31 38) | (65 00 32 00 30 00 64 00 63 00 32 00 65 00 64 00 2d 00 36 00 34 00 35 00 35 00 2d 00 34 00 31 00 30 00 31 00 2d 00 39 00 64 00 37 00 38 00 2d 00 66 00 63 00 63 00 61 00 63 00 31 00 63 00 62 00 37 00 61 00 31 00 38 00))}
		$typelibguid0up = {((45 32 30 44 43 32 45 44 2d 36 34 35 35 2d 34 31 30 31 2d 39 44 37 38 2d 46 43 43 41 43 31 43 42 37 41 31 38) | (45 00 32 00 30 00 44 00 43 00 32 00 45 00 44 00 2d 00 36 00 34 00 35 00 35 00 2d 00 34 00 31 00 30 00 31 00 2d 00 39 00 44 00 37 00 38 00 2d 00 46 00 43 00 43 00 41 00 43 00 31 00 43 00 42 00 37 00 41 00 31 00 38 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_Whisker : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/eladshamir/Whisker"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		id = "ecb0c59f-2111-58d9-8dc9-dfe005cad3be"

	strings:
		$typelibguid0lo = {((34 32 37 35 30 61 63 30 2d 31 62 66 66 2d 34 66 32 35 2d 38 63 39 64 2d 39 61 66 31 34 34 34 30 33 62 61 64) | (34 00 32 00 37 00 35 00 30 00 61 00 63 00 30 00 2d 00 31 00 62 00 66 00 66 00 2d 00 34 00 66 00 32 00 35 00 2d 00 38 00 63 00 39 00 64 00 2d 00 39 00 61 00 66 00 31 00 34 00 34 00 34 00 30 00 33 00 62 00 61 00 64 00))}
		$typelibguid0up = {((34 32 37 35 30 41 43 30 2d 31 42 46 46 2d 34 46 32 35 2d 38 43 39 44 2d 39 41 46 31 34 34 34 30 33 42 41 44) | (34 00 32 00 37 00 35 00 30 00 41 00 43 00 30 00 2d 00 31 00 42 00 46 00 46 00 2d 00 34 00 46 00 32 00 35 00 2d 00 38 00 43 00 39 00 44 00 2d 00 39 00 41 00 46 00 31 00 34 00 34 00 34 00 30 00 33 00 42 00 41 00 44 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_ShadowSpray : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/Dec0ne/ShadowSpray"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		id = "91dd52ef-07a1-5ffd-b5c3-59bca18d4c7c"

	strings:
		$typelibguid0lo = {((37 65 34 37 64 35 38 36 2d 64 64 63 36 2d 34 33 38 32 2d 38 34 38 63 2d 35 63 66 30 37 39 38 30 38 34 65 31) | (37 00 65 00 34 00 37 00 64 00 35 00 38 00 36 00 2d 00 64 00 64 00 63 00 36 00 2d 00 34 00 33 00 38 00 32 00 2d 00 38 00 34 00 38 00 63 00 2d 00 35 00 63 00 66 00 30 00 37 00 39 00 38 00 30 00 38 00 34 00 65 00 31 00))}
		$typelibguid0up = {((37 45 34 37 44 35 38 36 2d 44 44 43 36 2d 34 33 38 32 2d 38 34 38 43 2d 35 43 46 30 37 39 38 30 38 34 45 31) | (37 00 45 00 34 00 37 00 44 00 35 00 38 00 36 00 2d 00 44 00 44 00 43 00 36 00 2d 00 34 00 33 00 38 00 32 00 2d 00 38 00 34 00 38 00 43 00 2d 00 35 00 43 00 46 00 30 00 37 00 39 00 38 00 30 00 38 00 34 00 45 00 31 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_MalSCCM : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/nettitude/MalSCCM"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		id = "4a88532b-e2bc-5ce9-828d-6ef62d91f6b9"

	strings:
		$typelibguid0lo = {((35 34 33 39 63 65 63 64 2d 33 62 62 33 2d 34 38 30 37 2d 62 33 33 66 2d 65 34 63 32 39 39 62 37 31 63 61 32) | (35 00 34 00 33 00 39 00 63 00 65 00 63 00 64 00 2d 00 33 00 62 00 62 00 33 00 2d 00 34 00 38 00 30 00 37 00 2d 00 62 00 33 00 33 00 66 00 2d 00 65 00 34 00 63 00 32 00 39 00 39 00 62 00 37 00 31 00 63 00 61 00 32 00))}
		$typelibguid0up = {((35 34 33 39 43 45 43 44 2d 33 42 42 33 2d 34 38 30 37 2d 42 33 33 46 2d 45 34 43 32 39 39 42 37 31 43 41 32) | (35 00 34 00 33 00 39 00 43 00 45 00 43 00 44 00 2d 00 33 00 42 00 42 00 33 00 2d 00 34 00 38 00 30 00 37 00 2d 00 42 00 33 00 33 00 46 00 2d 00 45 00 34 00 43 00 32 00 39 00 39 00 42 00 37 00 31 00 43 00 41 00 32 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SpoolSample : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/leechristensen/SpoolSample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		id = "38346575-cf5b-59bf-b2b2-21aacf05b8a4"

	strings:
		$typelibguid0lo = {((36 34 30 63 33 36 62 34 2d 66 34 31 37 2d 34 64 38 35 2d 62 30 33 31 2d 38 33 61 39 64 32 33 63 31 34 30 62) | (36 00 34 00 30 00 63 00 33 00 36 00 62 00 34 00 2d 00 66 00 34 00 31 00 37 00 2d 00 34 00 64 00 38 00 35 00 2d 00 62 00 30 00 33 00 31 00 2d 00 38 00 33 00 61 00 39 00 64 00 32 00 33 00 63 00 31 00 34 00 30 00 62 00))}
		$typelibguid0up = {((36 34 30 43 33 36 42 34 2d 46 34 31 37 2d 34 44 38 35 2d 42 30 33 31 2d 38 33 41 39 44 32 33 43 31 34 30 42) | (36 00 34 00 30 00 43 00 33 00 36 00 42 00 34 00 2d 00 46 00 34 00 31 00 37 00 2d 00 34 00 44 00 38 00 35 00 2d 00 42 00 30 00 33 00 31 00 2d 00 38 00 33 00 41 00 39 00 44 00 32 00 33 00 43 00 31 00 34 00 30 00 42 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule HKTL_NET_GUID_SharpOxidResolver : hardened
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/S3cur3Th1sSh1t/SharpOxidResolver"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		id = "e8a957bc-3319-51c2-8289-01bd0b8a632a"

	strings:
		$typelibguid0lo = {((63 65 35 39 66 38 66 66 2d 30 65 63 66 2d 34 31 65 39 2d 61 31 66 64 2d 31 37 37 36 63 61 30 62 37 30 33 64) | (63 00 65 00 35 00 39 00 66 00 38 00 66 00 66 00 2d 00 30 00 65 00 63 00 66 00 2d 00 34 00 31 00 65 00 39 00 2d 00 61 00 31 00 66 00 64 00 2d 00 31 00 37 00 37 00 36 00 63 00 61 00 30 00 62 00 37 00 30 00 33 00 64 00))}
		$typelibguid0up = {((43 45 35 39 46 38 46 46 2d 30 45 43 46 2d 34 31 45 39 2d 41 31 46 44 2d 31 37 37 36 43 41 30 42 37 30 33 44) | (43 00 45 00 35 00 39 00 46 00 38 00 46 00 46 00 2d 00 30 00 45 00 43 00 46 00 2d 00 34 00 31 00 45 00 39 00 2d 00 41 00 31 00 46 00 44 00 2d 00 31 00 37 00 37 00 36 00 43 00 41 00 30 00 42 00 37 00 30 00 33 00 44 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

