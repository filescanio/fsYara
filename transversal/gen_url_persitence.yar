rule Methodology_Suspicious_Shortcut_Local_URL : hardened limited
{
	meta:
		author = "@itsreallynick (Nick Carr), @QW5kcmV3 (Andrew Thompson)"
		description = "Detects local script usage for .URL persistence"
		reference = "https://twitter.com/cglyer/status/1176184798248919044"
		score = 50
		date = "27.09.2019"
		id = "438d9323-cb6a-5f5d-af71-76692b93436a"

	strings:
		$file = {55 52 4c 3d 66 69 6c 65 3a 2f 2f 2f}
		$url_clsid = {5b 7b 30 30 30 32 31 34 41 30 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d 5d}
		$url_explicit = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d}

	condition:
		$file and any of ( $url* ) and uint16( 0 ) != 0x5A4D and uint32( 0 ) != 0x464c457f and uint32( 0 ) != 0xBEBAFECA and uint32( 0 ) != 0xFEEDFACE and uint32( 0 ) != 0xFEEDFACF and uint32( 0 ) != 0xCEFAEDFE and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_SMB_URL : hardened limited
{
	meta:
		author = "@itsreallynick (Nick Carr), @QW5kcmV3 (Andrew Thompson)"
		description = "Detects remote SMB path for .URL persistence"
		reference = "https://twitter.com/cglyer/status/1176184798248919044"
		sample = "e0bef7497fcb284edb0c65b59d511830"
		score = 50
		date = "27.09.2019"
		id = "e23609a1-9b18-5a56-92ee-c7f84c966865"

	strings:
		$file = /URL=file:\/\/[a-z0-9]/ nocase
		$url_clsid = {5b 7b 30 30 30 32 31 34 41 30 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d 5d}
		$url_explicit = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d}

	condition:
		$file and any of ( $url* ) and uint16( 0 ) != 0x5A4D and uint32( 0 ) != 0x464c457f and uint32( 0 ) != 0xBEBAFECA and uint32( 0 ) != 0xFEEDFACE and uint32( 0 ) != 0xFEEDFACF and uint32( 0 ) != 0xCEFAEDFE and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_IconRemote_SMBorLocal : hardened limited
{
	meta:
		author = "@itsreallynick (Nick Carr)"
		description = "This is the syntax used for NTLM hash stealing via Responder - https://www.securify.nl/nl/blog/SFY20180501/living-off-the-land_-stealing-netntlm-hashes.html"
		reference = "https://twitter.com/ItsReallyNick/status/1176241449148588032"
		score = 50
		date = "27.09.2019"
		id = "9362ce46-265c-5215-bee1-3d784d0cb928"

	strings:
		$icon = {49 63 6f 6e 46 69 6c 65 3d 66 69 6c 65 3a 2f 2f}
		$url_clsid = {5b 7b 30 30 30 32 31 34 41 30 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d 5d}
		$url_explicit = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d}

	condition:
		$icon and any of ( $url* ) and uint16( 0 ) != 0x5A4D and uint32( 0 ) != 0x464c457f and uint32( 0 ) != 0xBEBAFECA and uint32( 0 ) != 0xFEEDFACE and uint32( 0 ) != 0xFEEDFACF and uint32( 0 ) != 0xCEFAEDFE and filesize < 30KB
}

rule Methodology_Shortcut_HotKey : hardened limited
{
	meta:
		author = "@itsreallynick (Nick Carr)"
		description = "Detects possible shortcut usage for .URL persistence"
		reference = "https://twitter.com/cglyer/status/1176184798248919044"
		score = 50
		date = "27.09.2019"
		id = "0ce377c4-db9b-59fa-987b-a77eaf408765"

	strings:
		$hotkey = /[\x0a\x0d]HotKey=[1-9]/ nocase
		$url_clsid = {5b 7b 30 30 30 32 31 34 41 30 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d 5d}
		$url_explicit = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d}

	condition:
		$hotkey and any of ( $url* ) and uint16( 0 ) != 0x5A4D and uint32( 0 ) != 0x464c457f and uint32( 0 ) != 0xBEBAFECA and uint32( 0 ) != 0xFEEDFACE and uint32( 0 ) != 0xFEEDFACF and uint32( 0 ) != 0xCEFAEDFE and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_BaseURLSyntax : hardened limited
{
	meta:
		author = "@itsreallynick (Nick Carr)"
		description = "Detects possible shortcut usage for .URL persistence"
		reference = "https://twitter.com/cglyer/status/1176184798248919044"
		score = 50
		date = "27.09.2019"
		id = "cab7b573-d197-5afc-95a9-ef05a07c2b7a"

	strings:
		$baseurl1 = {42 41 53 45 55 52 4c 3d 66 69 6c 65 3a 2f 2f}
		$baseurl2 = {5b 44 45 46 41 55 4c 54 5d}
		$url_clsid = {5b 7b 30 30 30 32 31 34 41 30 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d 5d}
		$url_explicit = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d}

	condition:
		all of ( $baseurl* ) and any of ( $url* ) and uint16( 0 ) != 0x5A4D and uint32( 0 ) != 0x464c457f and uint32( 0 ) != 0xBEBAFECA and uint32( 0 ) != 0xFEEDFACE and uint32( 0 ) != 0xFEEDFACF and uint32( 0 ) != 0xCEFAEDFE and filesize < 30KB
}

rule Methodology_Contains_Shortcut_OtherURIhandlers : hardened limited
{
	meta:
		author = "@itsreallynick (Nick Carr)"
		description = "Noisy rule for .URL shortcuts containing unique URI handlers"
		description = "Detects possible shortcut usage for .URL persistence"
		reference = "https://twitter.com/cglyer/status/1176184798248919044"
		score = 35
		date = "27.09.2019"
		id = "1c0750d2-2177-5e2c-908b-4226ae099981"

	strings:
		$file = {55 52 4c 3d}
		$filenegate = /[\x0a\x0d](Base|)URL\s*=\s*(https?|file):\/\// nocase
		$url_clsid = {5b 7b 30 30 30 32 31 34 41 30 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d 5d}
		$url_explicit = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d}

	condition:
		$file and any of ( $url* ) and not $filenegate and uint16( 0 ) != 0x5A4D and uint32( 0 ) != 0x464c457f and uint32( 0 ) != 0xBEBAFECA and uint32( 0 ) != 0xFEEDFACE and uint32( 0 ) != 0xFEEDFACF and uint32( 0 ) != 0xCEFAEDFE and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_IconNotFromExeOrDLLOrICO : hardened limited
{
	meta:
		author = "@itsreallynick (Nick Carr)"
		reference = "https://twitter.com/ItsReallyNick/status/1176229087196696577"
		description = "Detects possible shortcut usage for .URL persistence"
		score = 50
		date = "27.09.2019"
		id = "82d0483f-48ee-5d0c-ba7d-73d9e9455423"

	strings:
		$icon = {49 63 6f 6e 46 69 6c 65 3d}
		$icon_negate = /[\x0a\x0d]IconFile=[^\x0d]*\.(dll|exe|ico)\x0d/ nocase
		$url_clsid = {5b 7b 30 30 30 32 31 34 41 30 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d 5d}
		$url_explicit = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d}

	condition:
		any of ( $url* ) and $icon and not $icon_negate and uint16( 0 ) != 0x5A4D and uint32( 0 ) != 0x464c457f and uint32( 0 ) != 0xBEBAFECA and uint32( 0 ) != 0xFEEDFACE and uint32( 0 ) != 0xFEEDFACF and uint32( 0 ) != 0xCEFAEDFE and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_Evasion : hardened limited
{
	meta:
		author = "@itsreallynick (Nick Carr)"
		description = "Non-standard .URLs and evasion"
		reference = "https://twitter.com/DissectMalware/status/1176736510856634368"
		score = 50
		date = "27.09.2019"
		id = "36df4252-2575-5efa-88ce-17e68a349306"

	strings:
		$URI = /[\x0a\x0d](IconFile|(Base|)URL)[^\x0d=]+/ nocase
		$filetype_clsid = {5b 7b 30 30 30 32 31 34 41 30 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d 5d}
		$filetype_explicit = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d}

	condition:
		any of ( $filetype* ) and $URI and uint16( 0 ) != 0x5A4D and uint32( 0 ) != 0x464c457f and uint32( 0 ) != 0xBEBAFECA and uint32( 0 ) != 0xFEEDFACE and uint32( 0 ) != 0xFEEDFACF and uint32( 0 ) != 0xCEFAEDFE and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_LOLcommand : hardened limited
{
	meta:
		author = "@itsreallynick (Nick Carr)"
		reference = "https://twitter.com/ItsReallyNick/status/1176601500069576704"
		description = "Detects possible shortcut usage for .URL persistence"
		score = 50
		date = "27.09.2019"
		modified = "2021-02-14"
		id = "061e7919-17f1-5774-ad7d-fc964dc9a947"

	strings:
		$file1 = /[\x0a\x0d](IconFile|(Base|)URL)\s*=[^\x0d]*(powershell|cmd|certutil|mshta|wscript|cscript|rundll32|wmic|regsvr32|msbuild)(\.exe|)[^\x0d]{2,50}\x0d/ nocase
		$url_clsid = {5b 7b 30 30 30 32 31 34 41 30 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d 5d}
		$url_explicit = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d}

	condition:
		any of ( $url* ) and any of ( $file* ) and uint16( 0 ) != 0x5A4D and uint32( 0 ) != 0x464c457f and uint32( 0 ) != 0xBEBAFECA and uint32( 0 ) != 0xFEEDFACE and uint32( 0 ) != 0xFEEDFACF and uint32( 0 ) != 0xCEFAEDFE and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_WebDAV : hardened limited
{
	meta:
		author = "@itsreallynick (Nick Carr)"
		reference = "https://twitter.com/cglyer/status/1176243536754282497"
		description = "Detects possible shortcut usage for .URL persistence"
		score = 50
		date = "27.09.2019"
		id = "cd660b84-d7c6-52fc-9e1d-76450e5262b1"

	strings:
		$file1 = /[\x0a\x0d](IconFile|(Base|)URL)\s*=\s*\/\/[A-Za-z0-9]/
		$url_clsid = {5b 7b 30 30 30 32 31 34 41 30 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d 5d}
		$url_explicit = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d}

	condition:
		any of ( $url* ) and any of ( $file* ) and uint16( 0 ) != 0x5A4D and uint32( 0 ) != 0x464c457f and uint32( 0 ) != 0xBEBAFECA and uint32( 0 ) != 0xFEEDFACE and uint32( 0 ) != 0xFEEDFACF and uint32( 0 ) != 0xCEFAEDFE and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_ScriptURL : hardened limited
{
	meta:
		author = "@itsreallynick (Nick Carr)"
		description = "Detects possible shortcut usage for .URL persistence"
		reference = "https://twitter.com/cglyer/status/1176184798248919044"
		score = 50
		date = "27.09.2019"
		id = "2f55f8a9-4e4b-5480-9042-da6bb66b2e06"

	strings:
		$file1 = /[\x0a\x0d](IconFile|(Base|)URL)\s*=[^\x0d]*script:/ nocase
		$url_clsid = {5b 7b 30 30 30 32 31 34 41 30 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d 5d}
		$url_explicit = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d}

	condition:
		any of ( $url* ) and any of ( $file* ) and uint16( 0 ) != 0x5A4D and uint32( 0 ) != 0x464c457f and uint32( 0 ) != 0xBEBAFECA and uint32( 0 ) != 0xFEEDFACE and uint32( 0 ) != 0xFEEDFACF and uint32( 0 ) != 0xCEFAEDFE and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_WorkingDirRemote_HTTP : hardened limited
{
	meta:
		author = "@itsreallynick (Nick Carr)"
		description = "Detects possible shortcut usage for .URL persistence"
		reference = "https://twitter.com/cglyer/status/1176184798248919044"
		score = 50
		date = "27.09.2019"
		id = "68e54f8a-11e4-59e4-8498-59d88e70e438"

	strings:
		$icon = {57 6f 72 6b 69 6e 67 44 69 72 65 63 74 6f 72 79 3d 68 74 74 70}
		$url_clsid = {5b 7b 30 30 30 32 31 34 41 30 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d 5d}
		$url_explicit = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d}

	condition:
		$icon and any of ( $url* ) and uint16( 0 ) != 0x5A4D and uint32( 0 ) != 0x464c457f and uint32( 0 ) != 0xBEBAFECA and uint32( 0 ) != 0xFEEDFACE and uint32( 0 ) != 0xFEEDFACF and uint32( 0 ) != 0xCEFAEDFE and filesize < 30KB
}

rule Methodology_Suspicious_Shortcut_WorkingDirRemote_SMB : hardened limited
{
	meta:
		author = "@itsreallynick (Nick Carr)"
		description = "Detects possible shortcut usage for .URL persistence"
		reference = "https://twitter.com/cglyer/status/1176184798248919044"
		score = 50
		date = "27.09.2019"
		id = "26e19fe3-c25c-53b0-9b41-c04803134bc2"

	strings:
		$icon = {57 6f 72 6b 69 6e 67 44 69 72 65 63 74 6f 72 79 3d 66 69 6c 65 3a 2f 2f}
		$url_clsid = {5b 7b 30 30 30 32 31 34 41 30 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d 5d}
		$url_explicit = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d}

	condition:
		$icon and any of ( $url* ) and uint16( 0 ) != 0x5A4D and uint32( 0 ) != 0x464c457f and uint32( 0 ) != 0xBEBAFECA and uint32( 0 ) != 0xFEEDFACE and uint32( 0 ) != 0xFEEDFACF and uint32( 0 ) != 0xCEFAEDFE and filesize < 30KB
}

