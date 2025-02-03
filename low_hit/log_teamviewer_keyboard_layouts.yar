rule LOG_TeamViewer_Connect_Chinese_Keyboard_Layout : hardened
{
	meta:
		description = "Detects a suspicious TeamViewer log entry stating that the remote systems had a Chinese keyboard layout"
		author = "Florian Roth (Nextron Systems)"
		date = "2019-10-12"
		modified = "2020-12-16"
		score = 60
		limit = "Logscan"
		reference = "https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-input-locales-for-windows-language-packs"
		id = "f901818b-5150-540f-b645-686c12784a38"

	strings:
		$x1 = {43 68 61 6e 67 69 6e 67 20 6b 65 79 62 6f 61 72 64 20 6c 61 79 6f 75 74 20 74 6f 3a 20 30 38 30 34}
		$x2 = {43 68 61 6e 67 69 6e 67 20 6b 65 79 62 6f 61 72 64 20 6c 61 79 6f 75 74 20 74 6f 3a 20 30 34 32 61}
		$fp1 = {43 68 61 6e 67 69 6e 67 20 6b 65 79 62 6f 61 72 64 20 6c 61 79 6f 75 74 20 74 6f 3a 20 30 38 30 34 30 38 30 34}
		$fp2 = {43 68 61 6e 67 69 6e 67 20 6b 65 79 62 6f 61 72 64 20 6c 61 79 6f 75 74 20 74 6f 3a 20 30 34 32 61 30 34 32 61}

	condition:
		(#x1 + #x2 ) > ( #fp1 + #fp2 )
}

rule LOG_TeamViewer_Connect_Russian_Keyboard_Layout : hardened
{
	meta:
		description = "Detects a suspicious TeamViewer log entry stating that the remote systems had a Russian keyboard layout"
		author = "Florian Roth (Nextron Systems)"
		date = "2019-10-12"
		modified = "2022-12-07"
		score = 60
		limit = "Logscan"
		reference = "https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-input-locales-for-windows-language-packs"
		id = "360a1cca-2a64-5fd8-bcde-f49e1b17281e"

	strings:
		$x1 = {43 68 61 6e 67 69 6e 67 20 6b 65 79 62 6f 61 72 64 20 6c 61 79 6f 75 74 20 74 6f 3a 20 30 34 31 39}
		$fp1 = {43 68 61 6e 67 69 6e 67 20 6b 65 79 62 6f 61 72 64 20 6c 61 79 6f 75 74 20 74 6f 3a 20 30 34 31 39 30 34 31 39}

	condition:
		#x1> #fp1
}

