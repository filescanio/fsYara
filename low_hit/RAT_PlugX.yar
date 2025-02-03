rule PlugXStrings : PlugX Family hardened limited
{
	meta:
		description = "PlugX Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-12"

	strings:
		$BootLDR = {((62 6f 6f 74 2e 6c 64 72) | (62 00 6f 00 6f 00 74 00 2e 00 6c 00 64 00 72 00))}
		$Dwork = {64 3a 5c 77 6f 72 6b}
		$Plug25 = {70 6c 75 67 32 2e 35}
		$Plug30 = {50 6c 75 67 33 2e 30}
		$Shell6 = {53 68 65 6c 6c 36}

	condition:
		$BootLDR or ( $Dwork and ( $Plug25 or $Plug30 or $Shell6 ) )
}

rule plugX : rat hardened
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "PlugX RAT"
		date = "2014-05-13"
		filetype = "memory"
		version = "1.0"
		ref1 = "https://github.com/mattulm/IR-things/blob/master/volplugs/plugx.py"

	strings:
		$v1a = { 47 55 4C 50 00 00 00 00 }
		$v1b = {2f 75 70 64 61 74 65 3f 69 64 3d 25 38 2e 38 78}
		$v1algoa = { BB 33 33 33 33 2B }
		$v1algob = { BB 44 44 44 44 2B }
		$v2a = {50 72 6f 78 79 2d 41 75 74 68 3a}
		$v2b = { 68 A0 02 00 00 }
		$v2k = { C1 8F 3A 71 }

	condition:
		$v1a at 0 or $v1b or ( ( $v2a or $v2b ) and ( ( $v1algoa and $v1algob ) or $v2k ) )
}

rule PlugX_mw : hardened
{
	meta:
		maltype = "plugX"
		author = "https://github.com/reed1713"
		reference = "http://www.fireeye.com/blog/technical/targeted-attack/2014/02/operation-greedywonk-multiple-economic-and-foreign-policy-sites-compromised-serving-up-flash-zero-day-exploit.html"
		description = "Malware creates a randomized directory within the appdata roaming directory and launches the malware. Should see multiple events for create process rundll32.exe and iexplorer.exe as it repeatedly uses iexplorer to launch the rundll32 process."

	strings:
		$type = {4d 69 63 72 6f 73 6f 66 74 2d 57 69 6e 64 6f 77 73 2d 53 65 63 75 72 69 74 79 2d 41 75 64 69 74 69 6e 67}
		$eventid = {34 36 38 38}
		$data = /\\AppData\\Roaming\\[0-9]{9,12}\VMwareCplLauncher\.exe/
		$type1 = {4d 69 63 72 6f 73 6f 66 74 2d 57 69 6e 64 6f 77 73 2d 53 65 63 75 72 69 74 79 2d 41 75 64 69 74 69 6e 67}
		$eventid1 = {34 36 38 38}
		$data1 = {5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65}
		$type2 = {4d 69 63 72 6f 73 6f 66 74 2d 57 69 6e 64 6f 77 73 2d 53 65 63 75 72 69 74 79 2d 41 75 64 69 74 69 6e 67}
		$eventid2 = {34 36 38 38}
		$data2 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65}

	condition:
		all of them
}

