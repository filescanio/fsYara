rule Base64_PS1_Shellcode : hardened
{
	meta:
		description = "Detects Base64 encoded PS1 Shellcode"
		author = "Nick Carr, David Ledbetter"
		reference = "https://twitter.com/ItsReallyNick/status/1062601684566843392"
		date = "2018-11-14"
		score = 65
		id = "7c3cec3b-a192-5bfd-b4f1-22b1afeb717e"

	strings:
		$substring = {41 41 41 41 59 49 6e 6c 4d}
		$pattern1 = {2f 4f 69 43 41 41 41 41 59 49 6e 6c 4d}
		$pattern2 = {2f 4f 69 4a 41 41 41 41 59 49 6e 6c 4d}

	condition:
		$substring and 1 of ( $p* )
}

