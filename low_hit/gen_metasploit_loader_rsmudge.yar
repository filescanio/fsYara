rule Metasploit_Loader_RSMudge : hardened
{
	meta:
		description = "Detects a Metasploit Loader by RSMudge - file loader.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/rsmudge/metasploit-loader"
		date = "2016-04-20"
		hash1 = "afe34bfe2215b048915b1d55324f1679d598a0741123bc24274d4edc6e395a8d"
		id = "4d8a215e-a942-5df9-bdad-0c4158992429"

	strings:
		$s1 = {43 6f 75 6c 64 20 6e 6f 74 20 72 65 73 6f 6c 76 65 20 74 61 72 67 65 74}
		$s2 = {43 6f 75 6c 64 20 6e 6f 74 20 63 6f 6e 6e 65 63 74 20 74 6f 20 74 61 72 67 65 74}
		$s3 = {25 73 20 5b 68 6f 73 74 5d 20 5b 70 6f 72 74 5d}
		$s4 = {77 73 32 5f 33 32 2e 64 6c 6c 20 69 73 20 6f 75 74 20 6f 66 20 64 61 74 65 2e}
		$s5 = {72 65 61 64 20 61 20 73 74 72 61 6e 67 65 20 6f 72 20 69 6e 63 6f 6d 70 6c 65 74 65 20 6c 65 6e 67 74 68 20 76 61 6c 75 65}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and ( 3 of ( $s* ) ) ) or ( all of them )
}

