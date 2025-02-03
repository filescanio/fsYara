rule gen_unicorn_obfuscated_powershell : hardened
{
	meta:
		description = "PowerShell payload obfuscated by Unicorn toolkit"
		author = "John Lambert @JohnLaTwC"
		date = "2018-04-03"
		hash = "b93d2fe6a671a6a967f31d5b3a0a16d4f93abcaf25188a2bbdc0894087adb10d"
		hash2 = "1afb9795cb489abce39f685a420147a2875303a07c32bf7eec398125300a460b"
		reference = "https://github.com/trustedsec/unicorn/"
		id = "0235795b-6d0b-5bba-8ae6-606c3b613c86"

	strings:
		$h1 = {70 6f 77 65 72 73 68 65 6c 6c}
		$sa1 = {2e 76 61 6c 75 65 2e 74 6f 53 74 72 69 6e 67 28 29 20 27 4a 41 42}
		$sa2 = {2e 76 61 6c 75 65 2e 74 6f 53 74 72 69 6e 67 28 29 20 28 27 4a 41 42}
		$sb1 = {2d 77 20 31 20 2d 43 20 22 73}
		$sb2 = {2f 77 20 31 20 2f 43 20 22 73}

	condition:
		filesize < 20KB and uint32be( 0 ) == 0x706f7765 and $h1 at 0 and ( uint16be( filesize - 2 ) == 0x2722 or ( uint16be( filesize - 2 ) == 0x220a and uint8( filesize - 3 ) == 0x27 ) or ( uint16be( filesize - 2 ) == 0x2922 and uint8( filesize - 3 ) == 0x27 ) ) and ( 1 of ( $sa* ) and 1 of ( $sb* ) )
}

