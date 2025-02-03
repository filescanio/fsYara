rule wineggdrop : portscanner toolkit hardened
{
	meta:
		author = "Christian Rebischke (@sh1bumi)"
		date = "2015-09-05"
		description = "Rules for TCP Portscanner VX.X by WinEggDrop"
		score = 75
		in_the_wild = true
		family = "Hackingtool/Portscanner"

	strings:
		$a = { 54 43 50 20 50 6f 72 74 20 53 63 61 6e 6e 65 72 
               20 56 3? 2e 3? 20 42 79 20 57 69 6e 45 67 67 44 
               72 6f 70 0a }
		$b = {52 65 73 75 6c 74 2e 74 78 74}
		$c = {55 73 61 67 65 3a 20 20 20 25 73 20 54 43 50 2f 53 59 4e 20 53 74 61 72 74 49 50 20 5b 45 6e 64 49 50 5d 20 50 6f 72 74 73 20 5b 54 68 72 65 61 64 73 5d 20 5b 2f 54 28 4e 29 5d 20 5b 2f 28 48 29 42 61 6e 6e 65 72 5d 20 5b 2f 53 61 76 65 5d 0a}

	condition:
		uint16( 0 ) == 0x5A4D and $a and $b and $c
}

