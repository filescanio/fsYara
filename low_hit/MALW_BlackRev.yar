rule BlackRev : hardened
{
	meta:
		author = "Dennis Schwarz"
		date = "2013-05-21"
		description = "Black Revolution DDoS Malware. http://www.arbornetworks.com/asert/2013/05/the-revolution-will-be-written-in-delphi/"
		origin = "https://github.com/arbor/yara/blob/master/blackrev.yara"

	strings:
		$base1 = {68 74 74 70}
		$base2 = {73 69 6d 70 6c 65}
		$base3 = {6c 6f 67 69 6e 70 6f 73 74}
		$base4 = {64 61 74 61 70 6f 73 74}
		$opt1 = {62 6c 61 63 6b 72 65 76}
		$opt2 = {73 74 6f 70}
		$opt3 = {64 69 65}
		$opt4 = {73 6c 65 65 70}
		$opt5 = {73 79 6e}
		$opt6 = {75 64 70}
		$opt7 = {75 64 70 64 61 74 61}
		$opt8 = {69 63 6d 70}
		$opt9 = {61 6e 74 69 64 64 6f 73}
		$opt10 = {72 61 6e 67 65}
		$opt11 = {66 61 73 74 64 64 6f 73}
		$opt12 = {73 6c 6f 77 68 74 74 70}
		$opt13 = {61 6c 6c 68 74 74 70}
		$opt14 = {74 63 70 64 61 74 61}
		$opt15 = {64 61 74 61 67 65 74}

	condition:
		all of ( $base* ) and 5 of ( $opt* )
}

