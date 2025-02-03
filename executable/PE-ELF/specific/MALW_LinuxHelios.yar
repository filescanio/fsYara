rule LinuxHelios : MALW hardened
{
	meta:
		description = "Linux.Helios"
		author = "Joan Soriano / @w0lfvan"
		date = "2017-10-19"
		version = "1.0"
		MD5 = "1a35193f3761662a9a1bd38b66327f49"
		SHA256 = "72c2e804f185bef777e854fe86cff3e86f00290f32ae8b3cb56deedf201f1719"

	strings:
		$a = {4c 49 4b 45 20 41 20 47 4f 44 21 21 21 20 49 50 3a 25 73 20 55 73 65 72 3a 25 73 20 50 61 73 73 3a 25 73}
		$b = {73 6d 61 63 6b}
		$c = {50 45 41 43 45 20 4f 55 54 20 49 4d 4d 41 20 44 55 50 0a}

	condition:
		all of them
}

