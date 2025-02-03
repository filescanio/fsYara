rule dropperMapin : android hardened
{
	meta:
		author = "https://twitter.com/plutec_net"
		source = "https://koodous.com/"
		reference = "http://www.welivesecurity.com/2015/09/22/android-trojan-drops-in-despite-googles-bouncer/"
		description = "This rule detects mapin dropper files"
		sample = "7e97b234a5f169e41a2d6d35fadc786f26d35d7ca60ab646fff947a294138768"
		sample2 = "bfd13f624446a2ce8dec9006a16ae2737effbc4e79249fd3d8ea2dc1ec809f1a"
		score = 70

	strings:
		$a = {3a 57 72 69 74 65 20 41 50 4b 20 66 69 6c 65 20 28 66 72 6f 6d 20 74 78 74 20 69 6e 20 61 73 73 65 74 73 29 20 74 6f 20 53 44 43 61 72 64 20 73 75 63 65 73 73 66 75 6c 6c 79 21}
		$b = {34 57 72 69 74 65 20 41 50 4b 20 28 66 72 6f 6d 20 54 78 74 20 69 6e 20 61 73 73 65 74 73 29 20 66 69 6c 65 20 74 6f 20 53 44 43 61 72 64 20 20 46 61 69 6c 21}
		$c = {64 65 76 69 63 65 5f 61 64 6d 69 6e}

	condition:
		all of them
}

rule Mapin : android hardened
{
	meta:
		author = "https://twitter.com/plutec_net"
		source = "https://koodous.com/"
		reference = "http://www.welivesecurity.com/2015/09/22/android-trojan-drops-in-despite-googles-bouncer/"
		description = "Mapin trojan, not for droppers"
		sample = "7f208d0acee62712f3fa04b0c2744c671b3a49781959aaf6f72c2c6672d53776"
		score = 70

	strings:
		$a = {31 33 38 36 37 35 31 35 30 39 36 33}
		$b = {72 65 73 2f 78 6d 6c 2f 64 65 76 69 63 65 5f 61 64 6d 69 6e 2e 78 6d 6c}
		$c = {44 65 76 69 63 65 20 72 65 67 69 73 74 65 72 65 64 3a 20 72 65 67 49 64 20 3d}

	condition:
		all of them
}

