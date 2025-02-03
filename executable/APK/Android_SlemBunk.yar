rule SlemBunk : android hardened
{
	meta:
		description = "Rule to detect trojans imitating banks of North America, Eurpope and Asia"
		author = "@plutec_net"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
		score = 65
		source = "https://www.fireeye.com/blog/threat-research/2015/12/slembunk_an_evolvin.html"

	strings:
		$a = {23 69 6e 74 65 72 63 65 70 74 5f 73 6d 73 5f 73 74 61 72 74}
		$b = {23 69 6e 74 65 72 63 65 70 74 5f 73 6d 73 5f 73 74 6f 70}
		$c = {23 62 6c 6f 63 6b 5f 6e 75 6d 62 65 72 73}
		$d = {23 77 69 70 65 5f 64 61 74 61}
		$e = {56 69 73 61 20 45 6c 65 63 74 72 6f 6e}

	condition:
		all of them
}

