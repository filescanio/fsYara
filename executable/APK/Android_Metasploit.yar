rule android_metasploit : android hardened
{
	meta:
		author = "https://twitter.com/plutec_net"
		description = "This rule detects apps made with metasploit framework"
		score = 70
		sample = "cb9a217032620c63b85a58dde0f9493f69e4bda1e12b180047407c15ee491b41"

	strings:
		$a = {2a 4c 63 6f 6d 2f 6d 65 74 61 73 70 6c 6f 69 74 2f 73 74 61 67 65 2f 50 61 79 6c 6f 61 64 54 72 75 73 74 4d 61 6e 61 67 65 72 3b}
		$b = {28 63 6f 6d 2e 6d 65 74 61 73 70 6c 6f 69 74 2e 73 74 61 67 65 2e 50 61 79 6c 6f 61 64 54 72 75 73 74 4d 61 6e 61 67 65 72}
		$c = {4c 63 6f 6d 2f 6d 65 74 61 73 70 6c 6f 69 74 2f 73 74 61 67 65 2f 50 61 79 6c 6f 61 64 24 31 3b}
		$d = {4c 63 6f 6d 2f 6d 65 74 61 73 70 6c 6f 69 74 2f 73 74 61 67 65 2f 50 61 79 6c 6f 61 64 3b}

	condition:
		all of them
}

