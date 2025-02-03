rule apt28_win_zebrocy_golang_loader_modified : hardened
{
	meta:
		description = "Detects unpacked modified APT28/Sofacy Zebrocy Golang."
		author = "@VK_Intel"
		date = "2018-12-25"
		reference = "https://www.vkremez.com/2018/12/lets-learn-progression-of-apt28sofacy.html"
		id = "cce9ba6c-954c-5b13-a058-cdf7895d63fc"

	strings:
		$go = { 47 6f 20 62 75 69 6c 64 20 49 44 3a 20 }
		$init = { 6d 61 69 6e 2e 69 6e 69 74 }
		$main = {((6d 61 69 6e) | (6d 00 61 00 69 00 6e 00))}
		$scr_git = {67 69 74 68 75 62 2e 63 6f 6d 2f 6b 62 69 6e 61}
		$s0 = {6f 73 2f 65 78 65 63 2e 28 2a 43 6d 64 29 2e 52 75 6e}
		$s1 = {6e 65 74 2f 68 74 74 70 2e 28 2a 68 74 74 70 32 63 6c 69 65 6e 74 43 6f 6e 6e 52 65 61 64 4c 6f 6f 70 29 2e 70 72 6f 63 65 73 73 48 65 61 64 65 72 73}
		$s2 = {6f 73 2e 4d 6b 64 69 72 41 6c 6c}
		$s3 = {6f 73 2e 47 65 74 65 6e 76}
		$s4 = {6f 73 2e 43 72 65 61 74 65}
		$s5 = {69 6f 2f 69 6f 75 74 69 6c 2e 57 72 69 74 65 46 69 6c 65}

	condition:
		uint16( 0 ) == 0x5a4d and $go and $init and all of ( $s* ) and #main > 10 and #scr_git > 5
}

