rule DirtJumper_drive : hardened
{
	meta:
		author = "Jason Jones <jasonjones@arbor.net>"
		date = "2013-08-26"
		description = "Identify first version of drive DDoS malware"
		source = "https://github.com/arbor/yara/blob/master/drive.yara"

	strings:
		$cmd1 = {2d 67 65 74}
		$cmd2 = {2d 69 70}
		$cmd3 = {2d 69 70 32}
		$cmd4 = {2d 70 6f 73 74 31}
		$cmd5 = {2d 70 6f 73 74 32}
		$cmd6 = {2d 75 64 70}
		$str1 = {6c 6f 67 69 6e 3d 5b 31 30 30 30 5d 26 70 61 73 73 3d 5b 31 30 30 30 5d 26 70 61 73 73 77 6f 72 64 3d 5b 35 30 5d 26 6c 6f 67 3d 5b 35 30 5d 26 70 61 73 73 77 72 64 3d 5b 35 30 5d 26 75 73 65 72 3d 5b 35 30 5d 26 75 73 65 72 6e 61 6d 65 3d 5b 35 30 5d 26 76 62 5f 6c 6f 67 69 6e 5f 75 73 65 72 6e 61 6d 65 3d 5b 35 30 5d 26 76 62 5f 6c 6f 67 69 6e 5f 6d 64 35 70 61 73 73 77 6f 72 64 3d 5b 35 30 5d}
		$str2 = {2d 74 69 6d 65 6f 75 74}
		$str3 = {2d 74 68 72 65 61 64}
		$str4 = {20 4c 6f 63 61 6c 3b 20 72 75 29 20 50 72 65 73 74 6f 2f 32 2e 31 30 2e 32 38 39 20 56 65 72 73 69 6f 6e 2f}
		$str5 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 38 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54}
		$newver1 = {2d 69 63 6d 70}
		$newver2 = {3c 78 6d 70 3e}

	condition:
		4 of ( $cmd* ) and all of ( $str* ) and not any of ( $newver* )
}

rule DirtJumper_drive2 : hardened
{
	meta:
		author = "Jason Jones <jasonjones@arbor.net>"
		date = "2013-08-26"
		description = "Identify newer version of drive DDoS malware"
		source = "https://github.com/arbor/yara/blob/master/drive2.yara"

	strings:
		$cmd1 = {2d 67 65 74}
		$cmd2 = {2d 69 70}
		$cmd3 = {2d 69 70 32}
		$cmd4 = {2d 70 6f 73 74 31}
		$cmd5 = {2d 70 6f 73 74 32}
		$cmd6 = {2d 75 64 70}
		$str1 = {6c 6f 67 69 6e 3d 5b 31 30 30 30 5d 26 70 61 73 73 3d 5b 31 30 30 30 5d 26 70 61 73 73 77 6f 72 64 3d 5b 35 30 5d 26 6c 6f 67 3d 5b 35 30 5d 26 70 61 73 73 77 72 64 3d 5b 35 30 5d 26 75 73 65 72 3d 5b 35 30 5d 26 75 73 65 72 6e 61 6d 65 3d 5b 35 30 5d 26 76 62 5f 6c 6f 67 69 6e 5f 75 73 65 72 6e 61 6d 65 3d 5b 35 30 5d 26 76 62 5f 6c 6f 67 69 6e 5f 6d 64 35 70 61 73 73 77 6f 72 64 3d 5b 35 30 5d}
		$str2 = {2d 74 69 6d 65 6f 75 74}
		$str3 = {2d 74 68 72 65 61 64}
		$str4 = {20 4c 6f 63 61 6c 3b 20 72 75 29 20 50 72 65 73 74 6f 2f 32 2e 31 30 2e 32 38 39 20 56 65 72 73 69 6f 6e 2f}
		$str5 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 38 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54}
		$newver1 = {2d 69 63 6d 70}
		$newver2 = {2d 62 79 74 65}
		$newver3 = {2d 6c 6f 6e 67}
		$newver4 = {3c 78 6d 70 3e}

	condition:
		4 of ( $cmd* ) and all of ( $str* ) and all of ( $newver* )
}

rule DirtJumper_drive3 : hardened
{
	meta:
		author = "Jason Jones <jasonjones@arbor.net>"
		date = "2014-03-17"
		description = "Identify version of Drive DDoS malware using compromised sites"
		source = "https://github.com/arbor/yara/blob/master/drive3.yara"

	strings:
		$cmd1 = {2d 67 65 74}
		$cmd2 = {2d 69 70}
		$cmd3 = {2d 69 70 32}
		$cmd4 = {2d 70 6f 73 74 31}
		$cmd5 = {2d 70 6f 73 74 32}
		$cmd6 = {2d 75 64 70}
		$str1 = {6c 6f 67 69 6e 3d 5b 31 30 30 30 5d 26 70 61 73 73 3d 5b 31 30 30 30 5d 26 70 61 73 73 77 6f 72 64 3d 5b 35 30 5d 26 6c 6f 67 3d 5b 35 30 5d 26 70 61 73 73 77 72 64 3d 5b 35 30 5d 26 75 73 65 72 3d 5b 35 30 5d 26 75 73 65 72 6e 61 6d 65 3d 5b 35 30 5d 26 76 62 5f 6c 6f 67 69 6e 5f 75 73 65 72 6e 61 6d 65 3d 5b 35 30 5d 26 76 62 5f 6c 6f 67 69 6e 5f 6d 64 35 70 61 73 73 77 6f 72 64 3d 5b 35 30 5d}
		$str2 = {2d 74 69 6d 65 6f 75 74}
		$str3 = {2d 74 68 72 65 61 64}
		$str4 = {20 4c 6f 63 61 6c 3b 20 72 75 29 20 50 72 65 73 74 6f 2f 32 2e 31 30 2e 32 38 39 20 56 65 72 73 69 6f 6e 2f}
		$str5 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 38 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54}
		$newver1 = {2d 69 63 6d 70}
		$newver2 = {2d 62 79 74 65}
		$newver3 = {2d 6c 6f 6e 67}
		$drive3 = {39 39 3d 31}

	condition:
		4 of ( $cmd* ) and all of ( $str* ) and all of ( $newver* ) and $drive3
}

