rule HKTL_PowerSploit : hardened limited
{
	meta:
		description = "Detects default strings used by PowerSploit to establish persistence"
		author = "Markus Neis"
		reference = "https://www.hybrid-analysis.com/sample/16937e76db6d88ed0420ee87317424af2d4e19117fe12d1364fee35aa2fadb75?environmentId=100"
		date = "2018-06-23"
		hash1 = "16937e76db6d88ed0420ee87317424af2d4e19117fe12d1364fee35aa2fadb75"
		id = "8cb0753c-c5bb-56fc-b492-4e785f4bdaf4"

	strings:
		$ps = {((66 75 6e 63 74 69 6f 6e) | (66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00))}
		$s1 = {((2f 43 72 65 61 74 65 20 2f 52 55 20 73 79 73 74 65 6d 20 2f 53 43 20 4f 4e 4c 4f 47 4f 4e) | (2f 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 52 00 55 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00 2f 00 53 00 43 00 20 00 4f 00 4e 00 4c 00 4f 00 47 00 4f 00 4e 00))}
		$s2 = {((53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e) | (53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00))}

	condition:
		all of them
}

