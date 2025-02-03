rule LuaBot : MALW hardened
{
	meta:
		description = "LuaBot"
		author = "Joan Soriano / @joanbtl"
		date = "2017-06-07"
		version = "1.0"
		MD5 = "9df3372f058874fa964548cbb74c74bf"
		SHA1 = "89226865501ee7d399354656d870b4a9c02db1d3"
		ref1 = "http://blog.malwaremustdie.org/2016/09/mmd-0057-2016-new-elf-botnet-linuxluabot.html"

	strings:
		$a = {4c 55 41 5f 50 41 54 48}
		$b = {48 69 2e 20 48 61 70 70 79 20 72 65 76 65 72 73 69 6e 67 2c 20 79 6f 75 20 63 61 6e 20 6d 61 69 6c 20 6d 65 3a 20 6c 75 61 62 6f 74 40 79 61 6e 64 65 78 2e 72 75}
		$c = {2f 74 6d 70 2f 6c 75 61 5f 58 58 58 58 58 58}
		$d = {4e 4f 54 49 46 59}
		$e = {55 50 44 41 54 45}

	condition:
		all of them
}

