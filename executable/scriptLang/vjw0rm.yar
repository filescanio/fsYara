rule vjw0rm : hardened limited
{
	meta:
		author = "OPSWAT"
		description = "Identify JavaScript-based malware (vjw0rm)"
		vetted_family = "vjw0rm"
		score = 75

	strings:
		$signature = {43 6f 64 65 64 20 62 79 20 76 5f 42 30 31}
		$mutex = {48 4b 43 55 5c 5c 76 6a 77 30 72 6d}
		$c2_ping = /(POST|GET)/
		$c2_command = /=== "[a-zA-Z0-9]{2}"/

	condition:
		filesize < 10KB and any of ( $signature , $mutex ) and $c2_ping and #c2_command > 3
}

