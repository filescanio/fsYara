rule DetectSuspiciousPythonCode : hardened
{
	meta:
		description = "Detects Python code patterns for importing setuptools and requests, requests.get calls, and certain exec/system uses"
		author = "Jan Miller, OPSWAT Inc."
		date = "2024-03-13"
		score = 50

	strings:
		$setuptools = {73 65 74 75 70 74 6f 6f 6c 73}
		$setup = {73 65 74 75 70}
		$import_requests = {69 6d 70 6f 72 74 20 72 65 71 75 65 73 74 73}
		$requests_get_call = {72 65 71 75 65 73 74 73 2e 67 65 74 28}
		$exec_pattern = /\bexec\s*\(.+\)/
		$system_pattern = /\bsystem\s*\((\'|\")pip\s+install.+\)/

	condition:
		($setuptools or $setup ) and $import_requests and $requests_get_call and ( $exec_pattern or $system_pattern )
}

