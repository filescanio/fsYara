rule NTLM_Dump_Output : hardened
{
	meta:
		description = "NTML Hash Dump output file - John/LC format"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015-10-01"
		score = 75
		id = "d17ee473-317b-57d4-8ea8-7c89e8f2b2ed"

	strings:
		$s0 = {35 30 30 3a 41 41 44 33 42 34 33 35 42 35 31 34 30 34 45 45 41 41 44 33 42 34 33 35 42 35 31 34 30 34 45 45 3a}
		$s1 = {35 30 30 3a 61 61 64 33 62 34 33 35 62 35 31 34 30 34 65 65 61 61 64 33 62 34 33 35 62 35 31 34 30 34 65 65 3a}

	condition:
		1 of them
}

rule Gsecdump_password_dump_file : hardened
{
	meta:
		description = "Detects a gsecdump output file"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://t.co/OLIj1yVJ4m"
		date = "2018-03-06"
		score = 65
		id = "c7c8ab61-f728-5eb2-a5e3-b3dd84980870"

	strings:
		$x1 = {41 64 6d 69 6e 69 73 74 72 61 74 6f 72 28 63 75 72 72 65 6e 74 29 3a 35 30 30 3a}

	condition:
		uint32be( 0 ) == 0x41646d69 and filesize < 3000 and $x1 at 0
}

rule SUSP_ZIP_NtdsDIT : T1003_003 hardened
{
	meta:
		description = "Detects ntds.dit files in ZIP archives that could be a left over of administrative activity or traces of data exfiltration"
		author = "Florian Roth (Nextron Systems)"
		score = 50
		reference = "https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/"
		date = "2020-08-10"
		id = "131ed73d-bb34-5ff6-b145-f95e4469d7f9"

	strings:
		$s1 = {6e 74 64 73 2e 64 69 74}

	condition:
		uint16( 0 ) == 0x4b50 and $s1 in ( 0 .. 256 )
}

