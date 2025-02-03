rule Venom_Rootkit : hardened
{
	meta:
		description = "Venom Linux Rootkit"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://security.web.cern.ch/security/venom.shtml"
		date = "2017-01-12"
		id = "fedc6fa9-7dfb-5e54-a7bf-9a16f96d6886"

	strings:
		$s1 = {25 25 56 45 4e 4f 4d 25 43 54 52 4c 25 4d 4f 44 45 25 25}
		$s2 = {25 25 56 45 4e 4f 4d 25 4f 4b 25 4f 4b 25 25}
		$s3 = {25 25 56 45 4e 4f 4d 25 57 49 4e 25 57 4e 25 25}
		$s4 = {25 25 56 45 4e 4f 4d 25 41 55 54 48 45 4e 54 49 43 41 54 45 25 25}
		$s5 = {2e 20 65 6e 74 65 72 69 6e 67 20 69 6e 74 65 72 61 63 74 69 76 65 20 73 68 65 6c 6c}
		$s6 = {2e 20 70 72 6f 63 65 73 73 69 6e 67 20 6c 74 75 6e 20 72 65 71 75 65 73 74}
		$s7 = {2e 20 70 72 6f 63 65 73 73 69 6e 67 20 72 74 75 6e 20 72 65 71 75 65 73 74}
		$s8 = {2e 20 70 72 6f 63 65 73 73 69 6e 67 20 67 65 74 20 72 65 71 75 65 73 74}
		$s9 = {2e 20 70 72 6f 63 65 73 73 69 6e 67 20 70 75 74 20 72 65 71 75 65 73 74}
		$s10 = {76 65 6e 6f 6d 20 62 79 20 6d 6f 75 7a 6f 6e 65}
		$s11 = {6a 75 73 74 43 41 4e 54 62 65 53 54 4f 50 50 45 44}

	condition:
		filesize < 4000KB and 2 of them
}

