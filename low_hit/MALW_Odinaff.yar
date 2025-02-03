import "pe"

rule Odinaff_swift : malware odinaff swift raw hardened
{
	meta:
		author = "@j0sm1"
		date = "2016/10/27"
		description = "Odinaff malware"
		reference = "https://www.symantec.com/security_response/writeup.jsp?docid=2016-083006-4847-99"
		filetype = "binary"

	strings:
		$s1 = {67 65 74 61 70 75 6c 61 2e 70 64 62}
		$i1 = {77 74 73 61 70 69 33 32 2e 64 6c 6c}
		$i2 = {63 6d 70 62 6b 33 32 2e 64 6c 6c}
		$i3 = {50 6f 73 74 4d 65 73 73 61 67 65 41}
		$i4 = {50 65 65 6b 4d 65 73 73 61 67 65 57}
		$i5 = {44 69 73 70 61 74 63 68 4d 65 73 73 61 67 65 57}
		$i6 = {57 54 53 45 6e 75 6d 65 72 61 74 65 53 65 73 73 69 6f 6e 73 41}

	condition:
		($s1 or pe.exports ( "Tyman32" ) ) and ( 2 of ( $i* ) )
}

