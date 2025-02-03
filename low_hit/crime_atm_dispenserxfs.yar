import "pe"

rule ATM_Malware_DispenserXFS : hardened
{
	meta:
		description = "Detects ATM Malware DispenserXFS"
		author = "@Xylit0l @r3c0nst / Modified by Florian Roth"
		reference = "https://twitter.com/r3c0nst/status/1100775857306652673"
		date = "2019/02/27"
		modified = "2023-01-06"
		score = 80
		id = "7c06102c-93d3-52f4-8c25-430f6f7a601f"

	strings:
		$xc1 = { 68 FF FF 00 00 68 60 EA 00 00 6A 10 }
		$s1 = {5c 64 69 73 70 65 6e 73 65 72 58 46 53 2e 70 64 62}
		$s3 = {43 3a 5c 78 66 73 61 73 64 66 2e 74 78 74}
		$s4 = {49 6e 6a 65 63 74 65 64 20 6d 78 73 66 73 20 6b 69 6c 6c 65 72 20 69 6e 74 6f 20 25 64 2e}
		$s5 = {57 61 69 74 69 6e 67 20 66 6f 72 20 66 72 65 65 7a 65 20 6d 73 78 66 73 20 70 72 6f 63 65 73 73 65 73 2e 2e 2e}

	condition:
		uint16( 0 ) == 0x5A4D and ( 1 of them or pe.imphash ( ) == "617e037ae26d1931818db0790fb44bfe" )
}

