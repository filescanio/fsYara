rule LokiBot_Dropper_ScanCopyPDF_Feb18 : hardened
{
	meta:
		description = "Auto-generated rule - file Scan Copy.pdf.com"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://app.any.run/tasks/401df4d9-098b-4fd0-86e0-7a52ce6ddbf5"
		date = "2018-02-14"
		hash1 = "6f8ff26a5daf47effdea5795cdadfff9265c93a0ebca0ce5a4144712f8cab5be"
		id = "64c45d91-4e18-5fd1-8d93-b5db4df7da29"

	strings:
		$x1 = {57 00 69 00 6e 00 33 00 32 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 53 00 63 00 61 00 6e 00 20 00 43 00 6f 00 70 00 79 00 2e 00 70 00 64 00 66 00 20 00 20 00 20 00}
		$a1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 5c 4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 39 38 5c 56 42 36 2e 4f 4c 42}
		$s1 = {43 00 6f 00 6d 00 70 00 69 00 6c 00 69 00 6e 00 67 00 32 00 2e 00 65 00 78 00 65 00}
		$s2 = {55 6e 73 74 61 6c 6c 65 64 32}
		$s3 = {43 00 6f 00 6d 00 70 00 69 00 6c 00 69 00 6e 00 67 00 2e 00 65 00 78 00 65 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and $x1 or ( $a1 and 1 of ( $s* ) )
}

rule LokiBot_Dropper_Packed_R11_Feb18 : hardened
{
	meta:
		description = "Auto-generated rule - file scan copy.pdf.r11"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://app.any.run/tasks/401df4d9-098b-4fd0-86e0-7a52ce6ddbf5"
		date = "2018-02-14"
		hash1 = "3b248d40fd7acb839cc592def1ed7652734e0e5ef93368be3c36c042883a3029"
		id = "83cd6225-eb6d-5d17-a751-51f20db9c7eb"

	strings:
		$s1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 5c 4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 39 38 5c 56 42 36 2e 4f 4c 42}

	condition:
		uint16( 0 ) == 0x0000 and filesize < 2000KB and 1 of them
}

