rule Word_2007_XML_Flat_OPC : maldoc hardened
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect Word 2007 XML Document in the Flat OPC format w/ embedded Microsoft Office 2007+ document"
		date = "2018-04-29"
		reference = "https://blogs.msdn.microsoft.com/ericwhite/2008/09/29/the-flat-opc-format/"
		hash1 = "060c036ce059b465a05c42420efa07bf"
		hash2 = "2af21d35bb909a0ac081c2399d0939b1"
		hash3 = "72ffa688c228b0b833e69547885650fe"
		filetype = "Office documents"

	strings:
		$xml = {3c 3f 78 6d 6c}
		$WordML = {3c 3f 6d 73 6f 2d 61 70 70 6c 69 63 61 74 69 6f 6e 20 70 72 6f 67 69 64 3d 22 57 6f 72 64 2e 44 6f 63 75 6d 65 6e 74 22 3f 3e}
		$OPC = {3c 70 6b 67 3a 70 61 63 6b 61 67 65}
		$xmlns = {68 74 74 70 3a 2f 2f 73 63 68 65 6d 61 73 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 6f 66 66 69 63 65 2f 32 30 30 36 2f 78 6d 6c 50 61 63 6b 61 67 65}
		$binaryData = {3c 70 6b 67 3a 62 69 6e 61 72 79 44 61 74 61 3e 30 4d 38 52 34 4b 47 78 47 75 45}
		$docm = {70 6b 67 3a 6e 61 6d 65 3d 22 2f 77 6f 72 64 2f 76 62 61 50 72 6f 6a 65 63 74 2e 62 69 6e 22}

	condition:
		$xml at 0 and $WordML and $OPC and $xmlns and $binaryData and $docm
}

