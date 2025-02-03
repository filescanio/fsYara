rule PoetRat_Doc : hardened
{
	meta:
		Author = "Nishan Maharjan"
		Description = "A yara rule to catch PoetRat Word Document"
		Data = "6th May 2020"

	strings:
		$pythonRegEx = /(\.py$|\.pyc$|\.pyd$|Python)/
		$pythonFile1 = {6c 61 75 6e 63 68 65 72 2e 70 79}
		$zipFile = {73 6d 69 6c 65 2e 7a 69 70}
		$pythonFile2 = {73 6d 69 6c 65 5f 66 75 6e 73 2e 70 79}
		$pythonFile3 = {66 72 6f 77 6e 2e 70 79}
		$pythonFile4 = {62 61 63 6b 65 72 2e 70 79}
		$pythonFile5 = {73 6d 69 6c 65 2e 70 79}
		$pythonFile6 = {61 66 66 69 6e 65 2e 70 79}
		$dlls = /\.dll/
		$cmd = {63 6d 64}
		$exe = {2e 65 78 65}

	condition:
		all of them
}

