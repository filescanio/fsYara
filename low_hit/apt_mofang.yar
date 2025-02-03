rule shimrat : hardened
{
	meta:
		description = "Detects ShimRat and the ShimRat loader"
		author = "Yonathan Klijnsma (yonathan.klijnsma@fox-it.com)"
		date = "20/11/2015"
		id = "21431895-1180-5552-8e82-1589992ffa1d"

	strings:
		$dll = {2e 64 6c 6c}
		$dat = {2e 64 61 74}
		$headersig = {51 57 45 52 54 59 55 49 4f 50 4c 4b 4a 48 47}
		$datasig = {4d 4e 42 56 43 58 5a 4c 4b 4a 48 47 46 44 53}
		$datamarker1 = {44 61 74 61 24 24 30 30}
		$datamarker2 = {44 61 74 61 24 24 30 31 25 63 25 73 44 61 74 61}
		$cmdlineformat = {70 69 6e 67 20 6c 6f 63 61 6c 68 6f 73 74 20 2d 6e 20 39 20 2f 63 20 25 73 20 3e 20 6e 75 6c}
		$demoproject_keyword1 = {44 65 6d 6f}
		$demoproject_keyword2 = {57 69 6e 33 32 41 70 70}
		$comspec = {43 4f 4d 53 50 45 43}
		$shim_func1 = {53 68 69 6d 4d 61 69 6e}
		$shim_func2 = {4e 6f 74 69 66 79 53 68 69 6d 73}
		$shim_func3 = {47 65 74 48 6f 6f 6b 41 50 49 73}

	condition:
		($dll and $dat and $headersig and $datasig ) or ( $datamarker1 and $datamarker2 ) or ( $cmdlineformat and $demoproject_keyword1 and $demoproject_keyword2 and $comspec ) or ( $dll and $dat and $shim_func1 and $shim_func2 and $shim_func3 )
}

rule shimratreporter : hardened
{
	meta:
		description = "Detects ShimRatReporter"
		author = "Yonathan Klijnsma (yonathan.klijnsma@fox-it.com)"
		date = "20/11/2015"
		id = "01688b3c-2f06-518f-939d-4d65529be5ae"

	strings:
		$IpInfo = {49 50 2d 49 4e 46 4f}
		$NetworkInfo = {4e 65 74 77 6f 72 6b 2d 49 4e 46 4f}
		$OsInfo = {4f 53 2d 49 4e 46 4f}
		$ProcessInfo = {50 72 6f 63 65 73 73 2d 49 4e 46 4f}
		$BrowserInfo = {42 72 6f 77 73 65 72 2d 49 4e 46 4f}
		$QueryUserInfo = {51 75 65 72 79 55 73 65 72 2d 49 4e 46 4f}
		$UsersInfo = {55 73 65 72 73 2d 49 4e 46 4f}
		$SoftwareInfo = {53 6f 66 74 77 61 72 65 2d 49 4e 46 4f}
		$AddressFormat = {25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58}
		$proxy_str = {28 66 72 6f 6d 20 65 6e 76 69 72 6f 6e 6d 65 6e 74 29 20 3d 20 25 73}
		$netuserfun = {4e 65 74 55 73 65 72 45 6e 75 6d}
		$networkparams = {47 65 74 4e 65 74 77 6f 72 6b 50 61 72 61 6d 73}

	condition:
		all of them
}

