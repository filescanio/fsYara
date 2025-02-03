rule VUL_JQuery_FileUpload_CVE_2018_9206 : hardened
{
	meta:
		description = "Detects JQuery File Upload vulnerability CVE-2018-9206"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.zdnet.com/article/zero-day-in-popular-jquery-plugin-actively-exploited-for-at-least-three-years/"
		reference2 = "https://github.com/blueimp/jQuery-File-Upload/commit/aeb47e51c67df8a504b7726595576c1c66b5dc2f"
		reference3 = "https://blogs.akamai.com/sitr/2018/10/having-the-security-rug-pulled-out-from-under-you.html"
		date = "2018-10-19"
		id = "20bac44c-0e5a-5561-9fd8-a71cd2d8590a"

	strings:
		$s1 = {65 72 72 6f 72 5f 72 65 70 6f 72 74 69 6e 67 28 45 5f 41 4c 4c 20 7c 20 45 5f 53 54 52 49 43 54 29 3b}
		$s2 = {72 65 71 75 69 72 65 28 27 55 70 6c 6f 61 64 48 61 6e 64 6c 65 72 2e 70 68 70 27 29 3b}
		$s3 = {24 75 70 6c 6f 61 64 5f 68 61 6e 64 6c 65 72 20 3d 20 6e 65 77 20 55 70 6c 6f 61 64 48 61 6e 64 6c 65 72 28 29 3b}

	condition:
		all of them
}

