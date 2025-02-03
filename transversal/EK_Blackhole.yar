rule blackhole_basic : EK hardened
{
	strings:
		$a = /\.php\?.*?\:[a-zA-Z0-9\:]{6,}?\&.*?\&/

	condition:
		$a
}

rule blackhole2_css : EK hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-27"
		description = "BlackHole2 Exploit Kit Detection"
		hash0 = "9664a16c65782d56f02789e7d52359cd"
		sample_filetype = "js-html"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string1 = {62 61 63 6b 67 72 6f 75 6e 64 3a 75 72 6c 28 27 25 25 3f 61 3d 69 6d 67 26 69 6d 67 3d 63 6f 75 6e 74 72 69 65 73 2e 67 69 66 27 29}
		$string2 = {62 61 63 6b 67 72 6f 75 6e 64 3a 75 72 6c 28 27 25 25 3f 61 3d 69 6d 67 26 69 6d 67 3d 65 78 70 6c 6f 69 74 2e 67 69 66 27 29}
		$string3 = {62 61 63 6b 67 72 6f 75 6e 64 3a 75 72 6c 28 27 25 25 3f 61 3d 69 6d 67 26 69 6d 67 3d 6f 73 65 73 2e 67 69 66 27 29}
		$string4 = {62 61 63 6b 67 72 6f 75 6e 64 3a 75 72 6c 28 27 25 25 3f 61 3d 69 6d 67 26 69 6d 67 3d 62 72 6f 77 73 65 72 73 2e 67 69 66 27 29}
		$string5 = {62 61 63 6b 67 72 6f 75 6e 64 3a 75 72 6c 28 27 25 25 3f 61 3d 69 6d 67 26 69 6d 67 3d 65 64 69 74 2e 70 6e 67 27 29}
		$string6 = {62 61 63 6b 67 72 6f 75 6e 64 3a 75 72 6c 28 27 25 25 3f 61 3d 69 6d 67 26 69 6d 67 3d 61 64 64 2e 70 6e 67 27 29}
		$string7 = {62 61 63 6b 67 72 6f 75 6e 64 3a 75 72 6c 28 27 25 25 3f 61 3d 69 6d 67 26 69 6d 67 3d 61 63 63 65 70 74 2e 70 6e 67 27 29}
		$string8 = {62 61 63 6b 67 72 6f 75 6e 64 3a 75 72 6c 28 27 25 25 3f 61 3d 69 6d 67 26 69 6d 67 3d 64 65 6c 2e 70 6e 67 27 29}
		$string9 = {62 61 63 6b 67 72 6f 75 6e 64 3a 75 72 6c 28 27 25 25 3f 61 3d 69 6d 67 26 69 6d 67 3d 73 74 61 74 2e 67 69 66 27 29}

	condition:
		18 of them
}

rule blackhole2_htm : EK hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-27"
		description = "BlackHole2 Exploit Kit Detection"
		hash0 = "92e21e491a90e24083449fd906515684"
		hash1 = "98b302a504a7ad0e3515ab6b96d623f9"
		hash2 = "a91d885ef4c4a0d16c88b956db9c6f43"
		hash3 = "d8336f7ae9b3a4db69317aea105f49be"
		hash4 = "eba5daf0442dff5b249274c99552177b"
		hash5 = "02d8e6daef5a4723621c25cfb766a23d"
		hash6 = "dadf69ce2124283a59107708ffa9c900"
		hash7 = "467199178ac940ca311896c7d116954f"
		hash8 = "17ab5b85f2e1f2b5da436555ea94f859"
		sample_filetype = "js-html"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {3e 6c 69 6e 6b 73 2f 3c 2f 61 3e 3c 2f 74 64 3e 3c 74 64 20 61 6c 69 67 6e}
		$string1 = {3e 36 38 34 4b 3c 2f 74 64 3e 3c 74 64 3e}
		$string2 = {3e 20 33 36 4b 3c 2f 74 64 3e 3c 74 64 3e}
		$string3 = {6d 6f 76 65 5f 6c 6f 67 73 2e 70 68 70}
		$string4 = {66 69 6c 65 73 2f}
		$string5 = {63 72 6f 6e 5f 75 70 64 61 74 65 74 6f 72 2e 70 68 70}
		$string6 = {3e 31 32 2d 53 65 70 2d 32 30 31 32 20 32 33 3a 34 35 20 20 3c 2f 74 64 3e 3c 74 64 20 61 6c 69 67 6e}
		$string7 = {3e 20 20 2d 20 3c 2f 74 64 3e 3c 74 64 3e}
		$string8 = {63 72 6f 6e 5f 63 68 65 63 6b 2e 70 68 70}
		$string9 = {2d 2f 2f 57 33 43 2f 2f 44 54 44 20 48 54 4d 4c 20 33 2e 32 20 46 69 6e 61 6c 2f 2f 45 4e}
		$string10 = {62 68 61 64 6d 69 6e 2e 70 68 70}
		$string11 = {3e 32 31 2d 53 65 70 2d 32 30 31 32 20 31 35 3a 32 35 20 20 3c 2f 74 64 3e 3c 74 64 20 61 6c 69 67 6e}
		$string12 = {3e 64 61 74 61 2f 3c 2f 61 3e 3c 2f 74 64 3e 3c 74 64 20 61 6c 69 67 6e}
		$string13 = {3e 33 2e 33 4b 3c 2f 74 64 3e 3c 74 64 3e}
		$string14 = {63 72 6f 6e 5f 75 70 64 61 74 65 2e 70 68 70}

	condition:
		14 of them
}

rule blackhole2_htm10 : EK hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-27"
		description = "BlackHole2 Exploit Kit Detection"
		hash0 = "83704d531c9826727016fec285675eb1"
		hash1 = "103ef0314607d28b3c54cd07e954cb25"
		hash2 = "16c002dc45976caae259d7cabc95b2c3"
		hash3 = "fd84d695ac3f2ebfb98d3255b3a4e1de"
		hash4 = "c7b417a4d650c72efebc2c45eefbac2a"
		hash5 = "c3c35e465e316a71abccca296ff6cd22"
		hash2 = "16c002dc45976caae259d7cabc95b2c3"
		hash7 = "10ce7956266bfd98fe310d7568bfc9d0"
		hash8 = "60024caf40f4239d7e796916fb52dc8c"
		sample_filetype = "js-html"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {3c 2f 62 6f 64 79 3e 3c 2f 68 74 6d 6c 3e}
		$string1 = {2f 69 63 6f 6e 73 2f 62 61 63 6b 2e 67 69 66}
		$string2 = {3e 33 37 33 4b 3c 2f 74 64 3e 3c 74 64 3e}
		$string3 = {2f 69 63 6f 6e 73 2f 75 6e 6b 6e 6f 77 6e 2e 67 69 66}
		$string4 = {3e 4c 61 73 74 20 6d 6f 64 69 66 69 65 64 3c 2f 61 3e 3c 2f 74 68 3e 3c 74 68 3e 3c 61 20 68 72 65 66}
		$string5 = {74 6d 70 2e 67 7a}
		$string6 = {3e 74 6d 70 2e 67 7a 3c 2f 61 3e 3c 2f 74 64 3e 3c 74 64 20 61 6c 69 67 6e}
		$string7 = {6e 62 73 70 3b 3c 2f 74 64 3e 3c 74 64 20 61 6c 69 67 6e}
		$string8 = {3c 2f 74 61 62 6c 65 3e}
		$string9 = {3e 20 20 2d 20 3c 2f 74 64 3e 3c 74 64 3e}
		$string10 = {3e 66 69 6c 65 66 64 63 37 61 61 66 34 61 33 3c 2f 61 3e 3c 2f 74 64 3e 3c 74 64 20 61 6c 69 67 6e}
		$string11 = {3e 31 39 2d 53 65 70 2d 32 30 31 32 20 30 37 3a 30 36 20 20 3c 2f 74 64 3e 3c 74 64 20 61 6c 69 67 6e}
		$string12 = {3e 3c 69 6d 67 20 73 72 63}
		$string13 = {66 69 6c 65 33 66 61 37 62 64 64 37 64 63}
		$string14 = {20 20 3c 74 69 74 6c 65 3e 49 6e 64 65 78 20 6f 66 20 2f 66 69 6c 65 73 3c 2f 74 69 74 6c 65 3e}
		$string15 = {30 64 61 34 39 65 30 34 32 64}

	condition:
		15 of them
}

rule blackhole2_htm12 : EK hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-27"
		description = "BlackHole2 Exploit Kit Detection"
		hash0 = "0d3acb5285cfe071e30be051d2aaf28a"
		hash1 = "6f27377115ba5fd59f007d2cb3f50b35"
		hash2 = "f7ffe1fd1a57d337a04d3c777cddc065"
		hash3 = "06997228f2769859ef5e4cd8a454d650"
		hash4 = "11062eea9b7f2a2675c1e60047e8735c"
		hash0 = "0d3acb5285cfe071e30be051d2aaf28a"
		hash2 = "f7ffe1fd1a57d337a04d3c777cddc065"
		hash7 = "4ec720cfafabd1c9b1034bb82d368a30"
		hash8 = "ecd7d11dc9bb6ee842e2a2dce56edc6f"
		sample_filetype = "js-html"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {20 20 3c 74 69 74 6c 65 3e 49 6e 64 65 78 20 6f 66 20 2f 64 61 74 61 3c 2f 74 69 74 6c 65 3e}
		$string1 = {3c 74 72 3e 3c 74 68 20 63 6f 6c 73 70 61 6e}
		$string2 = {3c 2f 62 6f 64 79 3e 3c 2f 68 74 6d 6c 3e}
		$string3 = {3e 20 32 30 4b 3c 2f 74 64 3e 3c 74 64 3e}
		$string4 = {2f 69 63 6f 6e 73 2f 6c 61 79 6f 75 74 2e 67 69 66}
		$string5 = {20 3c 62 6f 64 79 3e}
		$string6 = {3e 4e 61 6d 65 3c 2f 61 3e 3c 2f 74 68 3e 3c 74 68 3e 3c 61 20 68 72 65 66}
		$string7 = {3e 73 70 6e 2e 6a 61 72 3c 2f 61 3e 3c 2f 74 64 3e 3c 74 64 20 61 6c 69 67 6e}
		$string8 = {3e 73 70 6e 32 2e 6a 61 72 3c 2f 61 3e 3c 2f 74 64 3e 3c 74 64 20 61 6c 69 67 6e}
		$string9 = {20 3c 68 65 61 64 3e}
		$string10 = {2d 2f 2f 57 33 43 2f 2f 44 54 44 20 48 54 4d 4c 20 33 2e 32 20 46 69 6e 61 6c 2f 2f 45 4e}
		$string11 = {3e 20 31 30 4b 3c 2f 74 64 3e 3c 74 64 3e}
		$string12 = {3e 37 2e 39 4b 3c 2f 74 64 3e 3c 74 64 3e}
		$string13 = {3e 53 69 7a 65 3c 2f 61 3e 3c 2f 74 68 3e 3c 74 68 3e 3c 61 20 68 72 65 66}
		$string14 = {3e 3c 68 72 3e 3c 2f 74 68 3e 3c 2f 74 72 3e}

	condition:
		14 of them
}

rule blackhole2_htm3 : EK hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-27"
		description = "BlackHole2 Exploit Kit Detection"
		hash0 = "018ef031bc68484587eafeefa66c7082"
		sample_filetype = "js-html"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70}
		$string1 = {2e 2f 66 69 6c 65 73 2f 66 64 63 37 61 61 66 34 61 33 20 6d 64 35 20 69 73 20 33 31 36 39 39 36 39 65 39 31 66 35 66 65 35 34 34 36 39 30 39 62 62 61 62 36 65 31 34 64 35 64}
		$string2 = {33 32 31 65 37 37 34 64 38 31 62 32 63 33 61 65}
		$string3 = {2f 66 69 6c 65 73 2f 6e 65 77 30 30 30 31 30 2f 35 35 34 2d 30 30 30 32 2e 65 78 65 20 6d 64 35 20 69 73 20 38 61 34 39 37 63 66 34 66 66 61 38 61 31 37 33 61 37 61 63 37 35 66 30 64 65 31 66 38 64 38 62}
		$string4 = {2e 2f 66 69 6c 65 73 2f 33 66 61 37 62 64 64 37 64 63 20 6d 64 35 20 69 73 20 38 61 34 39 37 63 66 34 66 66 61 38 61 31 37 33 61 37 61 63 37 35 66 30 64 65 31 66 38 64 38 62}
		$string5 = {31 36 30 33 32 35 36 36 33 36 35 33 30 31 32 30 39 31 35 20 6d 64 35 20 69 73 20 34 32 35 65 62 64 66 63 66 30 33 30 34 35 39 31 37 64 39 30 38 37 38 64 32 36 34 37 37 33 64 32}

	condition:
		3 of them
}

rule blackhole2_htm4 : EK hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-27"
		description = "BlackHole2 Exploit Kit Detection"
		hash0 = "926429bf5fe1fbd531eb100fc6e53524"
		hash1 = "7b6cdc67077fc3ca75a54dea0833afe3"
		hash2 = "82f108d4e6f997f8fc4cc02aad02629a"
		hash3 = "bd819c3714dffb5d4988d2f19d571918"
		hash4 = "9bc9f925f60bd8a7b632ae3a6147cb9e"
		hash0 = "926429bf5fe1fbd531eb100fc6e53524"
		hash2 = "82f108d4e6f997f8fc4cc02aad02629a"
		hash7 = "386cb76d46b281778c8c54ac001d72dc"
		hash8 = "0d95c666ea5d5c28fca5381bd54304b3"
		sample_filetype = "js-html"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {77 6f 72 64 73 2e 64 61 74}
		$string1 = {2f 69 63 6f 6e 73 2f 62 61 63 6b 2e 67 69 66}
		$string2 = {64 61 74 61 2e 64 61 74}
		$string3 = {66 69 6c 65 73 2e 70 68 70}
		$string4 = {6a 73 2e 70 68 70}
		$string5 = {74 65 6d 70 6c 61 74 65 2e 70 68 70}
		$string6 = {6b 63 61 70 74 63 68 61}
		$string7 = {2f 69 63 6f 6e 73 2f 62 6c 61 6e 6b 2e 67 69 66}
		$string8 = {6a 61 76 61 2e 64 61 74}

	condition:
		8 of them
}

rule blackhole2_htm5 : EK hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-27"
		description = "BlackHole2 Exploit Kit Detection"
		hash0 = "fccb8f71663620a5a8b53dcfb396cfb5"
		hash1 = "a09bcf1a1bdabe4e6e7e52e7f8898012"
		hash2 = "40db66bf212dd953a169752ba9349c6a"
		hash3 = "25a87e6da4baa57a9d6a2cdcb2d43249"
		hash4 = "6f4c64a1293c03c9f881a4ef4e1491b3"
		hash0 = "fccb8f71663620a5a8b53dcfb396cfb5"
		hash2 = "40db66bf212dd953a169752ba9349c6a"
		hash7 = "4bdfff8de0bb5ea2d623333a4a82c7f9"
		hash8 = "b43b6a1897c2956c2a0c9407b74c4232"
		sample_filetype = "js-html"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {72 75 6c 65 45 64 69 74 2e 70 68 70}
		$string1 = {64 6f 6d 61 69 6e 73 2e 70 68 70}
		$string2 = {6d 65 6e 75 2e 70 68 70}
		$string3 = {62 72 6f 77 73 65 72 73 5f 73 74 61 74 2e 70 68 70}
		$string4 = {49 6e 64 65 78 20 6f 66 20 2f 6c 69 62 72 61 72 79 2f 74 65 6d 70 6c 61 74 65 73}
		$string5 = {2f 69 63 6f 6e 73 2f 75 6e 6b 6e 6f 77 6e 2e 67 69 66}
		$string6 = {62 72 6f 77 73 65 72 73 5f 62 73 74 61 74 2e 70 68 70}
		$string7 = {6f 73 65 73 5f 73 74 61 74 2e 70 68 70}
		$string8 = {65 78 70 6c 6f 69 74 73 5f 62 73 74 61 74 2e 70 68 70}
		$string9 = {62 6c 6f 63 6b 5f 63 6f 6e 66 69 67 2e 70 68 70}
		$string10 = {74 68 72 65 61 64 73 5f 62 73 74 61 74 2e 70 68 70}
		$string11 = {62 72 6f 77 73 65 72 73 5f 62 73 74 61 74 2e 70 68 70}
		$string12 = {73 65 74 74 69 6e 67 73 2e 70 68 70}

	condition:
		12 of them
}

rule blackhole2_htm6 : EK hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-27"
		description = "BlackHole2 Exploit Kit Detection"
		hash0 = "a5f94d7bdeb88b57be67132473e48286"
		hash1 = "2e72a317d07aa1603f8d138787a2c582"
		hash2 = "9440d49e1ed0794c90547758ef6023f7"
		hash3 = "58265fc893ed5a001e3a7c925441298c"
		hash2 = "9440d49e1ed0794c90547758ef6023f7"
		hash0 = "a5f94d7bdeb88b57be67132473e48286"
		hash2 = "9440d49e1ed0794c90547758ef6023f7"
		hash7 = "95c6462d0f21181c5003e2a74c8d3529"
		hash8 = "9236e7f96207253b4684f3497bcd2b3d"
		sample_filetype = "js-html"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {75 6e 69 71 31 2e 70 6e 67}
		$string1 = {65 64 69 74 2e 70 6e 67}
		$string2 = {6c 65 66 74 2e 67 69 66}
		$string3 = {69 6e 66 69 6e 2e 70 6e 67}
		$string4 = {6f 75 74 64 65 6e 74 2e 67 69 66}
		$string5 = {65 78 70 6c 6f 69 74 2e 67 69 66}
		$string6 = {73 65 6d 5f 67 2e 70 6e 67}
		$string7 = {49 6e 64 65 78 20 6f 66 20 2f 6c 69 62 72 61 72 79 2f 74 65 6d 70 6c 61 74 65 73 2f 69 6d 67}
		$string8 = {75 6e 69 71 31 2e 70 6e 67}

	condition:
		8 of them
}

rule blackhole2_htm8 : EK hardened
{
	meta:
		author = "Josh Berry"
		date = "2016-06-27"
		description = "BlackHole2 Exploit Kit Detection"
		hash0 = "3f47452c1e40f68160beff4bb2a3e5f4"
		hash1 = "1e2ba0176787088e3580dfce0245bc16"
		hash2 = "1c78d96bb8d8f8a71294bc1e6d374b0f"
		hash3 = "f5e16a6cd2c2ac71289aaf1c087224ee"
		hash2 = "1c78d96bb8d8f8a71294bc1e6d374b0f"
		hash0 = "3f47452c1e40f68160beff4bb2a3e5f4"
		hash2 = "1c78d96bb8d8f8a71294bc1e6d374b0f"
		hash7 = "6702efdee17e0cd6c29349978961d9fa"
		hash8 = "287dca9469c8f7f0cb6e5bdd9e2055cd"
		sample_filetype = "js-html"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"

	strings:
		$string0 = {3e 44 65 73 63 72 69 70 74 69 6f 6e 3c 2f 61 3e 3c 2f 74 68 3e 3c 2f 74 72 3e 3c 74 72 3e 3c 74 68 20 63 6f 6c 73 70 61 6e}
		$string1 = {3e 4e 61 6d 65 3c 2f 61 3e 3c 2f 74 68 3e 3c 74 68 3e 3c 61 20 68 72 65 66}
		$string2 = {6d 61 69 6e 2e 6a 73}
		$string3 = {64 61 74 65 70 69 63 6b 65 72 2e 6a 73}
		$string4 = {66 6f 72 6d 2e 6a 73}
		$string5 = {3c 61 64 64 72 65 73 73 3e 41 70 61 63 68 65 2f 32 2e 32 2e 31 35 20 28 43 65 6e 74 4f 53 29 20 53 65 72 76 65 72 20 61 74 20 6f 6e 6c 69 6e 65 2d 6d 6f 6f 2d 76 69 69 69 2e 6e 65 74 20 50 6f 72 74 20 38 30 3c 2f 61 64 64 72 65 73 73 3e}
		$string6 = {77 79 73 69 77 79 67 2e 6a 73}

	condition:
		6 of them
}

