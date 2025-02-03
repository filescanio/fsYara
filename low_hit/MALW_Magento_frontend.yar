rule onepage_or_checkout : hardened
{
	strings:
		$ = {5c 78 36 46 5c 78 36 45 5c 78 36 35 5c 78 37 30 5c 78 36 31 5c 78 36 37 5c 78 36 35 5c 78 37 43 5c 78 36 33 5c 78 36 38 5c 78 36 35 5c 78 36 33 5c 78 36 42 5c 78 36 46 5c 78 37 35 5c 78 37 34}

	condition:
		any of them
}

rule sinlesspleasure_com : hardened
{
	strings:
		$ = {35 65 39 30 38 72 39 34 38 71 39 65 36 30 35 6a 38 74 39 62 39 31 35 6e 35 6f 39 66 38 72 35 65 35 64 39 36 39 67 39 64 37 39 35 62 34 73 36 70 38 74 39 68 39 66 39 37 38 6f 38 70 38 73 39 35 39 30 39 33 36 6c 36 6b 38 6a 39 36 37 30 35 32 34 70 37 34 39 30 39 31 35 6c 35 66 38 72 39 30 38 37 38 74 39 31 37 66 37 67 38 70 38 6f 38 70 38 6b 39 63 36 30 35 69 38 64 39 33 37 74 37 6d 38 69 38 71 38 6f 38 71 39 35 39 68 37 70 38 32 38 65 37 72 38 65 37 71 37 65 38 6d 38 6f 35 67 35 65 39 31 39 39 39 31 38 6f 39 67 37 71 37 63 38 63 38 74 39 39 39 30 35 61 35 69 38 6c 39 34 39 38 39 68 37 72 37 67 38 69 38 74 38 6d 35 66 35 6f 39 32 39 31 37 71 37 6b 39 69 39 65 39 34 38 63 39 31 39 68 39 32 35 61 35 64 38 6a 39 31 35 68 36 30 38 74 38 70 38 74 39 66 39 33 37 62 37 6b 39 69 39 65 39 34 38 63 39 31 39 68 39 32}

	condition:
		any of them
}

rule amasty_biz : hardened
{
	strings:
		$ = {31 31 38 2c 39 37 2c 31 31 34 2c 33 32 2c 31 31 35 2c 31 31 30 2c 31 30 30 2c 33 32 2c 36 31 2c 31 31 30 2c 31 31 37 2c 31 30 38 2c 31 30 38 2c 35 39 2c 31 30 2c 31 30 2c 31 30 32 2c 31 31 37}

	condition:
		any of them
}

rule amasty_biz_js : hardened
{
	strings:
		$ = {74 5f 70 23 30 2e 71 6c 62 23 30 2e 23 31 42 6c 73 6a 6a 23 31 40 23 2e 3f 23 2e 3f 64 73 6c 61 72 67 6d 6c 23 30 2e 71 72 5f 70 72 23 30 36 23 30 37 23 35 40 23 2e 3f 23 30}

	condition:
		any of them
}

rule returntosender : hardened
{
	strings:
		$ = {5c 78 32 46 5c 78 36 44 5c 78 36 35 5c 78 36 34 5c 78 36 39 5c 78 36 31 5c 78 32 46 5c 78 36 33 5c 78 36 31 5c 78 37 34 5c 78 36 31 5c 78 36 43 5c 78 36 46 5c 78 36 37 5c 78 32 46 5c 78 37 30 5c 78 37 32 5c 78 36 46 5c 78 36 34 5c 78 37 35 5c 78 36 33 5c 78 37 34 5c 78 32 46 5c 78 36 33 5c 78 36 31 5c 78 36 33 5c 78 36 38 5c 78 36 35 5c 78 32 46 5c 78 33 31 5c 78 32 46 5c 78 37 34 5c 78 36 38 5c 78 37 35 5c 78 36 44 5c 78 36 32 5c 78 36 45 5c 78 36 31 5c 78 36 39 5c 78 36 43 5c 78 32 46 5c 78 33 37 5c 78 33 30 5c 78 33 30 5c 78 37 38 5c 78 32 46 5c 78 33 32 5c 78 36 32 5c 78 36 36 5c 78 33 38 5c 78 36 36 5c 78 33 32 5c 78 36 32 5c 78 33 38 5c 78 36 34 5c 78 33 30 5c 78 33 32 5c 78 33 38 5c 78 36 33 5c 78 36 33 5c 78 36 35 5c 78 33 39 5c 78 33 36 5c 78 32 46 5c 78 34 32 5c 78 32 46 5c 78 35 37 5c 78 32 46 5c 78 36 34 5c 78 36 31 5c 78 33 34 5c 78 33 31 5c 78 33 38 5c 78 33 30 5c 78 33 33 5c 78 36 33 5c 78 36 33 5c 78 33 39 5c 78 33 38 5c 78 33 34 5c 78 36 32 5c 78 33 38 5c 78 36 33 5c 78 32 45 5c 78 37 30 5c 78 36 38 5c 78 37 30}

	condition:
		any of them
}

rule ip_5uu8_com : hardened
{
	strings:
		$ = {5c 78 36 39 5c 78 37 30 5c 78 32 65 5c 78 33 35 5c 78 37 35 5c 78 37 35 5c 78 33 38 5c 78 32 65 5c 78 36 33 5c 78 36 66 5c 78 36 64}

	condition:
		any of them
}

rule cloudfusion_me : hardened
{
	strings:
		$ = {26 23 39 39 3b 26 23 31 30 38 3b 26 23 31 31 31 3b 26 23 31 31 37 3b 26 23 31 30 30 3b 26 23 31 30 32 3b 26 23 31 31 37 3b 26 23 31 31 35 3b 26 23 31 30 35 3b 26 23 31 31 31 3b 26 23 31 31 30 3b 26 23 34 36 3b 26 23 31 30 39 3b 26 23 31 30 31 3b}

	condition:
		any of them
}

rule grelos_v : hardened
{
	strings:
		$ = {76 61 72 20 67 72 65 6c 6f 73 5f 76}

	condition:
		any of them
}

rule hacked_domains : hardened
{
	strings:
		$ = {69 6e 66 6f 70 72 6f 6d 6f 2e 62 69 7a}
		$ = {6a 71 75 65 72 79 2d 63 6f 64 65 2e 73 75}
		$ = {6a 71 75 65 72 79 2d 63 73 73 2e 73 75}
		$ = {6d 65 67 61 6c 69 74 68 2d 67 61 6d 65 73 2e 63 6f 6d}
		$ = {63 64 6e 2d 63 6c 6f 75 64 2e 70 77}
		$ = {61 6e 69 6d 61 6c 7a 7a 39 32 31 2e 70 77}
		$ = {73 74 61 74 73 64 6f 74 2e 65 75}

	condition:
		any of them
}

rule mage_cdn_link : hardened
{
	strings:
		$ = {5c 78 36 44 5c 78 36 31 5c 78 36 37 5c 78 36 35 5c 78 32 44 5c 78 36 33 5c 78 36 34 5c 78 36 45 5c 78 32 45 5c 78 36 43 5c 78 36 39 5c 78 36 45 5c 78 36 42}

	condition:
		any of them
}

rule credit_card_regex : hardened
{
	strings:
		$ = {52 65 67 45 78 70 28 22 5b 30 2d 39 5d 7b 31 33 2c 31 36 7d 22 29}

	condition:
		any of them
}

rule jquery_code_su : hardened
{
	strings:
		$ = {31 30 35 2c 31 30 32 2c 34 30 2c 34 30 2c 31 31 30 2c 31 30 31 2c 31 31 39 2c 33 32 2c 38 32 2c 31 30 31 2c 31 30 33 2c 36 39 2c 31 32 30 2c 31 31 32 2c 34 30 2c 33 39 2c 31 31 31 2c 31 31 30 2c 31 30 31 2c 31 31 32 2c 39 37 2c 31 30 33 2c 31 30 31}

	condition:
		any of them
}

rule jquery_code_su_multi : hardened
{
	strings:
		$ = {3d 6f 51 4b 70 6b 79 4a 38 64 43 4b 30 6c 47 62 77 4e 6e 4c 6e 34 32 62 70 52 58 59 6a 39 47 62 45 4e 44 66 74 31 32 62 6b 42 6a 4d 38 56 32 59 70 78 32 63 38 52 6e 62 6c 35 32 62 77 31 32 62 44 6c 6b 55 56 56 47 5a 76 4e 57 5a 6b 5a 30 4d 38 35 57 61 76 70 47 66 73 4a 58 64 38 52 31 55 50 42 31 4e 79 77 58 5a 74 46 6d 62 30 4e 33 62 6f 78}

	condition:
		any of them
}

rule Trafficanalyzer_js : hardened
{
	strings:
		$ = {7a 3d 78 5b 27 6c 65 6e 67 74 68 27 5d 3b 66 6f 72 28 69 3d 30 3b 69 3c 7a 3b 69 2b 2b 29 7b 79 2b 3d 53 74 72 69 6e 67 5b 27 66 72 6f 6d 43 68 61 72 43 6f 64 65 27 5d 28 78 5b 27 63 68 61 72 43 6f 64 65 41 74 27 5d 28 69 29 2d 31 30 29 20 7d 77 3d 74 68 69 73 5b 27 75 6e 65 73 63 61 70 65 27 5d 28 79 29 3b 74 68 69 73 5b 27 65 76 61 6c 27 5d 28 77 29 3b}

	condition:
		any of them
}

rule atob_js : hardened
{
	strings:
		$ = {74 68 69 73 5b 27 65 76 61 6c 27 5d 28 74 68 69 73 5b 27 61 74 6f 62 27 5d 28 27}

	condition:
		any of them
}

rule gate_php_js : hardened
{
	strings:
		$ = /\/gate.php\?token=.{,10}&host=/

	condition:
		any of them
}

rule googieplay_js : hardened
{
	strings:
		$ = {74 64 73 6a 71 75 21 74 73 64 3e 23 69 75 75 71 3b 30 30 68 70 70 68 6a 66 71 6d 62 7a 2f 6a 6f 67 70 30 6e 62 68 66 6f 75 70 60 68 70 70 68 6a 66 71 6d 62 7a 2f 6b 74 23 3f 3d 30 74 64 73 6a 71 75 3f}

	condition:
		any of them
}

rule mag_php_js : hardened
{
	strings:
		$ = {6f 6e 65 70 61 67 65 7c 63 68 65 63 6b 6f 75 74 7c 6f 6e 65 73 74 65 70 7c 66 69 72 65 63 68 65 63 6b 6f 75 74 7c 6f 6e 65 73 74 65 70 63 68 65 63 6b 6f 75 74}
		$ = {27 6f 6e 65 7c 63 68 65 63 6b 27}

	condition:
		any of them
}

rule thetech_org_js : hardened
{
	strings:
		$ = {7c 52 65 67 45 78 70 7c 6f 6e 65 70 61 67 65 7c 63 68 65 63 6b 6f 75 74 7c}

	condition:
		any of them
}

rule md5_cdn_js_link_js : hardened
{
	strings:
		$ = {67 72 65 6c 6f 73 5f 76 3d 20 6e 75 6c 6c}

	condition:
		any of them
}

