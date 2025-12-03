rule dump_sales_quote_payment : hardened
{
	strings:
		$ = {69 6e 63 6c 75 64 65 20 27 2e 2e 2f 2e 2e 2f 2e 2e 2f 2e 2e 2f 2e 2e 2f 2e 2e 2f 2e 2e 2f 2e 2e 2f 2e 2e 2f 2e 2e 2f 61 70 70 2f 4d 61 67 65 2e 70 68 70 27 3b 20 4d 61 67 65 3a 3a 61 70 70 28 29 3b 20 24 71 20 3d 20 4d 61 67 65 3a 3a 67 65 74 4d 6f 64 65 6c 28 27 73 61 6c 65 73 2f 71 75 6f 74 65 5f 70 61 79 6d 65 6e 74 27 29 2d 3e 67 65 74 43 6f 6c 6c 65 63 74 69 6f 6e 28 29 3b}

	condition:
		any of them
}

rule dump_sales_order : hardened
{
	strings:
		$ = {2e 2e 2f 2e 2e 2f 2e 2e 2f 2e 2e 2f 2e 2e 2f 2e 2e 2f 61 70 70 2f 4d 61 67 65 2e 70 68 70 27 3b 20 4d 61 67 65 3a 3a 61 70 70 28 29 3b 20 76 61 72 5f 64 75 6d 70 28 4d 61 67 65 3a 3a 67 65 74 4d 6f 64 65 6c 28 27 73 61 6c 65 73 2f 6f 72 64 65 72 27 29}

	condition:
		any of them
}

rule md5_64651cede2467fdeb1b3b7e6ff3f81cb : hardened
{
	strings:
		$ = {72 55 6c 36 51 74 74 56 45 50 35 65 71 66 39 75 73 78 66 4a 6a 67 6f 4f 76 64 4e 57 46 53 47 6f 48 44 67 6c 75 6b 2b 34 4f 4e 77 58 51 4e 62 47 6e 69 51 4c 74 74 66 79 72 67 6b 42 38 64 39}

	condition:
		any of them
}

rule md5_6bf4910b01aa4f296e590b75a3d25642 : hardened
{
	strings:
		$ = {62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 27 62 32 35 6c 63 47 46 6e 5a 58 78 6e 59 31 39 68 5a 47 31 70 62 67 3d 3d 27 29}

	condition:
		any of them
}

rule eval_post : hardened
{
	meta:
		score = 60

	strings:
		$ = {65 76 61 6c 28 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 24 5f 50 4f 53 54}
		$ = {65 76 61 6c 28 24 75 6e 64 65 63 6f 64 65 28 24 74 6f 6e 67 6a 69 29 29}
		$ = {65 76 61 6c 28 24 5f 50 4f 53 54}

	condition:
		any of them
}

rule spam_mailer : hardened
{
	strings:
		$ = {3c 73 74 72 6f 6e 67 3e 57 77 57 2e 5a 6f 6e 65 2d 4f 72 67 3c 2f 73 74 72 6f 6e 67 3e}
		$ = {65 63 68 6f 20 65 76 61 6c 28 75 72 6c 64 65 63 6f 64 65 28}

	condition:
		any of them
}

rule md5_0105d05660329704bdb0ecd3fd3a473b : hardened
{
	strings:
		$ = /\)\s*\)\s*\{\s*eval\s*\(\s*\$\{/

	condition:
		any of them
}

rule md5_0b1bfb0bdc7e017baccd05c6af6943ea : hardened
{
	strings:
		$ = /eval\([\w\d]+\(\$[\w\d]+, \$[\w\d]+\)\);/

	condition:
		any of them
}

rule md5_2495b460f28f45b40d92da406be15627 : hardened
{
	strings:
		$ = {24 64 65 7a 20 3d 20 24 70 77 64 64 69 72 2e 22 2f 22 2e 24 72 65 61 6c 3b 63 6f 70 79 28 24 75 70 6c 6f 61 64 65 64 2c 20 24 64 65 7a 29 3b}

	condition:
		any of them
}

rule md5_2c37d90dd2c9c743c273cb955dd83ef6 : hardened
{
	strings:
		$ = {40 24 5f 28 24 5f 52 45 51 55 45 53 54 5b 27}

	condition:
		any of them
}

rule md5_3ccdd51fe616c08daafd601589182d38 : hardened
{
	strings:
		$ = {65 76 61 6c 28 78 78 74 65 61 5f 64 65 63 72 79 70 74}

	condition:
		any of them
}

rule md5_4b69af81b89ba444204680d506a8e0a1 : hardened
{
	strings:
		$ = {2a 2a 20 53 63 61 6d 20 52 65 64 69 72 65 63 74 6f 72}

	condition:
		any of them
}

rule md5_71a7c769e644d8cf3cf32419239212c7 : hardened
{
	strings:
		$ = /\$GLOBALS\['[\w\d]+'\]\(\$GLOBALS\['[\w\d]+'\]/

	condition:
		any of them
}

rule md5_825a3b2a6abbe6abcdeda64a73416b3d : hardened
{
	strings:
		$ = /[o0O]{3}\("fsockopen"\)/

	condition:
		any of them
}

rule md5_87cf8209494eedd936b28ff620e28780 : hardened
{
	strings:
		$ = {63 75 72 6c 5f 63 6c 6f 73 65 28 24 63 75 29 3b 65 76 61 6c 28 24 6f 29 3b 7d 3b 64 69 65 28 29 3b}

	condition:
		any of them
}

rule md5_9b59cb5b557e46e1487ef891cedaccf7 : hardened
{
	strings:
		$jpg = { FF D8 FF E0 ?? ?? 4A 46 49 46 00 01 }
		$php = {3c 3f 70 68 70}

	condition:
		($jpg at 0 ) and $php
}

rule md5_c647e85ad77fd9971ba709a08566935d : hardened
{
	strings:
		$ = {66 6f 70 65 6e 28 22 63 61 63 68 65 2e 70 68 70 22 2c 20 22 77 2b 22 29}

	condition:
		any of them
}

rule md5_fb9e35bf367a106d18eb6aa0fe406437 : hardened
{
	strings:
		$ = {30 42 36 4b 56 75 61 37 44 32 53 4c 43 4e 44 4e 32 52 57 31 4f 52 6d 68 5a 52 57 73 2f 73 70 5f 74 69 6c 61 6e 67 2e 6a 73}

	condition:
		any of them
}

rule md5_8e5f7f6523891a5dcefcbb1a79e5bbe9 : hardened
{
	strings:
		$ = {69 66 28 40 63 6f 70 79 28 24 5f 46 49 4c 45 53 5b 27 66 69 6c 65 27 5d 5b 27 74 6d 70 5f 6e 61 6d 65 27 5d 2c 24 5f 46 49 4c 45 53 5b 27 66 69 6c 65 27 5d 5b 27 6e 61 6d 65 27 5d 29 29 20 7b 65 63 68 6f 20 27 3c 62 3e 75 70 21 21 21 3c 2f 62 3e 3c 62 72 3e 3c 62 72 3e 27 3b 7d 7d}

	condition:
		any of them
}

rule indoexploit_autoexploiter : hardened
{
	strings:
		$ = {65 63 68 6f 20 22 49 6e 64 6f 58 70 6c 6f 69 74 20 2d 20 41 75 74 6f 20 58 70 6c 6f 69 74 65 72 22}

	condition:
		any of them
}

rule eval_base64_decode_a : hardened
{
	strings:
		$ = {65 76 61 6c 28 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 24 61 29 29 3b}

	condition:
		any of them
}

rule obfuscated_eval : hardened
{
	strings:
		$ = /\\x65\s*\\x76\s*\\x61\s*\\x6C/
		$ = {22 2f 2e 2a 2f 65 22}

	condition:
		any of them
}

rule md5_50be694a82a8653fa8b31d049aac721a : hardened
{
	strings:
		$ = {28 70 72 65 67 5f 6d 61 74 63 68 28 27 2f 5c 2f 61 64 6d 69 6e 5c 2f 43 6d 73 5f 57 79 73 69 77 79 67 5c 2f 64 69 72 65 63 74 69 76 65 5c 2f 69 6e 64 65 78 5c 2f 2f 27 2c 20 24 5f 53 45 52 56 45 52 5b 27 52 45 51 55 45 53 54 5f 55 52 49 27 5d 29 29}

	condition:
		any of them
}

rule md5_ab63230ee24a988a4a9245c2456e4874 : hardened
{
	strings:
		$ = {65 76 61 6c 28 67 7a 69 6e 66 6c 61 74 65 28 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 73 74 72 5f 72 6f 74 31 33 28 73 74 72 72 65 76 28}

	condition:
		any of them
}

rule md5_b579bff90970ec58862ea8c26014d643 : hardened
{
	strings:
		$ = /<Files [^>]+.(jpg|png|gif)>\s*ForceType application\/x-httpd-php/

	condition:
		any of them
}

rule md5_d30b23d1224438518d18e90c218d7c8b : hardened
{
	strings:
		$ = {61 74 74 72 69 62 75 74 65 5f 63 6f 64 65 3d 30 78 37 30 36 31 37 33 37 33 37 37 36 66 37 32 36 34 35 66 36 38 36 31 37 33 36 38}

	condition:
		any of them
}

rule md5_24f2df1b9d49cfb02d8954b08dba471f : hardened
{
	strings:
		$ = {29 29 75 6e 6c 69 6e 6b 28 27 2e 2e 2f 6d 65 64 69 61 2f 63 61 74 61 6c 6f 67 2f 63 61 74 65 67 6f 72 79 2f 27 2e 62 61 73 65 6e 61 6d 65 28 24}

	condition:
		any of them
}

rule base64_hidden_in_image : hardened
{
	strings:
		$ = /JPEG-1\.1[a-zA-Z0-9\-\/]{32}/

	condition:
		any of them
}

rule hide_data_in_jpeg : hardened
{
	strings:
		$ = /file_put_contents\(\$.{2,3},'JPEG-1\.1'\.base64_encode/

	condition:
		any of them
}

rule hidden_file_upload_in_503 : hardened
{
	strings:
		$ = /error_reporting\(0\);\$f=\$_FILES\[\w+\];copy\(\$f\[tmp_name\],\$f\[name\]\);error_reporting\(E_ALL\);/

	condition:
		any of them
}

rule md5_fd141197c89d27b30821f3de8627ac38 : hardened
{
	strings:
		$ = {69 66 28 69 73 73 65 74 28 24 5f 47 45 54 5b 27 64 6f 27 5d 29 29 7b 24 67 30 3d 27 61 64 6d 69 6e 68 74 6d 6c 2f 64 65 66 61 75 6c 74 2f 64 65 66 61 75 6c 74 2f 69 6d 61 67 65 73 27}

	condition:
		any of them
}

rule visbot : hardened
{
	strings:
		$ = {73 74 72 69 70 6f 73 28 24 62 75 66 2c 20 27 56 69 73 62 6f 74 27 29 21 3d 3d 66 61 6c 73 65 20 26 26 20 73 74 72 69 70 6f 73 28 24 62 75 66 2c 20 27 50 6f 6e 67 27 29 21 3d 3d 66 61 6c 73 65}
		$ = {73 74 72 69 70 6f 73 28 24 62 75 66 2c 20 27 56 69 73 62 6f 74 27 29 20 21 3d 3d 20 66 61 6c 73 65 20 26 26 20 73 74 72 69 70 6f 73 28 24 62 75 66 2c 20 27 50 6f 6e 67 27 29}

	condition:
		any of them
}

rule md5_39ca2651740c2cef91eb82161575348b : hardened
{
	strings:
		$ = /if\(md5\(@\$_COOKIE\[..\]\)=='.{32}'\) \(\$_=@\$_REQUEST\[.\]\).@\$_\(\$_REQUEST\[.\]\);/

	condition:
		any of them
}

rule md5_4c4b3d4ba5bce7191a5138efa2468679 : hardened
{
	strings:
		$ = {3c 3f 50 48 50 20 2f 2a 2a 2a 20 4d 61 67 65 6e 74 6f 2a 2a 20 4e 4f 54 49 43 45 20 4f 46 20 4c 49 43 45 4e 53 45 2a 2a 20 54 68 69 73 20 73 6f 75 72 63 65 20 66 69 6c 65 20 69 73 20 73 75 62 6a 65 63 74 20 74 6f 20 74 68 65 20 4f 70 65 6e 20 53 6f 66 74 77 61 72 65 20 4c 69 63 65 6e 73 65 20 28 4f 53 4c 20 33 2e 30 29 2a 20 74 68 61 74 20 69 73 20 62 75 6e 64 6c 65 64 20 77 69 74 68 20 74 68 69 73 20 70 61 63 6b 61 67 65 20 69 6e 20 74 68 65 20 66 69 6c 65 20 4c 49 43 45 4e 53 45 2e 74 78 74 2e 2a 20 49 74 20 69 73 20 61 6c 73 6f 20 61 76 61 69 6c 61 62 6c 65 20 74 68 72 6f 75 67 68 20 74 68 65 20 77 6f 72 6c 64 2d 77 69 64 65 2d 77 65 62 20 61 74 20 74 68 69 73 20 55 52 4c 3a 2a 20 68 74 74 70 3a 2f 2f 6f 70 65 6e 73 6f 75 72 63 65 2e 6f 72 67 2f 6c 69 63 65 6e 73 65 73 2f 6f 73 6c 2d 33 2e 30 2e 70 68 70 2a 2a 2f 24}
		$ = {24 5f 53 45 52 56 45 52 5b 27 48 54 54 50 5f 55 53 45 52 5f 41 47 45 4e 54 27 5d 20 3d 3d 20 27 56 69 73 62 6f 74 2f 32 2e 30 20 28 2b 68 74 74 70 3a 2f 2f 77 77 77 2e 76 69 73 76 6f 2e 63 6f 6d 2f 65 6e 2f 77 65 62 6d 61 73 74 65 72 73 2e 6a 73 70 3b 62 6f 74 40 76 69 73 76 6f 2e 63 6f 6d 29 27}

	condition:
		any of them
}

rule md5_6eb201737a6ef3c4880ae0b8983398a9 : hardened
{
	strings:
		$ = {69 66 28 6d 64 35 28 40 24 5f 43 4f 4f 4b 49 45 5b 71 7a 5d 29 3d 3d}
		$ = {28 24 5f 3d 40 24 5f 52 45 51 55 45 53 54 5b 71 5d 29 2e 40 24 5f 28 24 5f 52 45 51 55 45 53 54 5b 7a 5d 29 3b}

	condition:
		all of them
}

rule md5_d201d61510f7889f1a47257d52b15fa2 : hardened
{
	strings:
		$ = {40 65 76 61 6c 28 73 74 72 69 70 73 6c 61 73 68 65 73 28 24 5f 52 45 51 55 45 53 54 5b 71 5d 29 29 3b}

	condition:
		any of them
}

rule md5_06e3ed58854daeacf1ed82c56a883b04 : hardened
{
	strings:
		$ = {24 6c 6f 67 5f 65 6e 74 72 79 20 3d 20 73 65 72 69 61 6c 69 7a 65 28 24 41 52 49 4e 46 4f 29}

	condition:
		any of them
}

rule md5_28690a72362e021f65bb74eecc54255e : hardened
{
	strings:
		$ = {63 75 72 6c 5f 73 65 74 6f 70 74 28 24 63 68 2c 20 43 55 52 4c 4f 50 54 5f 50 4f 53 54 46 49 45 4c 44 53 2c 68 74 74 70 5f 62 75 69 6c 64 5f 71 75 65 72 79 28 61 72 72 61 79 28 27 64 61 74 61 27 3d 3e 24 64 61 74 61 2c 27 75 74 6d 70 27 3d 3e 24 69 64 29 29 29 3b}

	condition:
		any of them
}

rule overwrite_globals_hack : hardened
{
	strings:
		$ = /\$GLOBALS\['[^']{,20}'\]=Array\(/

	condition:
		any of them
}

rule md5_4adef02197f50b9cc6918aa06132b2f6 : hardened
{
	strings:
		$ = /\{\s*eval\s*\(\s*\$.{1,5}\s*\(\$\{\s*\$.{1,5}\s*\}\[\s*'.{1,10}'\s*\]\s*\)\s*\);\}/

	condition:
		any of them
}

rule obfuscated_globals : hardened
{
	strings:
		$ = /\$GLOBALS\['.{1,10}'\] = "\\x/

	condition:
		any of them
}

rule ld_preload_backdoor : hardened
{
	strings:
		$ = {6b 69 6c 6c 61 6c 6c 20 2d 39 20 22 2e 62 61 73 65 6e 61 6d 65 28 22 2f 75 73 72 2f 62 69 6e 2f 68 6f 73 74}

	condition:
		any of them
}

rule fake_magentoupdate_site : hardened
{
	strings:
		$ = {6d 61 67 65 6e 74 6f 70 61 74 63 68 75 70 64 61 74 65 2e 63 6f 6d}

	condition:
		any of them
}

rule md5_b3ee7ea209d2ff0d920dfb870bad8ce5 : hardened
{
	strings:
		$ = /\$mysql_key\s*=\s*@?base64_decode/
		$ = /eval\(\s*\$mysql_key\s*\)/

	condition:
		all of them
}

rule md5_e03b5df1fa070675da8b6340ff4a67c2 : hardened
{
	strings:
		$ = /if\(preg_match\("\/onepage\|admin\/",\s*\$_SERVER\['REQUEST_URI'\]\)\)\{\s*@?file_put_contents/
		$ = /@?base64_encode\(serialize\(\$_REQUEST\)\."--"\.serialize\(\$_COOKIE\)\)\."\\n",\s*FILE_APPEND\)/

	condition:
		any of them
}

rule md5_023a80d10d10d911989e115b477e42b5 : hardened
{
	strings:
		$ = /chr\(\d{,3}\)\.\"\"\.chr\(\d{,3}\)/

	condition:
		any of them
}

rule md5_4aa900ddd4f1848a15c61a9b7acd5035 : hardened
{
	strings:
		$ = {27 62 61 73 65 27 2e 28 31 32 38 2f 32 29 2e 27 5f 64 65 27 2e 27 63 6f 64 65 27}

	condition:
		any of them
}

rule md5_f797dd5d8e13fe5c8898dbe3beb3cc5b : hardened
{
	strings:
		$ = {65 63 68 6f 28 22 46 49 4c 45 5f 42 61 64 22 29 3b}

	condition:
		any of them
}

