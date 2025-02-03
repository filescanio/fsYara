rule malicious_author : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 5

	strings:
		$magic = { 25 50 44 46 }
		$reg0 = /Creator.?\(yen vaw\)/
		$reg1 = /Title.?\(who cis\)/
		$reg2 = /Author.?\(ser pes\)/

	condition:
		$magic in ( 0 .. 1024 ) and all of ( $reg* )
}

rule suspicious_version : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3

	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1.\d{1}/

	condition:
		$magic in ( 0 .. 1024 ) and not $ver
}

rule suspicious_creation : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		score = 60

	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		$create0 = /CreationDate \(D:20101015142358\)/
		$create1 = /CreationDate \(2008312053854\)/

	condition:
		$magic in ( 0 .. 1024 ) and $header and 1 of ( $create* )
}

rule multiple_filtering : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.2"
		weight = 3

	strings:
		$magic = { 25 50 44 46 }
		$attrib = /\/Filter.*(\/ASCIIHexDecode\W+|\/LZWDecode\W+|\/ASCII85Decode\W+|\/FlateDecode\W+|\/RunLengthDecode){2}/

	condition:
		$magic in ( 0 .. 1024 ) and $attrib
}

rule suspicious_title : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4

	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		$title0 = {77 68 6f 20 63 69 73}
		$title1 = {50 36 36 4e 37 46 46}
		$title2 = {46 6f 68 63 69 72 79 61}

	condition:
		$magic in ( 0 .. 1024 ) and $header and 1 of ( $title* )
}

rule suspicious_author : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4

	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		$author0 = {55 62 7a 67 31 51 55 62 7a 75 7a 67 55 62 52 6a 76 63 55 62 31 34 52 6a 55 62 31}
		$author1 = {73 65 72 20 70 65 73}
		$author2 = {4d 69 65 6b 69 65 6d 6f 65 73}
		$author3 = {4e 73 61 72 6b 6f 6c 6b 65}

	condition:
		$magic in ( 0 .. 1024 ) and $header and 1 of ( $author* )
}

rule suspicious_producer : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2

	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		$producer0 = /Producer \(Scribus PDF Library/
		$producer1 = {4e 6f 74 65 70 61 64}

	condition:
		$magic in ( 0 .. 1024 ) and $header and 1 of ( $producer* )
}

rule possible_exploit : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3

	strings:
		$magic = { 25 50 44 46 }
		$attrib0 = /\/JavaScript /
		$attrib3 = /\/ASCIIHexDecode/
		$attrib4 = /\/ASCII85Decode/
		$action0 = /\/Action/
		$action1 = {41 72 72 61 79}
		$shell = {41}
		$cond0 = {75 6e 65 73 63 61 70 65}
		$cond1 = {53 74 72 69 6e 67 2e 66 72 6f 6d 43 68 61 72 43 6f 64 65}
		$nop = {25 75 39 30 39 30 25 75 39 30 39 30}

	condition:
		$magic in ( 0 .. 1024 ) and ( 2 of ( $attrib* ) ) or ( $action0 and #shell > 10 and 1 of ( $cond* ) ) or ( $action1 and $cond0 and $nop )
}

rule shellcode_blob_metadata : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		description = "When there's a large Base64 blob inserted into metadata fields it often indicates shellcode to later be decoded"
		weight = 4

	strings:
		$magic = { 25 50 44 46 }
		$reg_keyword = /\/Keywords.?\(([a-zA-Z0-9]{200,})/
		$reg_author = /\/Author.?\(([a-zA-Z0-9]{200,})/
		$reg_title = /\/Title.?\(([a-zA-Z0-9]{200,})/
		$reg_producer = /\/Producer.?\(([a-zA-Z0-9]{200,})/
		$reg_creator = /\/Creator.?\(([a-zA-Z0-9]{300,})/
		$reg_create = /\/CreationDate.?\(([a-zA-Z0-9]{200,})/

	condition:
		$magic in ( 0 .. 1024 ) and 1 of ( $reg* )
}

rule suspicious_obfuscation : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 5

	strings:
		$magic = { 25 50 44 46 }
		$reg = /\/\w#[a-zA-Z0-9]{2}#[a-zA-Z0-9]{2}/

	condition:
		$magic in ( 0 .. 1024 ) and #reg > 5
}

rule invalid_XObject_js : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "XObject's require v1.4+"
		ref = "https://blogs.adobe.com/ReferenceXObjects/"
		version = "0.1"
		weight = 2

	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1\.[4-9]/
		$attrib0 = /\/XObject/
		$attrib1 = /\/JavaScript/

	condition:
		$magic in ( 0 .. 1024 ) and not $ver and all of ( $attrib* )
}

rule invalid_trailer_structure : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 1

	strings:
		$magic = { 25 50 44 46 }
		$reg0 = /trailer\r?\n?.*\/Size.*\r?\n?\.*/
		$reg1 = /\/Root.*\r?\n?.*startxref\r?\n?.*\r?\n?%%EOF/

	condition:
		$magic in ( 0 .. 1024 ) and not $reg0 and not $reg1
}

rule multiple_versions : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		description = "Written very generically and doesn't hold any weight - just something that might be useful to know about to help show incremental updates to the file being analyzed"
		weight = 1

	strings:
		$magic = { 25 50 44 46 }
		$s0 = {74 72 61 69 6c 65 72}
		$s1 = {25 25 45 4f 46}

	condition:
		$magic in ( 0 .. 1024 ) and #s0 > 1 and #s1 > 1
}

rule js_wrong_version : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JavaScript was introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 2

	strings:
		$magic = { 25 50 44 46 }
		$js = /\/JavaScript/
		$ver = /%PDF-1\.[3-9]/
		$ver2 = /%PDF-2/

	condition:
		$magic in ( 0 .. 1024 ) and $js and not $ver and not $ver2
}

rule JBIG2_wrong_version : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JBIG2 was introduced in v1.4"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		score = 60

	strings:
		$magic = { 25 50 44 46 }
		$js = /\/JBIG2Decode/
		$ver = /%PDF-1\.[4-9]/

	condition:
		$magic in ( 0 .. 1024 ) and $js and not $ver
}

rule FlateDecode_wrong_version : PDF raw refined hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "Flate was introduced in v1.2"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		score = 40

	strings:
		$magic = { 25 50 44 46 }
		$js = /\/FlateDecode/
		$ver = /%PDF-1\.[2-9]/
		$ver2 = /%PDF-2/

	condition:
		$magic in ( 0 .. 1024 ) and $js and not $ver and not $ver2
}

rule embed_wrong_version : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "EmbeddedFiles were introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1

	strings:
		$magic = { 25 50 44 46 }
		$embed = /\/EmbeddedFiles/
		$ver = /%PDF-1\.[3-9]/
		$ver2 = /%PDF-2/

	condition:
		$magic in ( 0 .. 1024 ) and $embed and not $ver and not $ver2
}

rule invalid_xref_numbers : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		description = "The first entry in a cross-reference table is always free and has a generation number of 65,535"
		notes = "This can be also be in a stream..."
		weight = 1

	strings:
		$magic = { 25 50 44 46 }
		$reg0 = /xref\r?\n?.*\r?\n?.*65535\sf/
		$reg1 = /endstream.*\r?\n?endobj.*\r?\n?startxref/

	condition:
		$magic in ( 0 .. 1024 ) and not $reg0 and not $reg1
}

rule js_splitting : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		description = "These are commonly used to split up JS code"
		weight = 2

	strings:
		$magic = { 25 50 44 46 }
		$js = /\/JavaScript/
		$s0 = {67 65 74 41 6e 6e 6f 74 73}
		$s1 = {67 65 74 50 61 67 65 4e 75 6d 57 6f 72 64 73}
		$s2 = {67 65 74 50 61 67 65 4e 74 68 57 6f 72 64}
		$s3 = {74 68 69 73 2e 69 6e 66 6f}

	condition:
		$magic in ( 0 .. 1024 ) and $js and 1 of ( $s* )
}

rule BlackHole_v2 : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://fortknoxnetworks.blogspot.no/2012/10/blackhhole-exploit-kit-v-20-url-pattern.html"
		weight = 5

	strings:
		$magic = { 25 50 44 46 }
		$content = {49 6e 64 65 78 5b 35 20 31 20 37 20 31 20 39 20 34 20 32 33 20 34 20 35 30}

	condition:
		$magic in ( 0 .. 1024 ) and $content
}

rule XDP_embedded_PDF : PDF raw hardened
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://blog.9bplus.com/av-bypass-for-malicious-pdfs-using-xdp"
		weight = 1

	strings:
		$s1 = {3c 70 64 66 20 78 6d 6c 6e 73 3d}
		$s2 = {3c 63 68 75 6e 6b 3e}
		$s3 = {3c 2f 70 64 66 3e}
		$header0 = {25 50 44 46}
		$header1 = {4a 56 42 45 52 69 30}

	condition:
		all of ( $s* ) and 1 of ( $header* )
}

