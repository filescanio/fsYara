import "dotnet"
import "math"

rule bitmap_dotnet_packer : hardened
{
	meta:
		author = "ppt0"
		description = "Hunt potential .NET packer - stego bitmap in .NET resource. Key is presented as hexadecimal string"
		score = 50
		tags = "bitmap,stego"

	strings:
		$net_subresource_magic_number = { 40 00 01 00 00 00 FF FF FF }
		$system_drawing_bitmap_str = { 53 79 73 74 65 6D 2E 44 72 61 77 69 6E 67 2E 42 69 74 6D 61 70 }
		$png_magic_number = { 89 50 4E 47 0D 0A 1A 0A }

	condition:
		all of them and dotnet.is_dotnet and dotnet.number_of_resources > 0 and for 2 str in dotnet.user_strings : ( str matches /^([0-9A-Fa-f]\x00){4,}$/ ) and ( for 1 r in dotnet.resources : ( #net_subresource_magic_number in ( r.offset..r.offset + r.length ) > 0 and for 1 i in ( 1 .. #net_subresource_magic_number ) : ( @net_subresource_magic_number [ i ] > r.offset and @net_subresource_magic_number [ i ] < r.offset + r.length and $system_drawing_bitmap_str in ( @net_subresource_magic_number [ i ] .. @net_subresource_magic_number [ i ] + 150 ) and $png_magic_number in ( @net_subresource_magic_number [ i ] .. @net_subresource_magic_number [ i ] + 300 ) and ( @net_subresource_magic_number [ i + 1 ] and @net_subresource_magic_number [ i + 1 ] - @net_subresource_magic_number [ i ] > 150 * 1024 and math.entropy ( @net_subresource_magic_number [ i ] , @net_subresource_magic_number [ i + 1 ] ) >= 7 ) or ( #net_subresource_magic_number in ( r.offset..r.offset + r.length ) == 1 and r.offset + r.length - @net_subresource_magic_number [ i ] > 150 * 1024 and math.entropy ( @net_subresource_magic_number [ i ] , r.offset + r.length ) >= 7 ) ) ) )
}

