rule Xored_PE : hardened
{
	meta:
		description = "Contains a XORed PE executable"
		author = "Ivan Kwiatkowski (@JusticeRage)"
		score = 60

	strings:
		$a0 = { 55 69 68 72 21 71 73 6E 66 73 60 6C 21 62 60 6F 6F 6E 75 21 63 64 21 73 74 6F 21 68 6F 21 45 4E 52 21 6C 6E 65 64 2F }
		$a1 = { 56 6A 6B 71 22 72 70 6D 65 70 63 6F 22 61 63 6C 6C 6D 76 22 60 67 22 70 77 6C 22 6B 6C 22 46 4D 51 22 6F 6D 66 67 2C }
		$a2 = { 57 6B 6A 70 23 73 71 6C 64 71 62 6E 23 60 62 6D 6D 6C 77 23 61 66 23 71 76 6D 23 6A 6D 23 47 4C 50 23 6E 6C 67 66 2D }
		$a3 = { 50 6C 6D 77 24 74 76 6B 63 76 65 69 24 67 65 6A 6A 6B 70 24 66 61 24 76 71 6A 24 6D 6A 24 40 4B 57 24 69 6B 60 61 2A }
		$a4 = { 51 6D 6C 76 25 75 77 6A 62 77 64 68 25 66 64 6B 6B 6A 71 25 67 60 25 77 70 6B 25 6C 6B 25 41 4A 56 25 68 6A 61 60 2B }
		$a5 = { 52 6E 6F 75 26 76 74 69 61 74 67 6B 26 65 67 68 68 69 72 26 64 63 26 74 73 68 26 6F 68 26 42 49 55 26 6B 69 62 63 28 }
		$a6 = { 53 6F 6E 74 27 77 75 68 60 75 66 6A 27 64 66 69 69 68 73 27 65 62 27 75 72 69 27 6E 69 27 43 48 54 27 6A 68 63 62 29 }
		$a7 = { 5C 60 61 7B 28 78 7A 67 6F 7A 69 65 28 6B 69 66 66 67 7C 28 6A 6D 28 7A 7D 66 28 61 66 28 4C 47 5B 28 65 67 6C 6D 26 }
		$a8 = { 5D 61 60 7A 29 79 7B 66 6E 7B 68 64 29 6A 68 67 67 66 7D 29 6B 6C 29 7B 7C 67 29 60 67 29 4D 46 5A 29 64 66 6D 6C 27 }
		$a9 = { 5E 62 63 79 2A 7A 78 65 6D 78 6B 67 2A 69 6B 64 64 65 7E 2A 68 6F 2A 78 7F 64 2A 63 64 2A 4E 45 59 2A 67 65 6E 6F 24 }
		$a10 = { 5F 63 62 78 2B 7B 79 64 6C 79 6A 66 2B 68 6A 65 65 64 7F 2B 69 6E 2B 79 7E 65 2B 62 65 2B 4F 44 58 2B 66 64 6F 6E 25 }
		$a11 = { 58 64 65 7F 2C 7C 7E 63 6B 7E 6D 61 2C 6F 6D 62 62 63 78 2C 6E 69 2C 7E 79 62 2C 65 62 2C 48 43 5F 2C 61 63 68 69 22 }
		$a12 = { 59 65 64 7E 2D 7D 7F 62 6A 7F 6C 60 2D 6E 6C 63 63 62 79 2D 6F 68 2D 7F 78 63 2D 64 63 2D 49 42 5E 2D 60 62 69 68 23 }
		$a13 = { 5A 66 67 7D 2E 7E 7C 61 69 7C 6F 63 2E 6D 6F 60 60 61 7A 2E 6C 6B 2E 7C 7B 60 2E 67 60 2E 4A 41 5D 2E 63 61 6A 6B 20 }
		$a14 = { 5B 67 66 7C 2F 7F 7D 60 68 7D 6E 62 2F 6C 6E 61 61 60 7B 2F 6D 6A 2F 7D 7A 61 2F 66 61 2F 4B 40 5C 2F 62 60 6B 6A 21 }
		$a15 = { 44 78 79 63 30 60 62 7F 77 62 71 7D 30 73 71 7E 7E 7F 64 30 72 75 30 62 65 7E 30 79 7E 30 54 5F 43 30 7D 7F 74 75 3E }
		$a16 = { 45 79 78 62 31 61 63 7E 76 63 70 7C 31 72 70 7F 7F 7E 65 31 73 74 31 63 64 7F 31 78 7F 31 55 5E 42 31 7C 7E 75 74 3F }
		$a17 = { 46 7A 7B 61 32 62 60 7D 75 60 73 7F 32 71 73 7C 7C 7D 66 32 70 77 32 60 67 7C 32 7B 7C 32 56 5D 41 32 7F 7D 76 77 3C }
		$a18 = { 47 7B 7A 60 33 63 61 7C 74 61 72 7E 33 70 72 7D 7D 7C 67 33 71 76 33 61 66 7D 33 7A 7D 33 57 5C 40 33 7E 7C 77 76 3D }
		$a19 = { 40 7C 7D 67 34 64 66 7B 73 66 75 79 34 77 75 7A 7A 7B 60 34 76 71 34 66 61 7A 34 7D 7A 34 50 5B 47 34 79 7B 70 71 3A }
		$a20 = { 41 7D 7C 66 35 65 67 7A 72 67 74 78 35 76 74 7B 7B 7A 61 35 77 70 35 67 60 7B 35 7C 7B 35 51 5A 46 35 78 7A 71 70 3B }
		$a21 = { 42 7E 7F 65 36 66 64 79 71 64 77 7B 36 75 77 78 78 79 62 36 74 73 36 64 63 78 36 7F 78 36 52 59 45 36 7B 79 72 73 38 }
		$a22 = { 43 7F 7E 64 37 67 65 78 70 65 76 7A 37 74 76 79 79 78 63 37 75 72 37 65 62 79 37 7E 79 37 53 58 44 37 7A 78 73 72 39 }
		$a23 = { 4C 70 71 6B 38 68 6A 77 7F 6A 79 75 38 7B 79 76 76 77 6C 38 7A 7D 38 6A 6D 76 38 71 76 38 5C 57 4B 38 75 77 7C 7D 36 }
		$a24 = { 4D 71 70 6A 39 69 6B 76 7E 6B 78 74 39 7A 78 77 77 76 6D 39 7B 7C 39 6B 6C 77 39 70 77 39 5D 56 4A 39 74 76 7D 7C 37 }
		$a25 = { 4E 72 73 69 3A 6A 68 75 7D 68 7B 77 3A 79 7B 74 74 75 6E 3A 78 7F 3A 68 6F 74 3A 73 74 3A 5E 55 49 3A 77 75 7E 7F 34 }
		$a26 = { 4F 73 72 68 3B 6B 69 74 7C 69 7A 76 3B 78 7A 75 75 74 6F 3B 79 7E 3B 69 6E 75 3B 72 75 3B 5F 54 48 3B 76 74 7F 7E 35 }
		$a27 = { 48 74 75 6F 3C 6C 6E 73 7B 6E 7D 71 3C 7F 7D 72 72 73 68 3C 7E 79 3C 6E 69 72 3C 75 72 3C 58 53 4F 3C 71 73 78 79 32 }
		$a28 = { 49 75 74 6E 3D 6D 6F 72 7A 6F 7C 70 3D 7E 7C 73 73 72 69 3D 7F 78 3D 6F 68 73 3D 74 73 3D 59 52 4E 3D 70 72 79 78 33 }
		$a29 = { 4A 76 77 6D 3E 6E 6C 71 79 6C 7F 73 3E 7D 7F 70 70 71 6A 3E 7C 7B 3E 6C 6B 70 3E 77 70 3E 5A 51 4D 3E 73 71 7A 7B 30 }
		$a30 = { 4B 77 76 6C 3F 6F 6D 70 78 6D 7E 72 3F 7C 7E 71 71 70 6B 3F 7D 7A 3F 6D 6A 71 3F 76 71 3F 5B 50 4C 3F 72 70 7B 7A 31 }
		$a32 = { 75 49 48 52 01 51 53 4E 46 53 40 4C 01 42 40 4F 4F 4E 55 01 43 44 01 53 54 4F 01 48 4F 01 65 6E 72 01 4C 4E 45 44 0F }
		$a33 = { 76 4A 4B 51 02 52 50 4D 45 50 43 4F 02 41 43 4C 4C 4D 56 02 40 47 02 50 57 4C 02 4B 4C 02 66 6D 71 02 4F 4D 46 47 0C }
		$a34 = { 77 4B 4A 50 03 53 51 4C 44 51 42 4E 03 40 42 4D 4D 4C 57 03 41 46 03 51 56 4D 03 4A 4D 03 67 6C 70 03 4E 4C 47 46 0D }
		$a35 = { 70 4C 4D 57 04 54 56 4B 43 56 45 49 04 47 45 4A 4A 4B 50 04 46 41 04 56 51 4A 04 4D 4A 04 60 6B 77 04 49 4B 40 41 0A }
		$a36 = { 71 4D 4C 56 05 55 57 4A 42 57 44 48 05 46 44 4B 4B 4A 51 05 47 40 05 57 50 4B 05 4C 4B 05 61 6A 76 05 48 4A 41 40 0B }
		$a37 = { 72 4E 4F 55 06 56 54 49 41 54 47 4B 06 45 47 48 48 49 52 06 44 43 06 54 53 48 06 4F 48 06 62 69 75 06 4B 49 42 43 08 }
		$a38 = { 73 4F 4E 54 07 57 55 48 40 55 46 4A 07 44 46 49 49 48 53 07 45 42 07 55 52 49 07 4E 49 07 63 68 74 07 4A 48 43 42 09 }
		$a39 = { 7C 40 41 5B 08 58 5A 47 4F 5A 49 45 08 4B 49 46 46 47 5C 08 4A 4D 08 5A 5D 46 08 41 46 08 6C 67 7B 08 45 47 4C 4D 06 }
		$a40 = { 7D 41 40 5A 09 59 5B 46 4E 5B 48 44 09 4A 48 47 47 46 5D 09 4B 4C 09 5B 5C 47 09 40 47 09 6D 66 7A 09 44 46 4D 4C 07 }
		$a41 = { 7E 42 43 59 0A 5A 58 45 4D 58 4B 47 0A 49 4B 44 44 45 5E 0A 48 4F 0A 58 5F 44 0A 43 44 0A 6E 65 79 0A 47 45 4E 4F 04 }
		$a42 = { 7F 43 42 58 0B 5B 59 44 4C 59 4A 46 0B 48 4A 45 45 44 5F 0B 49 4E 0B 59 5E 45 0B 42 45 0B 6F 64 78 0B 46 44 4F 4E 05 }
		$a43 = { 78 44 45 5F 0C 5C 5E 43 4B 5E 4D 41 0C 4F 4D 42 42 43 58 0C 4E 49 0C 5E 59 42 0C 45 42 0C 68 63 7F 0C 41 43 48 49 02 }
		$a44 = { 79 45 44 5E 0D 5D 5F 42 4A 5F 4C 40 0D 4E 4C 43 43 42 59 0D 4F 48 0D 5F 58 43 0D 44 43 0D 69 62 7E 0D 40 42 49 48 03 }
		$a45 = { 7A 46 47 5D 0E 5E 5C 41 49 5C 4F 43 0E 4D 4F 40 40 41 5A 0E 4C 4B 0E 5C 5B 40 0E 47 40 0E 6A 61 7D 0E 43 41 4A 4B 00 }
		$a46 = { 7B 47 46 5C 0F 5F 5D 40 48 5D 4E 42 0F 4C 4E 41 41 40 5B 0F 4D 4A 0F 5D 5A 41 0F 46 41 0F 6B 60 7C 0F 42 40 4B 4A 01 }
		$a47 = { 64 58 59 43 10 40 42 5F 57 42 51 5D 10 53 51 5E 5E 5F 44 10 52 55 10 42 45 5E 10 59 5E 10 74 7F 63 10 5D 5F 54 55 1E }
		$a48 = { 65 59 58 42 11 41 43 5E 56 43 50 5C 11 52 50 5F 5F 5E 45 11 53 54 11 43 44 5F 11 58 5F 11 75 7E 62 11 5C 5E 55 54 1F }
		$a49 = { 66 5A 5B 41 12 42 40 5D 55 40 53 5F 12 51 53 5C 5C 5D 46 12 50 57 12 40 47 5C 12 5B 5C 12 76 7D 61 12 5F 5D 56 57 1C }
		$a50 = { 67 5B 5A 40 13 43 41 5C 54 41 52 5E 13 50 52 5D 5D 5C 47 13 51 56 13 41 46 5D 13 5A 5D 13 77 7C 60 13 5E 5C 57 56 1D }
		$a51 = { 60 5C 5D 47 14 44 46 5B 53 46 55 59 14 57 55 5A 5A 5B 40 14 56 51 14 46 41 5A 14 5D 5A 14 70 7B 67 14 59 5B 50 51 1A }
		$a52 = { 61 5D 5C 46 15 45 47 5A 52 47 54 58 15 56 54 5B 5B 5A 41 15 57 50 15 47 40 5B 15 5C 5B 15 71 7A 66 15 58 5A 51 50 1B }
		$a53 = { 62 5E 5F 45 16 46 44 59 51 44 57 5B 16 55 57 58 58 59 42 16 54 53 16 44 43 58 16 5F 58 16 72 79 65 16 5B 59 52 53 18 }
		$a54 = { 63 5F 5E 44 17 47 45 58 50 45 56 5A 17 54 56 59 59 58 43 17 55 52 17 45 42 59 17 5E 59 17 73 78 64 17 5A 58 53 52 19 }
		$a55 = { 6C 50 51 4B 18 48 4A 57 5F 4A 59 55 18 5B 59 56 56 57 4C 18 5A 5D 18 4A 4D 56 18 51 56 18 7C 77 6B 18 55 57 5C 5D 16 }
		$a56 = { 6D 51 50 4A 19 49 4B 56 5E 4B 58 54 19 5A 58 57 57 56 4D 19 5B 5C 19 4B 4C 57 19 50 57 19 7D 76 6A 19 54 56 5D 5C 17 }
		$a57 = { 6E 52 53 49 1A 4A 48 55 5D 48 5B 57 1A 59 5B 54 54 55 4E 1A 58 5F 1A 48 4F 54 1A 53 54 1A 7E 75 69 1A 57 55 5E 5F 14 }
		$a58 = { 6F 53 52 48 1B 4B 49 54 5C 49 5A 56 1B 58 5A 55 55 54 4F 1B 59 5E 1B 49 4E 55 1B 52 55 1B 7F 74 68 1B 56 54 5F 5E 15 }
		$a59 = { 68 54 55 4F 1C 4C 4E 53 5B 4E 5D 51 1C 5F 5D 52 52 53 48 1C 5E 59 1C 4E 49 52 1C 55 52 1C 78 73 6F 1C 51 53 58 59 12 }
		$a60 = { 69 55 54 4E 1D 4D 4F 52 5A 4F 5C 50 1D 5E 5C 53 53 52 49 1D 5F 58 1D 4F 48 53 1D 54 53 1D 79 72 6E 1D 50 52 59 58 13 }
		$a61 = { 6A 56 57 4D 1E 4E 4C 51 59 4C 5F 53 1E 5D 5F 50 50 51 4A 1E 5C 5B 1E 4C 4B 50 1E 57 50 1E 7A 71 6D 1E 53 51 5A 5B 10 }
		$a62 = { 6B 57 56 4C 1F 4F 4D 50 58 4D 5E 52 1F 5C 5E 51 51 50 4B 1F 5D 5A 1F 4D 4A 51 1F 56 51 1F 7B 70 6C 1F 52 50 5B 5A 11 }
		$a63 = { 14 28 29 33 60 30 32 2F 27 32 21 2D 60 23 21 2E 2E 2F 34 60 22 25 60 32 35 2E 60 29 2E 60 04 0F 13 60 2D 2F 24 25 6E }
		$a64 = { 15 29 28 32 61 31 33 2E 26 33 20 2C 61 22 20 2F 2F 2E 35 61 23 24 61 33 34 2F 61 28 2F 61 05 0E 12 61 2C 2E 25 24 6F }
		$a65 = { 16 2A 2B 31 62 32 30 2D 25 30 23 2F 62 21 23 2C 2C 2D 36 62 20 27 62 30 37 2C 62 2B 2C 62 06 0D 11 62 2F 2D 26 27 6C }
		$a66 = { 17 2B 2A 30 63 33 31 2C 24 31 22 2E 63 20 22 2D 2D 2C 37 63 21 26 63 31 36 2D 63 2A 2D 63 07 0C 10 63 2E 2C 27 26 6D }
		$a67 = { 10 2C 2D 37 64 34 36 2B 23 36 25 29 64 27 25 2A 2A 2B 30 64 26 21 64 36 31 2A 64 2D 2A 64 00 0B 17 64 29 2B 20 21 6A }
		$a68 = { 11 2D 2C 36 65 35 37 2A 22 37 24 28 65 26 24 2B 2B 2A 31 65 27 20 65 37 30 2B 65 2C 2B 65 01 0A 16 65 28 2A 21 20 6B }
		$a69 = { 12 2E 2F 35 66 36 34 29 21 34 27 2B 66 25 27 28 28 29 32 66 24 23 66 34 33 28 66 2F 28 66 02 09 15 66 2B 29 22 23 68 }
		$a70 = { 13 2F 2E 34 67 37 35 28 20 35 26 2A 67 24 26 29 29 28 33 67 25 22 67 35 32 29 67 2E 29 67 03 08 14 67 2A 28 23 22 69 }
		$a71 = { 1C 20 21 3B 68 38 3A 27 2F 3A 29 25 68 2B 29 26 26 27 3C 68 2A 2D 68 3A 3D 26 68 21 26 68 0C 07 1B 68 25 27 2C 2D 66 }
		$a72 = { 1D 21 20 3A 69 39 3B 26 2E 3B 28 24 69 2A 28 27 27 26 3D 69 2B 2C 69 3B 3C 27 69 20 27 69 0D 06 1A 69 24 26 2D 2C 67 }
		$a73 = { 1E 22 23 39 6A 3A 38 25 2D 38 2B 27 6A 29 2B 24 24 25 3E 6A 28 2F 6A 38 3F 24 6A 23 24 6A 0E 05 19 6A 27 25 2E 2F 64 }
		$a74 = { 1F 23 22 38 6B 3B 39 24 2C 39 2A 26 6B 28 2A 25 25 24 3F 6B 29 2E 6B 39 3E 25 6B 22 25 6B 0F 04 18 6B 26 24 2F 2E 65 }
		$a75 = { 18 24 25 3F 6C 3C 3E 23 2B 3E 2D 21 6C 2F 2D 22 22 23 38 6C 2E 29 6C 3E 39 22 6C 25 22 6C 08 03 1F 6C 21 23 28 29 62 }
		$a76 = { 19 25 24 3E 6D 3D 3F 22 2A 3F 2C 20 6D 2E 2C 23 23 22 39 6D 2F 28 6D 3F 38 23 6D 24 23 6D 09 02 1E 6D 20 22 29 28 63 }
		$a77 = { 1A 26 27 3D 6E 3E 3C 21 29 3C 2F 23 6E 2D 2F 20 20 21 3A 6E 2C 2B 6E 3C 3B 20 6E 27 20 6E 0A 01 1D 6E 23 21 2A 2B 60 }
		$a78 = { 1B 27 26 3C 6F 3F 3D 20 28 3D 2E 22 6F 2C 2E 21 21 20 3B 6F 2D 2A 6F 3D 3A 21 6F 26 21 6F 0B 00 1C 6F 22 20 2B 2A 61 }
		$a79 = { 04 38 39 23 70 20 22 3F 37 22 31 3D 70 33 31 3E 3E 3F 24 70 32 35 70 22 25 3E 70 39 3E 70 14 1F 03 70 3D 3F 34 35 7E }
		$a80 = { 05 39 38 22 71 21 23 3E 36 23 30 3C 71 32 30 3F 3F 3E 25 71 33 34 71 23 24 3F 71 38 3F 71 15 1E 02 71 3C 3E 35 34 7F }
		$a81 = { 06 3A 3B 21 72 22 20 3D 35 20 33 3F 72 31 33 3C 3C 3D 26 72 30 37 72 20 27 3C 72 3B 3C 72 16 1D 01 72 3F 3D 36 37 7C }
		$a82 = { 07 3B 3A 20 73 23 21 3C 34 21 32 3E 73 30 32 3D 3D 3C 27 73 31 36 73 21 26 3D 73 3A 3D 73 17 1C 00 73 3E 3C 37 36 7D }
		$a83 = { 00 3C 3D 27 74 24 26 3B 33 26 35 39 74 37 35 3A 3A 3B 20 74 36 31 74 26 21 3A 74 3D 3A 74 10 1B 07 74 39 3B 30 31 7A }
		$a84 = { 01 3D 3C 26 75 25 27 3A 32 27 34 38 75 36 34 3B 3B 3A 21 75 37 30 75 27 20 3B 75 3C 3B 75 11 1A 06 75 38 3A 31 30 7B }
		$a85 = { 02 3E 3F 25 76 26 24 39 31 24 37 3B 76 35 37 38 38 39 22 76 34 33 76 24 23 38 76 3F 38 76 12 19 05 76 3B 39 32 33 78 }
		$a86 = { 03 3F 3E 24 77 27 25 38 30 25 36 3A 77 34 36 39 39 38 23 77 35 32 77 25 22 39 77 3E 39 77 13 18 04 77 3A 38 33 32 79 }
		$a87 = { 0C 30 31 2B 78 28 2A 37 3F 2A 39 35 78 3B 39 36 36 37 2C 78 3A 3D 78 2A 2D 36 78 31 36 78 1C 17 0B 78 35 37 3C 3D 76 }
		$a88 = { 0D 31 30 2A 79 29 2B 36 3E 2B 38 34 79 3A 38 37 37 36 2D 79 3B 3C 79 2B 2C 37 79 30 37 79 1D 16 0A 79 34 36 3D 3C 77 }
		$a89 = { 0E 32 33 29 7A 2A 28 35 3D 28 3B 37 7A 39 3B 34 34 35 2E 7A 38 3F 7A 28 2F 34 7A 33 34 7A 1E 15 09 7A 37 35 3E 3F 74 }
		$a90 = { 0F 33 32 28 7B 2B 29 34 3C 29 3A 36 7B 38 3A 35 35 34 2F 7B 39 3E 7B 29 2E 35 7B 32 35 7B 1F 14 08 7B 36 34 3F 3E 75 }
		$a91 = { 08 34 35 2F 7C 2C 2E 33 3B 2E 3D 31 7C 3F 3D 32 32 33 28 7C 3E 39 7C 2E 29 32 7C 35 32 7C 18 13 0F 7C 31 33 38 39 72 }
		$a92 = { 09 35 34 2E 7D 2D 2F 32 3A 2F 3C 30 7D 3E 3C 33 33 32 29 7D 3F 38 7D 2F 28 33 7D 34 33 7D 19 12 0E 7D 30 32 39 38 73 }
		$a93 = { 0A 36 37 2D 7E 2E 2C 31 39 2C 3F 33 7E 3D 3F 30 30 31 2A 7E 3C 3B 7E 2C 2B 30 7E 37 30 7E 1A 11 0D 7E 33 31 3A 3B 70 }
		$a94 = { 0B 37 36 2C 7F 2F 2D 30 38 2D 3E 32 7F 3C 3E 31 31 30 2B 7F 3D 3A 7F 2D 2A 31 7F 36 31 7F 1B 10 0C 7F 32 30 3B 3A 71 }
		$a95 = { 34 08 09 13 40 10 12 0F 07 12 01 0D 40 03 01 0E 0E 0F 14 40 02 05 40 12 15 0E 40 09 0E 40 24 2F 33 40 0D 0F 04 05 4E }
		$a96 = { 35 09 08 12 41 11 13 0E 06 13 00 0C 41 02 00 0F 0F 0E 15 41 03 04 41 13 14 0F 41 08 0F 41 25 2E 32 41 0C 0E 05 04 4F }
		$a97 = { 36 0A 0B 11 42 12 10 0D 05 10 03 0F 42 01 03 0C 0C 0D 16 42 00 07 42 10 17 0C 42 0B 0C 42 26 2D 31 42 0F 0D 06 07 4C }
		$a98 = { 37 0B 0A 10 43 13 11 0C 04 11 02 0E 43 00 02 0D 0D 0C 17 43 01 06 43 11 16 0D 43 0A 0D 43 27 2C 30 43 0E 0C 07 06 4D }
		$a99 = { 30 0C 0D 17 44 14 16 0B 03 16 05 09 44 07 05 0A 0A 0B 10 44 06 01 44 16 11 0A 44 0D 0A 44 20 2B 37 44 09 0B 00 01 4A }
		$a100 = { 31 0D 0C 16 45 15 17 0A 02 17 04 08 45 06 04 0B 0B 0A 11 45 07 00 45 17 10 0B 45 0C 0B 45 21 2A 36 45 08 0A 01 00 4B }
		$a101 = { 32 0E 0F 15 46 16 14 09 01 14 07 0B 46 05 07 08 08 09 12 46 04 03 46 14 13 08 46 0F 08 46 22 29 35 46 0B 09 02 03 48 }
		$a102 = { 33 0F 0E 14 47 17 15 08 00 15 06 0A 47 04 06 09 09 08 13 47 05 02 47 15 12 09 47 0E 09 47 23 28 34 47 0A 08 03 02 49 }
		$a103 = { 3C 00 01 1B 48 18 1A 07 0F 1A 09 05 48 0B 09 06 06 07 1C 48 0A 0D 48 1A 1D 06 48 01 06 48 2C 27 3B 48 05 07 0C 0D 46 }
		$a104 = { 3D 01 00 1A 49 19 1B 06 0E 1B 08 04 49 0A 08 07 07 06 1D 49 0B 0C 49 1B 1C 07 49 00 07 49 2D 26 3A 49 04 06 0D 0C 47 }
		$a105 = { 3E 02 03 19 4A 1A 18 05 0D 18 0B 07 4A 09 0B 04 04 05 1E 4A 08 0F 4A 18 1F 04 4A 03 04 4A 2E 25 39 4A 07 05 0E 0F 44 }
		$a106 = { 3F 03 02 18 4B 1B 19 04 0C 19 0A 06 4B 08 0A 05 05 04 1F 4B 09 0E 4B 19 1E 05 4B 02 05 4B 2F 24 38 4B 06 04 0F 0E 45 }
		$a107 = { 38 04 05 1F 4C 1C 1E 03 0B 1E 0D 01 4C 0F 0D 02 02 03 18 4C 0E 09 4C 1E 19 02 4C 05 02 4C 28 23 3F 4C 01 03 08 09 42 }
		$a108 = { 39 05 04 1E 4D 1D 1F 02 0A 1F 0C 00 4D 0E 0C 03 03 02 19 4D 0F 08 4D 1F 18 03 4D 04 03 4D 29 22 3E 4D 00 02 09 08 43 }
		$a109 = { 3A 06 07 1D 4E 1E 1C 01 09 1C 0F 03 4E 0D 0F 00 00 01 1A 4E 0C 0B 4E 1C 1B 00 4E 07 00 4E 2A 21 3D 4E 03 01 0A 0B 40 }
		$a110 = { 3B 07 06 1C 4F 1F 1D 00 08 1D 0E 02 4F 0C 0E 01 01 00 1B 4F 0D 0A 4F 1D 1A 01 4F 06 01 4F 2B 20 3C 4F 02 00 0B 0A 41 }
		$a111 = { 24 18 19 03 50 00 02 1F 17 02 11 1D 50 13 11 1E 1E 1F 04 50 12 15 50 02 05 1E 50 19 1E 50 34 3F 23 50 1D 1F 14 15 5E }
		$a112 = { 25 19 18 02 51 01 03 1E 16 03 10 1C 51 12 10 1F 1F 1E 05 51 13 14 51 03 04 1F 51 18 1F 51 35 3E 22 51 1C 1E 15 14 5F }
		$a113 = { 26 1A 1B 01 52 02 00 1D 15 00 13 1F 52 11 13 1C 1C 1D 06 52 10 17 52 00 07 1C 52 1B 1C 52 36 3D 21 52 1F 1D 16 17 5C }
		$a114 = { 27 1B 1A 00 53 03 01 1C 14 01 12 1E 53 10 12 1D 1D 1C 07 53 11 16 53 01 06 1D 53 1A 1D 53 37 3C 20 53 1E 1C 17 16 5D }
		$a115 = { 20 1C 1D 07 54 04 06 1B 13 06 15 19 54 17 15 1A 1A 1B 00 54 16 11 54 06 01 1A 54 1D 1A 54 30 3B 27 54 19 1B 10 11 5A }
		$a116 = { 21 1D 1C 06 55 05 07 1A 12 07 14 18 55 16 14 1B 1B 1A 01 55 17 10 55 07 00 1B 55 1C 1B 55 31 3A 26 55 18 1A 11 10 5B }
		$a117 = { 22 1E 1F 05 56 06 04 19 11 04 17 1B 56 15 17 18 18 19 02 56 14 13 56 04 03 18 56 1F 18 56 32 39 25 56 1B 19 12 13 58 }
		$a118 = { 23 1F 1E 04 57 07 05 18 10 05 16 1A 57 14 16 19 19 18 03 57 15 12 57 05 02 19 57 1E 19 57 33 38 24 57 1A 18 13 12 59 }
		$a119 = { 2C 10 11 0B 58 08 0A 17 1F 0A 19 15 58 1B 19 16 16 17 0C 58 1A 1D 58 0A 0D 16 58 11 16 58 3C 37 2B 58 15 17 1C 1D 56 }
		$a120 = { 2D 11 10 0A 59 09 0B 16 1E 0B 18 14 59 1A 18 17 17 16 0D 59 1B 1C 59 0B 0C 17 59 10 17 59 3D 36 2A 59 14 16 1D 1C 57 }
		$a121 = { 2E 12 13 09 5A 0A 08 15 1D 08 1B 17 5A 19 1B 14 14 15 0E 5A 18 1F 5A 08 0F 14 5A 13 14 5A 3E 35 29 5A 17 15 1E 1F 54 }
		$a122 = { 2F 13 12 08 5B 0B 09 14 1C 09 1A 16 5B 18 1A 15 15 14 0F 5B 19 1E 5B 09 0E 15 5B 12 15 5B 3F 34 28 5B 16 14 1F 1E 55 }
		$a123 = { 28 14 15 0F 5C 0C 0E 13 1B 0E 1D 11 5C 1F 1D 12 12 13 08 5C 1E 19 5C 0E 09 12 5C 15 12 5C 38 33 2F 5C 11 13 18 19 52 }
		$a124 = { 29 15 14 0E 5D 0D 0F 12 1A 0F 1C 10 5D 1E 1C 13 13 12 09 5D 1F 18 5D 0F 08 13 5D 14 13 5D 39 32 2E 5D 10 12 19 18 53 }
		$a125 = { 2A 16 17 0D 5E 0E 0C 11 19 0C 1F 13 5E 1D 1F 10 10 11 0A 5E 1C 1B 5E 0C 0B 10 5E 17 10 5E 3A 31 2D 5E 13 11 1A 1B 50 }
		$a126 = { 2B 17 16 0C 5F 0F 0D 10 18 0D 1E 12 5F 1C 1E 11 11 10 0B 5F 1D 1A 5F 0D 0A 11 5F 16 11 5F 3B 30 2C 5F 12 10 1B 1A 51 }
		$a127 = { D4 E8 E9 F3 A0 F0 F2 EF E7 F2 E1 ED A0 E3 E1 EE EE EF F4 A0 E2 E5 A0 F2 F5 EE A0 E9 EE A0 C4 CF D3 A0 ED EF E4 E5 AE }
		$a128 = { D5 E9 E8 F2 A1 F1 F3 EE E6 F3 E0 EC A1 E2 E0 EF EF EE F5 A1 E3 E4 A1 F3 F4 EF A1 E8 EF A1 C5 CE D2 A1 EC EE E5 E4 AF }
		$a129 = { D6 EA EB F1 A2 F2 F0 ED E5 F0 E3 EF A2 E1 E3 EC EC ED F6 A2 E0 E7 A2 F0 F7 EC A2 EB EC A2 C6 CD D1 A2 EF ED E6 E7 AC }
		$a130 = { D7 EB EA F0 A3 F3 F1 EC E4 F1 E2 EE A3 E0 E2 ED ED EC F7 A3 E1 E6 A3 F1 F6 ED A3 EA ED A3 C7 CC D0 A3 EE EC E7 E6 AD }
		$a131 = { D0 EC ED F7 A4 F4 F6 EB E3 F6 E5 E9 A4 E7 E5 EA EA EB F0 A4 E6 E1 A4 F6 F1 EA A4 ED EA A4 C0 CB D7 A4 E9 EB E0 E1 AA }
		$a132 = { D1 ED EC F6 A5 F5 F7 EA E2 F7 E4 E8 A5 E6 E4 EB EB EA F1 A5 E7 E0 A5 F7 F0 EB A5 EC EB A5 C1 CA D6 A5 E8 EA E1 E0 AB }
		$a133 = { D2 EE EF F5 A6 F6 F4 E9 E1 F4 E7 EB A6 E5 E7 E8 E8 E9 F2 A6 E4 E3 A6 F4 F3 E8 A6 EF E8 A6 C2 C9 D5 A6 EB E9 E2 E3 A8 }
		$a134 = { D3 EF EE F4 A7 F7 F5 E8 E0 F5 E6 EA A7 E4 E6 E9 E9 E8 F3 A7 E5 E2 A7 F5 F2 E9 A7 EE E9 A7 C3 C8 D4 A7 EA E8 E3 E2 A9 }
		$a135 = { DC E0 E1 FB A8 F8 FA E7 EF FA E9 E5 A8 EB E9 E6 E6 E7 FC A8 EA ED A8 FA FD E6 A8 E1 E6 A8 CC C7 DB A8 E5 E7 EC ED A6 }
		$a136 = { DD E1 E0 FA A9 F9 FB E6 EE FB E8 E4 A9 EA E8 E7 E7 E6 FD A9 EB EC A9 FB FC E7 A9 E0 E7 A9 CD C6 DA A9 E4 E6 ED EC A7 }
		$a137 = { DE E2 E3 F9 AA FA F8 E5 ED F8 EB E7 AA E9 EB E4 E4 E5 FE AA E8 EF AA F8 FF E4 AA E3 E4 AA CE C5 D9 AA E7 E5 EE EF A4 }
		$a138 = { DF E3 E2 F8 AB FB F9 E4 EC F9 EA E6 AB E8 EA E5 E5 E4 FF AB E9 EE AB F9 FE E5 AB E2 E5 AB CF C4 D8 AB E6 E4 EF EE A5 }
		$a139 = { D8 E4 E5 FF AC FC FE E3 EB FE ED E1 AC EF ED E2 E2 E3 F8 AC EE E9 AC FE F9 E2 AC E5 E2 AC C8 C3 DF AC E1 E3 E8 E9 A2 }
		$a140 = { D9 E5 E4 FE AD FD FF E2 EA FF EC E0 AD EE EC E3 E3 E2 F9 AD EF E8 AD FF F8 E3 AD E4 E3 AD C9 C2 DE AD E0 E2 E9 E8 A3 }
		$a141 = { DA E6 E7 FD AE FE FC E1 E9 FC EF E3 AE ED EF E0 E0 E1 FA AE EC EB AE FC FB E0 AE E7 E0 AE CA C1 DD AE E3 E1 EA EB A0 }
		$a142 = { DB E7 E6 FC AF FF FD E0 E8 FD EE E2 AF EC EE E1 E1 E0 FB AF ED EA AF FD FA E1 AF E6 E1 AF CB C0 DC AF E2 E0 EB EA A1 }
		$a143 = { C4 F8 F9 E3 B0 E0 E2 FF F7 E2 F1 FD B0 F3 F1 FE FE FF E4 B0 F2 F5 B0 E2 E5 FE B0 F9 FE B0 D4 DF C3 B0 FD FF F4 F5 BE }
		$a144 = { C5 F9 F8 E2 B1 E1 E3 FE F6 E3 F0 FC B1 F2 F0 FF FF FE E5 B1 F3 F4 B1 E3 E4 FF B1 F8 FF B1 D5 DE C2 B1 FC FE F5 F4 BF }
		$a145 = { C6 FA FB E1 B2 E2 E0 FD F5 E0 F3 FF B2 F1 F3 FC FC FD E6 B2 F0 F7 B2 E0 E7 FC B2 FB FC B2 D6 DD C1 B2 FF FD F6 F7 BC }
		$a146 = { C7 FB FA E0 B3 E3 E1 FC F4 E1 F2 FE B3 F0 F2 FD FD FC E7 B3 F1 F6 B3 E1 E6 FD B3 FA FD B3 D7 DC C0 B3 FE FC F7 F6 BD }
		$a147 = { C0 FC FD E7 B4 E4 E6 FB F3 E6 F5 F9 B4 F7 F5 FA FA FB E0 B4 F6 F1 B4 E6 E1 FA B4 FD FA B4 D0 DB C7 B4 F9 FB F0 F1 BA }
		$a148 = { C1 FD FC E6 B5 E5 E7 FA F2 E7 F4 F8 B5 F6 F4 FB FB FA E1 B5 F7 F0 B5 E7 E0 FB B5 FC FB B5 D1 DA C6 B5 F8 FA F1 F0 BB }
		$a149 = { C2 FE FF E5 B6 E6 E4 F9 F1 E4 F7 FB B6 F5 F7 F8 F8 F9 E2 B6 F4 F3 B6 E4 E3 F8 B6 FF F8 B6 D2 D9 C5 B6 FB F9 F2 F3 B8 }
		$a150 = { C3 FF FE E4 B7 E7 E5 F8 F0 E5 F6 FA B7 F4 F6 F9 F9 F8 E3 B7 F5 F2 B7 E5 E2 F9 B7 FE F9 B7 D3 D8 C4 B7 FA F8 F3 F2 B9 }
		$a151 = { CC F0 F1 EB B8 E8 EA F7 FF EA F9 F5 B8 FB F9 F6 F6 F7 EC B8 FA FD B8 EA ED F6 B8 F1 F6 B8 DC D7 CB B8 F5 F7 FC FD B6 }
		$a152 = { CD F1 F0 EA B9 E9 EB F6 FE EB F8 F4 B9 FA F8 F7 F7 F6 ED B9 FB FC B9 EB EC F7 B9 F0 F7 B9 DD D6 CA B9 F4 F6 FD FC B7 }
		$a153 = { CE F2 F3 E9 BA EA E8 F5 FD E8 FB F7 BA F9 FB F4 F4 F5 EE BA F8 FF BA E8 EF F4 BA F3 F4 BA DE D5 C9 BA F7 F5 FE FF B4 }
		$a154 = { CF F3 F2 E8 BB EB E9 F4 FC E9 FA F6 BB F8 FA F5 F5 F4 EF BB F9 FE BB E9 EE F5 BB F2 F5 BB DF D4 C8 BB F6 F4 FF FE B5 }
		$a155 = { C8 F4 F5 EF BC EC EE F3 FB EE FD F1 BC FF FD F2 F2 F3 E8 BC FE F9 BC EE E9 F2 BC F5 F2 BC D8 D3 CF BC F1 F3 F8 F9 B2 }
		$a156 = { C9 F5 F4 EE BD ED EF F2 FA EF FC F0 BD FE FC F3 F3 F2 E9 BD FF F8 BD EF E8 F3 BD F4 F3 BD D9 D2 CE BD F0 F2 F9 F8 B3 }
		$a157 = { CA F6 F7 ED BE EE EC F1 F9 EC FF F3 BE FD FF F0 F0 F1 EA BE FC FB BE EC EB F0 BE F7 F0 BE DA D1 CD BE F3 F1 FA FB B0 }
		$a158 = { CB F7 F6 EC BF EF ED F0 F8 ED FE F2 BF FC FE F1 F1 F0 EB BF FD FA BF ED EA F1 BF F6 F1 BF DB D0 CC BF F2 F0 FB FA B1 }
		$a159 = { F4 C8 C9 D3 80 D0 D2 CF C7 D2 C1 CD 80 C3 C1 CE CE CF D4 80 C2 C5 80 D2 D5 CE 80 C9 CE 80 E4 EF F3 80 CD CF C4 C5 8E }
		$a160 = { F5 C9 C8 D2 81 D1 D3 CE C6 D3 C0 CC 81 C2 C0 CF CF CE D5 81 C3 C4 81 D3 D4 CF 81 C8 CF 81 E5 EE F2 81 CC CE C5 C4 8F }
		$a161 = { F6 CA CB D1 82 D2 D0 CD C5 D0 C3 CF 82 C1 C3 CC CC CD D6 82 C0 C7 82 D0 D7 CC 82 CB CC 82 E6 ED F1 82 CF CD C6 C7 8C }
		$a162 = { F7 CB CA D0 83 D3 D1 CC C4 D1 C2 CE 83 C0 C2 CD CD CC D7 83 C1 C6 83 D1 D6 CD 83 CA CD 83 E7 EC F0 83 CE CC C7 C6 8D }
		$a163 = { F0 CC CD D7 84 D4 D6 CB C3 D6 C5 C9 84 C7 C5 CA CA CB D0 84 C6 C1 84 D6 D1 CA 84 CD CA 84 E0 EB F7 84 C9 CB C0 C1 8A }
		$a164 = { F1 CD CC D6 85 D5 D7 CA C2 D7 C4 C8 85 C6 C4 CB CB CA D1 85 C7 C0 85 D7 D0 CB 85 CC CB 85 E1 EA F6 85 C8 CA C1 C0 8B }
		$a165 = { F2 CE CF D5 86 D6 D4 C9 C1 D4 C7 CB 86 C5 C7 C8 C8 C9 D2 86 C4 C3 86 D4 D3 C8 86 CF C8 86 E2 E9 F5 86 CB C9 C2 C3 88 }
		$a166 = { F3 CF CE D4 87 D7 D5 C8 C0 D5 C6 CA 87 C4 C6 C9 C9 C8 D3 87 C5 C2 87 D5 D2 C9 87 CE C9 87 E3 E8 F4 87 CA C8 C3 C2 89 }
		$a167 = { FC C0 C1 DB 88 D8 DA C7 CF DA C9 C5 88 CB C9 C6 C6 C7 DC 88 CA CD 88 DA DD C6 88 C1 C6 88 EC E7 FB 88 C5 C7 CC CD 86 }
		$a168 = { FD C1 C0 DA 89 D9 DB C6 CE DB C8 C4 89 CA C8 C7 C7 C6 DD 89 CB CC 89 DB DC C7 89 C0 C7 89 ED E6 FA 89 C4 C6 CD CC 87 }
		$a169 = { FE C2 C3 D9 8A DA D8 C5 CD D8 CB C7 8A C9 CB C4 C4 C5 DE 8A C8 CF 8A D8 DF C4 8A C3 C4 8A EE E5 F9 8A C7 C5 CE CF 84 }
		$a170 = { FF C3 C2 D8 8B DB D9 C4 CC D9 CA C6 8B C8 CA C5 C5 C4 DF 8B C9 CE 8B D9 DE C5 8B C2 C5 8B EF E4 F8 8B C6 C4 CF CE 85 }
		$a171 = { F8 C4 C5 DF 8C DC DE C3 CB DE CD C1 8C CF CD C2 C2 C3 D8 8C CE C9 8C DE D9 C2 8C C5 C2 8C E8 E3 FF 8C C1 C3 C8 C9 82 }
		$a172 = { F9 C5 C4 DE 8D DD DF C2 CA DF CC C0 8D CE CC C3 C3 C2 D9 8D CF C8 8D DF D8 C3 8D C4 C3 8D E9 E2 FE 8D C0 C2 C9 C8 83 }
		$a173 = { FA C6 C7 DD 8E DE DC C1 C9 DC CF C3 8E CD CF C0 C0 C1 DA 8E CC CB 8E DC DB C0 8E C7 C0 8E EA E1 FD 8E C3 C1 CA CB 80 }
		$a174 = { FB C7 C6 DC 8F DF DD C0 C8 DD CE C2 8F CC CE C1 C1 C0 DB 8F CD CA 8F DD DA C1 8F C6 C1 8F EB E0 FC 8F C2 C0 CB CA 81 }
		$a175 = { E4 D8 D9 C3 90 C0 C2 DF D7 C2 D1 DD 90 D3 D1 DE DE DF C4 90 D2 D5 90 C2 C5 DE 90 D9 DE 90 F4 FF E3 90 DD DF D4 D5 9E }
		$a176 = { E5 D9 D8 C2 91 C1 C3 DE D6 C3 D0 DC 91 D2 D0 DF DF DE C5 91 D3 D4 91 C3 C4 DF 91 D8 DF 91 F5 FE E2 91 DC DE D5 D4 9F }
		$a177 = { E6 DA DB C1 92 C2 C0 DD D5 C0 D3 DF 92 D1 D3 DC DC DD C6 92 D0 D7 92 C0 C7 DC 92 DB DC 92 F6 FD E1 92 DF DD D6 D7 9C }
		$a178 = { E7 DB DA C0 93 C3 C1 DC D4 C1 D2 DE 93 D0 D2 DD DD DC C7 93 D1 D6 93 C1 C6 DD 93 DA DD 93 F7 FC E0 93 DE DC D7 D6 9D }
		$a179 = { E0 DC DD C7 94 C4 C6 DB D3 C6 D5 D9 94 D7 D5 DA DA DB C0 94 D6 D1 94 C6 C1 DA 94 DD DA 94 F0 FB E7 94 D9 DB D0 D1 9A }
		$a180 = { E1 DD DC C6 95 C5 C7 DA D2 C7 D4 D8 95 D6 D4 DB DB DA C1 95 D7 D0 95 C7 C0 DB 95 DC DB 95 F1 FA E6 95 D8 DA D1 D0 9B }
		$a181 = { E2 DE DF C5 96 C6 C4 D9 D1 C4 D7 DB 96 D5 D7 D8 D8 D9 C2 96 D4 D3 96 C4 C3 D8 96 DF D8 96 F2 F9 E5 96 DB D9 D2 D3 98 }
		$a182 = { E3 DF DE C4 97 C7 C5 D8 D0 C5 D6 DA 97 D4 D6 D9 D9 D8 C3 97 D5 D2 97 C5 C2 D9 97 DE D9 97 F3 F8 E4 97 DA D8 D3 D2 99 }
		$a183 = { EC D0 D1 CB 98 C8 CA D7 DF CA D9 D5 98 DB D9 D6 D6 D7 CC 98 DA DD 98 CA CD D6 98 D1 D6 98 FC F7 EB 98 D5 D7 DC DD 96 }
		$a184 = { ED D1 D0 CA 99 C9 CB D6 DE CB D8 D4 99 DA D8 D7 D7 D6 CD 99 DB DC 99 CB CC D7 99 D0 D7 99 FD F6 EA 99 D4 D6 DD DC 97 }
		$a185 = { EE D2 D3 C9 9A CA C8 D5 DD C8 DB D7 9A D9 DB D4 D4 D5 CE 9A D8 DF 9A C8 CF D4 9A D3 D4 9A FE F5 E9 9A D7 D5 DE DF 94 }
		$a186 = { EF D3 D2 C8 9B CB C9 D4 DC C9 DA D6 9B D8 DA D5 D5 D4 CF 9B D9 DE 9B C9 CE D5 9B D2 D5 9B FF F4 E8 9B D6 D4 DF DE 95 }
		$a187 = { E8 D4 D5 CF 9C CC CE D3 DB CE DD D1 9C DF DD D2 D2 D3 C8 9C DE D9 9C CE C9 D2 9C D5 D2 9C F8 F3 EF 9C D1 D3 D8 D9 92 }
		$a188 = { E9 D5 D4 CE 9D CD CF D2 DA CF DC D0 9D DE DC D3 D3 D2 C9 9D DF D8 9D CF C8 D3 9D D4 D3 9D F9 F2 EE 9D D0 D2 D9 D8 93 }
		$a189 = { EA D6 D7 CD 9E CE CC D1 D9 CC DF D3 9E DD DF D0 D0 D1 CA 9E DC DB 9E CC CB D0 9E D7 D0 9E FA F1 ED 9E D3 D1 DA DB 90 }
		$a190 = { EB D7 D6 CC 9F CF CD D0 D8 CD DE D2 9F DC DE D1 D1 D0 CB 9F DD DA 9F CD CA D1 9F D6 D1 9F FB F0 EC 9F D2 D0 DB DA 91 }
		$a191 = { 94 A8 A9 B3 E0 B0 B2 AF A7 B2 A1 AD E0 A3 A1 AE AE AF B4 E0 A2 A5 E0 B2 B5 AE E0 A9 AE E0 84 8F 93 E0 AD AF A4 A5 EE }
		$a192 = { 95 A9 A8 B2 E1 B1 B3 AE A6 B3 A0 AC E1 A2 A0 AF AF AE B5 E1 A3 A4 E1 B3 B4 AF E1 A8 AF E1 85 8E 92 E1 AC AE A5 A4 EF }
		$a193 = { 96 AA AB B1 E2 B2 B0 AD A5 B0 A3 AF E2 A1 A3 AC AC AD B6 E2 A0 A7 E2 B0 B7 AC E2 AB AC E2 86 8D 91 E2 AF AD A6 A7 EC }
		$a194 = { 97 AB AA B0 E3 B3 B1 AC A4 B1 A2 AE E3 A0 A2 AD AD AC B7 E3 A1 A6 E3 B1 B6 AD E3 AA AD E3 87 8C 90 E3 AE AC A7 A6 ED }
		$a195 = { 90 AC AD B7 E4 B4 B6 AB A3 B6 A5 A9 E4 A7 A5 AA AA AB B0 E4 A6 A1 E4 B6 B1 AA E4 AD AA E4 80 8B 97 E4 A9 AB A0 A1 EA }
		$a196 = { 91 AD AC B6 E5 B5 B7 AA A2 B7 A4 A8 E5 A6 A4 AB AB AA B1 E5 A7 A0 E5 B7 B0 AB E5 AC AB E5 81 8A 96 E5 A8 AA A1 A0 EB }
		$a197 = { 92 AE AF B5 E6 B6 B4 A9 A1 B4 A7 AB E6 A5 A7 A8 A8 A9 B2 E6 A4 A3 E6 B4 B3 A8 E6 AF A8 E6 82 89 95 E6 AB A9 A2 A3 E8 }
		$a198 = { 93 AF AE B4 E7 B7 B5 A8 A0 B5 A6 AA E7 A4 A6 A9 A9 A8 B3 E7 A5 A2 E7 B5 B2 A9 E7 AE A9 E7 83 88 94 E7 AA A8 A3 A2 E9 }
		$a199 = { 9C A0 A1 BB E8 B8 BA A7 AF BA A9 A5 E8 AB A9 A6 A6 A7 BC E8 AA AD E8 BA BD A6 E8 A1 A6 E8 8C 87 9B E8 A5 A7 AC AD E6 }
		$a200 = { 9D A1 A0 BA E9 B9 BB A6 AE BB A8 A4 E9 AA A8 A7 A7 A6 BD E9 AB AC E9 BB BC A7 E9 A0 A7 E9 8D 86 9A E9 A4 A6 AD AC E7 }
		$a201 = { 9E A2 A3 B9 EA BA B8 A5 AD B8 AB A7 EA A9 AB A4 A4 A5 BE EA A8 AF EA B8 BF A4 EA A3 A4 EA 8E 85 99 EA A7 A5 AE AF E4 }
		$a202 = { 9F A3 A2 B8 EB BB B9 A4 AC B9 AA A6 EB A8 AA A5 A5 A4 BF EB A9 AE EB B9 BE A5 EB A2 A5 EB 8F 84 98 EB A6 A4 AF AE E5 }
		$a203 = { 98 A4 A5 BF EC BC BE A3 AB BE AD A1 EC AF AD A2 A2 A3 B8 EC AE A9 EC BE B9 A2 EC A5 A2 EC 88 83 9F EC A1 A3 A8 A9 E2 }
		$a204 = { 99 A5 A4 BE ED BD BF A2 AA BF AC A0 ED AE AC A3 A3 A2 B9 ED AF A8 ED BF B8 A3 ED A4 A3 ED 89 82 9E ED A0 A2 A9 A8 E3 }
		$a205 = { 9A A6 A7 BD EE BE BC A1 A9 BC AF A3 EE AD AF A0 A0 A1 BA EE AC AB EE BC BB A0 EE A7 A0 EE 8A 81 9D EE A3 A1 AA AB E0 }
		$a206 = { 9B A7 A6 BC EF BF BD A0 A8 BD AE A2 EF AC AE A1 A1 A0 BB EF AD AA EF BD BA A1 EF A6 A1 EF 8B 80 9C EF A2 A0 AB AA E1 }
		$a207 = { 84 B8 B9 A3 F0 A0 A2 BF B7 A2 B1 BD F0 B3 B1 BE BE BF A4 F0 B2 B5 F0 A2 A5 BE F0 B9 BE F0 94 9F 83 F0 BD BF B4 B5 FE }
		$a208 = { 85 B9 B8 A2 F1 A1 A3 BE B6 A3 B0 BC F1 B2 B0 BF BF BE A5 F1 B3 B4 F1 A3 A4 BF F1 B8 BF F1 95 9E 82 F1 BC BE B5 B4 FF }
		$a209 = { 86 BA BB A1 F2 A2 A0 BD B5 A0 B3 BF F2 B1 B3 BC BC BD A6 F2 B0 B7 F2 A0 A7 BC F2 BB BC F2 96 9D 81 F2 BF BD B6 B7 FC }
		$a210 = { 87 BB BA A0 F3 A3 A1 BC B4 A1 B2 BE F3 B0 B2 BD BD BC A7 F3 B1 B6 F3 A1 A6 BD F3 BA BD F3 97 9C 80 F3 BE BC B7 B6 FD }
		$a211 = { 80 BC BD A7 F4 A4 A6 BB B3 A6 B5 B9 F4 B7 B5 BA BA BB A0 F4 B6 B1 F4 A6 A1 BA F4 BD BA F4 90 9B 87 F4 B9 BB B0 B1 FA }
		$a212 = { 81 BD BC A6 F5 A5 A7 BA B2 A7 B4 B8 F5 B6 B4 BB BB BA A1 F5 B7 B0 F5 A7 A0 BB F5 BC BB F5 91 9A 86 F5 B8 BA B1 B0 FB }
		$a213 = { 82 BE BF A5 F6 A6 A4 B9 B1 A4 B7 BB F6 B5 B7 B8 B8 B9 A2 F6 B4 B3 F6 A4 A3 B8 F6 BF B8 F6 92 99 85 F6 BB B9 B2 B3 F8 }
		$a214 = { 83 BF BE A4 F7 A7 A5 B8 B0 A5 B6 BA F7 B4 B6 B9 B9 B8 A3 F7 B5 B2 F7 A5 A2 B9 F7 BE B9 F7 93 98 84 F7 BA B8 B3 B2 F9 }
		$a215 = { 8C B0 B1 AB F8 A8 AA B7 BF AA B9 B5 F8 BB B9 B6 B6 B7 AC F8 BA BD F8 AA AD B6 F8 B1 B6 F8 9C 97 8B F8 B5 B7 BC BD F6 }
		$a216 = { 8D B1 B0 AA F9 A9 AB B6 BE AB B8 B4 F9 BA B8 B7 B7 B6 AD F9 BB BC F9 AB AC B7 F9 B0 B7 F9 9D 96 8A F9 B4 B6 BD BC F7 }
		$a217 = { 8E B2 B3 A9 FA AA A8 B5 BD A8 BB B7 FA B9 BB B4 B4 B5 AE FA B8 BF FA A8 AF B4 FA B3 B4 FA 9E 95 89 FA B7 B5 BE BF F4 }
		$a218 = { 8F B3 B2 A8 FB AB A9 B4 BC A9 BA B6 FB B8 BA B5 B5 B4 AF FB B9 BE FB A9 AE B5 FB B2 B5 FB 9F 94 88 FB B6 B4 BF BE F5 }
		$a219 = { 88 B4 B5 AF FC AC AE B3 BB AE BD B1 FC BF BD B2 B2 B3 A8 FC BE B9 FC AE A9 B2 FC B5 B2 FC 98 93 8F FC B1 B3 B8 B9 F2 }
		$a220 = { 89 B5 B4 AE FD AD AF B2 BA AF BC B0 FD BE BC B3 B3 B2 A9 FD BF B8 FD AF A8 B3 FD B4 B3 FD 99 92 8E FD B0 B2 B9 B8 F3 }
		$a221 = { 8A B6 B7 AD FE AE AC B1 B9 AC BF B3 FE BD BF B0 B0 B1 AA FE BC BB FE AC AB B0 FE B7 B0 FE 9A 91 8D FE B3 B1 BA BB F0 }
		$a222 = { 8B B7 B6 AC FF AF AD B0 B8 AD BE B2 FF BC BE B1 B1 B0 AB FF BD BA FF AD AA B1 FF B6 B1 FF 9B 90 8C FF B2 B0 BB BA F1 }
		$a223 = { B4 88 89 93 C0 90 92 8F 87 92 81 8D C0 83 81 8E 8E 8F 94 C0 82 85 C0 92 95 8E C0 89 8E C0 A4 AF B3 C0 8D 8F 84 85 CE }
		$a224 = { B5 89 88 92 C1 91 93 8E 86 93 80 8C C1 82 80 8F 8F 8E 95 C1 83 84 C1 93 94 8F C1 88 8F C1 A5 AE B2 C1 8C 8E 85 84 CF }
		$a225 = { B6 8A 8B 91 C2 92 90 8D 85 90 83 8F C2 81 83 8C 8C 8D 96 C2 80 87 C2 90 97 8C C2 8B 8C C2 A6 AD B1 C2 8F 8D 86 87 CC }
		$a226 = { B7 8B 8A 90 C3 93 91 8C 84 91 82 8E C3 80 82 8D 8D 8C 97 C3 81 86 C3 91 96 8D C3 8A 8D C3 A7 AC B0 C3 8E 8C 87 86 CD }
		$a227 = { B0 8C 8D 97 C4 94 96 8B 83 96 85 89 C4 87 85 8A 8A 8B 90 C4 86 81 C4 96 91 8A C4 8D 8A C4 A0 AB B7 C4 89 8B 80 81 CA }
		$a228 = { B1 8D 8C 96 C5 95 97 8A 82 97 84 88 C5 86 84 8B 8B 8A 91 C5 87 80 C5 97 90 8B C5 8C 8B C5 A1 AA B6 C5 88 8A 81 80 CB }
		$a229 = { B2 8E 8F 95 C6 96 94 89 81 94 87 8B C6 85 87 88 88 89 92 C6 84 83 C6 94 93 88 C6 8F 88 C6 A2 A9 B5 C6 8B 89 82 83 C8 }
		$a230 = { B3 8F 8E 94 C7 97 95 88 80 95 86 8A C7 84 86 89 89 88 93 C7 85 82 C7 95 92 89 C7 8E 89 C7 A3 A8 B4 C7 8A 88 83 82 C9 }
		$a231 = { BC 80 81 9B C8 98 9A 87 8F 9A 89 85 C8 8B 89 86 86 87 9C C8 8A 8D C8 9A 9D 86 C8 81 86 C8 AC A7 BB C8 85 87 8C 8D C6 }
		$a232 = { BD 81 80 9A C9 99 9B 86 8E 9B 88 84 C9 8A 88 87 87 86 9D C9 8B 8C C9 9B 9C 87 C9 80 87 C9 AD A6 BA C9 84 86 8D 8C C7 }
		$a233 = { BE 82 83 99 CA 9A 98 85 8D 98 8B 87 CA 89 8B 84 84 85 9E CA 88 8F CA 98 9F 84 CA 83 84 CA AE A5 B9 CA 87 85 8E 8F C4 }
		$a234 = { BF 83 82 98 CB 9B 99 84 8C 99 8A 86 CB 88 8A 85 85 84 9F CB 89 8E CB 99 9E 85 CB 82 85 CB AF A4 B8 CB 86 84 8F 8E C5 }
		$a235 = { B8 84 85 9F CC 9C 9E 83 8B 9E 8D 81 CC 8F 8D 82 82 83 98 CC 8E 89 CC 9E 99 82 CC 85 82 CC A8 A3 BF CC 81 83 88 89 C2 }
		$a236 = { B9 85 84 9E CD 9D 9F 82 8A 9F 8C 80 CD 8E 8C 83 83 82 99 CD 8F 88 CD 9F 98 83 CD 84 83 CD A9 A2 BE CD 80 82 89 88 C3 }
		$a237 = { BA 86 87 9D CE 9E 9C 81 89 9C 8F 83 CE 8D 8F 80 80 81 9A CE 8C 8B CE 9C 9B 80 CE 87 80 CE AA A1 BD CE 83 81 8A 8B C0 }
		$a238 = { BB 87 86 9C CF 9F 9D 80 88 9D 8E 82 CF 8C 8E 81 81 80 9B CF 8D 8A CF 9D 9A 81 CF 86 81 CF AB A0 BC CF 82 80 8B 8A C1 }
		$a239 = { A4 98 99 83 D0 80 82 9F 97 82 91 9D D0 93 91 9E 9E 9F 84 D0 92 95 D0 82 85 9E D0 99 9E D0 B4 BF A3 D0 9D 9F 94 95 DE }
		$a240 = { A5 99 98 82 D1 81 83 9E 96 83 90 9C D1 92 90 9F 9F 9E 85 D1 93 94 D1 83 84 9F D1 98 9F D1 B5 BE A2 D1 9C 9E 95 94 DF }
		$a241 = { A6 9A 9B 81 D2 82 80 9D 95 80 93 9F D2 91 93 9C 9C 9D 86 D2 90 97 D2 80 87 9C D2 9B 9C D2 B6 BD A1 D2 9F 9D 96 97 DC }
		$a242 = { A7 9B 9A 80 D3 83 81 9C 94 81 92 9E D3 90 92 9D 9D 9C 87 D3 91 96 D3 81 86 9D D3 9A 9D D3 B7 BC A0 D3 9E 9C 97 96 DD }
		$a243 = { A0 9C 9D 87 D4 84 86 9B 93 86 95 99 D4 97 95 9A 9A 9B 80 D4 96 91 D4 86 81 9A D4 9D 9A D4 B0 BB A7 D4 99 9B 90 91 DA }
		$a244 = { A1 9D 9C 86 D5 85 87 9A 92 87 94 98 D5 96 94 9B 9B 9A 81 D5 97 90 D5 87 80 9B D5 9C 9B D5 B1 BA A6 D5 98 9A 91 90 DB }
		$a245 = { A2 9E 9F 85 D6 86 84 99 91 84 97 9B D6 95 97 98 98 99 82 D6 94 93 D6 84 83 98 D6 9F 98 D6 B2 B9 A5 D6 9B 99 92 93 D8 }
		$a246 = { A3 9F 9E 84 D7 87 85 98 90 85 96 9A D7 94 96 99 99 98 83 D7 95 92 D7 85 82 99 D7 9E 99 D7 B3 B8 A4 D7 9A 98 93 92 D9 }
		$a247 = { AC 90 91 8B D8 88 8A 97 9F 8A 99 95 D8 9B 99 96 96 97 8C D8 9A 9D D8 8A 8D 96 D8 91 96 D8 BC B7 AB D8 95 97 9C 9D D6 }
		$a248 = { AD 91 90 8A D9 89 8B 96 9E 8B 98 94 D9 9A 98 97 97 96 8D D9 9B 9C D9 8B 8C 97 D9 90 97 D9 BD B6 AA D9 94 96 9D 9C D7 }
		$a249 = { AE 92 93 89 DA 8A 88 95 9D 88 9B 97 DA 99 9B 94 94 95 8E DA 98 9F DA 88 8F 94 DA 93 94 DA BE B5 A9 DA 97 95 9E 9F D4 }
		$a250 = { AF 93 92 88 DB 8B 89 94 9C 89 9A 96 DB 98 9A 95 95 94 8F DB 99 9E DB 89 8E 95 DB 92 95 DB BF B4 A8 DB 96 94 9F 9E D5 }
		$a251 = { A8 94 95 8F DC 8C 8E 93 9B 8E 9D 91 DC 9F 9D 92 92 93 88 DC 9E 99 DC 8E 89 92 DC 95 92 DC B8 B3 AF DC 91 93 98 99 D2 }
		$a252 = { A9 95 94 8E DD 8D 8F 92 9A 8F 9C 90 DD 9E 9C 93 93 92 89 DD 9F 98 DD 8F 88 93 DD 94 93 DD B9 B2 AE DD 90 92 99 98 D3 }
		$a253 = { AA 96 97 8D DE 8E 8C 91 99 8C 9F 93 DE 9D 9F 90 90 91 8A DE 9C 9B DE 8C 8B 90 DE 97 90 DE BA B1 AD DE 93 91 9A 9B D0 }

	condition:
		any of them
}

rule MiningPool : hardened
{
	meta:
		description = "Contains references to mining pools"
		author = "Ivan Kwiatkowski (@JusticeRage), based on an idea from @__Emilien__"

	strings:
		$stratum = /stratum\+tcp:\/\/[A-Za-z0-9-.:]*/

	condition:
		$stratum
}

