rule malicious_author : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = "5"

	strings:
		$magic = { 25 50 44 46 }
		$reg0 = /Creator.?\(yen vaw\)/
		$reg1 = /Title.?\(who cis\)/
		$reg2 = /Author.?\(ser pes\)/

	condition:
		$magic at 0 and all of ($reg*)
}

rule pattern_pdf_names_1 : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = "5"

	strings:
		$magic = { 25 50 44 46 }
		$reg0 = /\/(Author|Title|Creator) ?\([a-z]{3,4}( [a-z]{3,4}){2,5}\)/ nocase

	condition:
		$magic at 0 and $reg0
}

rule pattern_pdf_names_2 : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = "5"

	strings:
		$magic = { 25 50 44 46 }
		$reg0 = /\/(Author|Title|Creator) ?\([a-z]{3,4}( [a-z]{3,4}){2,}\)/ nocase

	condition:
		$magic at 0 and $reg0
}

rule pattern_pdf_triple : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = "5"

	strings:
		$magic = { 25 50 44 46 }
		$reg0 = /\/Author ?\([a-z]{3,4} [a-z]{3,4}\)/ nocase
		$reg1 = /\/Creator ?\([a-z]{3,4} [a-z]{3,4}\)/ nocase
		$reg2 = /\/Title ?\([a-z]{3,4} [a-z]{3,4}\)/ nocase

	condition:
		$magic at 0 and all of ($reg*)
}

rule pdf_adobe_objstm : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = "5"

	strings:
		$magic = { 25 50 44 46 }
		$reg0 = /Adobe.*ObjStm/ nocase

	condition:
		$magic at 0 and $reg0
}
