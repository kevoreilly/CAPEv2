rule Generic_Phishing_PDF
{
meta:
	description = "Identifies generic phishing PDFs."
	author = "@bartblaze"
	date = "2019-03"
	reference = "https://bartblaze.blogspot.com/2019/03/analysing-massive-office-365-phishing.html"
	tlp = "White"

strings:
	$pdf = {25504446} //%PDF
	$s1 = "<xmp:CreatorTool>RAD PDF</xmp:CreatorTool>"
	$s2 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"DynaPDF"

condition:
	$pdf at 0 and all of ($s*)
}
