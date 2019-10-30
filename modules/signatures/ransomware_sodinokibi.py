from lib.cuckoo.common.abstracts import Signature

powershell = "RwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAFcAaQBuADMAMgBfAFMAaABhAGQAbwB3AGMAbwBwAHkAIAB8ACAARgBvAHIARQBhAGMAaAAtAE8AYgBqAGUAYwB0ACAAewAkAF8ALgBEAGUAbABlAHQAZQAoACkAOwB9AA=="

reg = (
	"HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\QtProject\OrganizationDefaults\SdXX6SS",
	"HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\QtProject\OrganizationDefaults\Xq71vG",
)

class sodinokibi(Signature):
	name = "Sodinokibi Behavior"
	description = "Detects Agent Sodinokibi Behavior"
	weight = 3
	severity = 3
	categories = ["Ransomware"]
	families = ["Sodinokibi"]
	authors = ["@NaxoneZ"]
	minimum = "1.2"
	evented = True
	samples = {
	"Sodinokibi":
		{
			"1": "03eb9b0e4e842cbe3726872ed46e241f5b79e18a09e1655341a403ac3e5136a6", #variant1
		}
	}

	def __init__(self, *args, **kwargs):
		Signature.__init__(self, *args, **kwargs)
		self.badness_reg = 0
		self.badness_powershell = 0
		self.badness_url = 0

	filter_apinames = set(["RegSetValueExW","CreateProcessInternalW","WinHttpOpen","bind"])

	def on_call(self, call, process):
		if call["api"] == "RegSetValueExW":
			node = self.get_argument(call,"FullName")
			for i in reg:
				if i in node:
					self.badness_reg +=1

		if call["api"] == "CreateProcessInternalW":
			node = self.get_argument(call,"CommandLine")
			if powershell in node:
				self.badness_powershell +=1

		if call["api"] == "WinHttpOpen":
			node = self.get_argument(call,"UserAgent")
			if "Mozilla/5.0 (Windows NT 5.1; rv:36.0) Gecko/20100101 Firefox/36.0" in node:
				self.badness_url +=1

		if call["api"] == "bind":
			node = self.get_argument(call,"ip")
			if "0.0.0.0" in node:
				self.badness_url +=1




	def on_complete(self):
		#Variant 1
		if self.badness_powershell > 0 and self.badness_reg> 2 and self.badness_url > 2:
			return True

		else:
			return False
