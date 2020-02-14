from lib.cuckoo.common.abstracts import Signature

class Static_PDF(Signature):
    name = "static_pdf"
    description = "The PDF file contains suspicious characteristics"
    severity = 2
    weight = 0
    categories = ["pdf","static"]
    authors = ["Kevin Ross","KillerInstinct"]
    minimum = "1.3"

    def run(self):

        exploit = 0

        if "static" in self.results and "pdf" in self.results["static"]:
            if "PDF" in self.results["target"]["file"]["type"]:            
                if "Data After EOF" in self.results["static"]["pdf"]["Info"]:
                    if self.results["static"]["pdf"]["Info"]["Data After EOF"] != "0":
                        self.data.append({"data_after_eof" : "PDF contains data after the declared end of file" })
                        self.weight += 1
                        self.severity = 3

                if "Keywords" in self.results["static"]["pdf"]:
                    if "/Page" in self.results["static"]["pdf"]["Keywords"]:
                        num_pages = self.results["static"]["pdf"]["Keywords"]["/Page"]
                        num_stream = self.results["static"]["pdf"]["Keywords"]["stream"]
                        num_obj = self.results["static"]["pdf"]["Keywords"]["obj"]
                        if num_pages > 10 and num_stream < 10 and num_obj < 35:
                            self.data.append({"content_anomaly" : "PDF is a %s page document yet contains a low amount of objects and streams indicating a possible lack of content"  % (num_pages)})
                            self.weight += 1

                if "Keywords" in self.results["static"]["pdf"]:
                    if "/Page" in self.results["static"]["pdf"]["Keywords"]:
                        num_pages = self.results["static"]["pdf"]["Keywords"]["/Page"]
                        if num_pages == 1:
                            self.data.append({"single_page" : "PDF contains one page. Many malicious PDFs only have one page." })
                            self.weight += 1

                if "Keywords" in self.results["static"]["pdf"]:
                    if "/JavaScript" in self.results["static"]["pdf"]["Keywords"] or "/JS" in self.results["static"]["pdf"]["Keywords"]:
                        if self.results["static"]["pdf"]["Keywords"]["/JavaScript"] > 0 or self.results["static"]["pdf"]["Keywords"]["/JS"] > 0:
                            self.data.append({"javascript_object" : "PDF contains JavaScript usage" })
                            self.weight += 1

                if "Keywords" in self.results["static"]["pdf"]:
                    if "/XFA" in self.results["static"]["pdf"]["Keywords"]:
                        if self.results["static"]["pdf"]["Keywords"]["/XFA"] > 0:
                            self.data.append({"xfa_object" : "Contains an XFA forms object" })
                            self.weight += 1

                if "Keywords" in self.results["static"]["pdf"]:
                    if "/EmbeddedFile" in self.results["static"]["pdf"]["Keywords"]:
                        if self.results["static"]["pdf"]["Keywords"]["/EmbeddedFile"] > 0:
                            self.data.append({"attachment" : "PDF contains an attachment" })
                            self.weight += 1

                if "Keywords" in self.results["static"]["pdf"]:
                    if "/OpenAction" in self.results["static"]["pdf"]["Keywords"] or "/AA" in self.results["static"]["pdf"]["Keywords"]:
                        if self.results["static"]["pdf"]["Keywords"]["/OpenAction"] > 0 or self.results["static"]["pdf"]["Keywords"]["/AA"] > 0:
                            self.data.append({"open_action" : "PDF contains an automatic open action" })
                            self.weight += 1

                # Specific Exploit Detection (this will be expanded upon & generic detections added too)
                if "Keywords" in self.results["static"]["pdf"]:
                    if "/Colors > 2^24" in self.results["static"]["pdf"]["Keywords"]:
                        if self.results["static"]["pdf"]["Keywords"]["/Colors > 2^24"] == 1:
                            self.data.append({"cve2009_3459" : "Colors greater than 2 ^ 24 heap overflow exploit" })
                            exploit += 1

            if exploit > 0:
                self.description += " and contains possible exploit code."
                self.severity = 3
                self.weight += 1
                          
        if self.weight:
            if self.weight >= 3:
                self.severity = 3
            return True

        return False
