from lib.common.abstracts import Package


class Edge(Package):
    """Edge analysis package."""

    PATHS = [
        ("ProgramFiles", "Microsoft", "Edge", "Application", "msedge.exe"),
    ]

    def start(self, url):
        chrome = self.get_path("chrome.exe")
        args = [
            "--disable-features=RendererCodeIntegrity",
    ]
        args.append('"{}"'.format(url))
        args = args.join(" ")
        return self.execute(chrome, args)
