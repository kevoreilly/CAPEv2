from lib.common.abstracts import Package


class Edge(Package):
    """Edge analysis package."""

    PATHS = [
        ("ProgramFiles", "Microsoft", "Edge", "Application", "msedge.exe"),
    ]
    summary = "Open the URL in Microsoft Edge."
    description = """Use msedge.exe to open the supplied url."""

    def start(self, url):
        edge = self.get_path("msedge.exe")
        return self.execute(edge, f'"{url}"', url)
