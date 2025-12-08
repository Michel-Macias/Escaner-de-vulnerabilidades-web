class BaseVulnerability:
    def __init__(self, requester):
        self.requester = requester
        self.vulnerabilities = []

    def scan(self, target):
        """
        Target can be a URL or a Form dictionary.
        Must be implemented by subclasses.
        """
        raise NotImplementedError
