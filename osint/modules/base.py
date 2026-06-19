class Recon:
    def __init__(self, target):
        self.target = target
        self.results = {}

    def run(self):
        raise NotImplementedError

    def summarize(self):
        print(self.results)