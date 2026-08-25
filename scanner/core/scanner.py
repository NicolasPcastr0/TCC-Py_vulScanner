class Scanner:

    def __init__(self):
        self.modules = []

    def register_module(self, module):
        self.modules.append(module)

    def run(self, **kwargs):
        findings = []

        for module in self.modules:
            results = module(**kwargs)

            if results is None:
                continue

            if isinstance(results, list):
                findings.extend(results)
            else:
                findings.append(results)

        return findings