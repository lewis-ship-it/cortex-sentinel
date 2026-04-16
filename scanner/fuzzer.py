# scanner/fuzzer.py

import random
import urllib.parse


class SmartFuzzer:

    BASE_PAYLOADS = [
        "' OR 1=1--",
        "<script>alert(1)</script>",
        "\";alert(1);//",
        "';WAITFOR DELAY '0:0:5'--",
    ]

    ENCODERS = [
        lambda x: x,
        urllib.parse.quote,
        lambda x: urllib.parse.quote_plus(x),
        lambda x: x.replace(" ", "/**/"),
        lambda x: x.upper(),
    ]

    def mutate(self, payload):
        encoder = random.choice(self.ENCODERS)
        return encoder(payload)

    def generate(self, context_payloads):
        results = []

        for p in context_payloads:
            results.append(p)

            # mutations
            for _ in range(3):
                mutated = self.mutate(p)
                results.append(mutated)

        # add base payloads
        for base in self.BASE_PAYLOADS:
            results.append(self.mutate(base))

        return list(set(results))