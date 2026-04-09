import urllib.parse

class PayloadMutator:

    def mutate(self, payload):
        return [
            payload,
            urllib.parse.quote(payload),
            payload.replace("<", "%3C").replace(">", "%3E"),
            payload.replace("script", "scr<script>ipt"),
        ]