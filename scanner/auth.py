# scanner/auth.py

import requests


class Authenticator:

    def login(self, login_url, username, password):
        session = requests.Session()

        data = {
            "username": username,
            "password": password
        }

        res = session.post(login_url, data=data)

        if res.status_code != 200:
            return None

        return {
            "cookies": session.cookies.get_dict(),
            "headers": dict(session.headers)
        }