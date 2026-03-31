# scanner/auth_handler.py

import logging

class AuthHandler:

    async def login(self, client, login_url, username, password):
        """
        Performs form-based login.
        You may need to customize field names per site.
        """

        payload = {
            "username": username,
            "password": password
        }

        try:
            logging.info(f"[AUTH] Attempting login: {login_url}")

            res = await client.post(login_url, data=payload)

            # basic success check
            if res.status_code == 200:
                logging.info("[AUTH] Login request sent")

                # check if session cookie exists
                if client.cookies:
                    logging.info("[AUTH] Session established")
                    return True

            logging.warning("[AUTH] Login may have failed")
            return False

        except Exception as e:
            logging.error(f"[AUTH ERROR] {e}")
            return False

    def inject_cookies(self, client, cookie_dict):
        """
        Manual session injection (for already logged-in sessions)
        """
        for k, v in cookie_dict.items():
            client.cookies.set(k, v)

        logging.info("[AUTH] Cookies injected")