import unittest

import app


class SqlInjectionTrainingLabTests(unittest.TestCase):
    def setUp(self):
        app.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        app.init_db()
        app.init_training_db()
        self.client = app.app.test_client()

    def test_pages_render(self):
        for route in ("/", "/vulnerable", "/secure", "/documentation"):
            response = self.client.get(route)
            self.assertEqual(response.status_code, 200)

    def test_vulnerable_training_uses_isolated_database_and_never_creates_session(self):
        response = self.client.post("/vulnerable", data={
            "mode": "vulnerable", "username": "' OR '1'='1' -- ", "password": "wrong"
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Unsafe training check accepted", response.data)
        self.assertIn(b"fictional training record", response.data)
        self.assertNotIn(b"Open the secure session dashboard", response.data)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_vulnerable_training_accepts_normal_fictional_credentials(self):
        response = self.client.post("/vulnerable", data={
            "mode": "vulnerable", "username": app.TRAINING_USERNAME,
            "password": app.TRAINING_PASSWORD,
        })
        self.assertIn(b"Unsafe training check accepted", response.data)

    def test_secure_training_treats_injection_text_as_data(self):
        response = self.client.post("/vulnerable", data={
            "mode": "secure-training", "username": "' OR '1'='1' -- ", "password": "wrong"
        })
        self.assertIn(b"Secure training check rejected", response.data)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_secure_training_normal_credentials_do_not_create_application_session(self):
        response = self.client.post("/vulnerable", data={
            "mode": "secure-training", "username": app.TRAINING_USERNAME,
            "password": app.TRAINING_PASSWORD,
        })
        self.assertIn(b"Secure training check accepted", response.data)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_existing_secure_login_and_logout_still_work(self):
        response = self.client.post("/secure", data={
            "username": app.DEMO_USERNAME, "password": app.DEMO_PASSWORD,
        })
        self.assertIn(b"Login successful", response.data)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.client.post("/logout")
        self.assertEqual(self.client.get("/dashboard").status_code, 302)


if __name__ == "__main__":
    unittest.main()
