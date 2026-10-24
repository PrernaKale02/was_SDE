import unittest

import app


class DefensiveSqlLabTests(unittest.TestCase):
    def setUp(self):
        app.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        app.LOGIN_ATTEMPTS.clear(); app.LOCKOUTS.clear(); app.init_db()
        self.client = app.app.test_client()

    def token(self, route="/"):
        self.client.get(route)
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def test_public_pages_render(self):
        for route in ("/", "/simulator", "/secure", "/quiz"):
            self.assertEqual(self.client.get(route).status_code, 200)

    def test_simulator_classifies_without_unsafe_execution(self):
        response = self.client.post("/simulator", data={"csrf_token": self.token("/simulator"), "username": "' OR '1'='1", "password": "wrong"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Suspicious syntax detected", response.data)
        self.assertNotIn(b"Unsafe training check", response.data)

    def test_csrf_blocks_missing_token(self):
        self.assertEqual(self.client.post("/secure", data={"username": "x", "password": "x"}).status_code, 400)

    def test_secure_login_and_instructor_telemetry(self):
        response = self.client.post("/secure", data={"csrf_token": self.token("/secure"), "username": app.INSTRUCTOR_USERNAME, "password": app.INSTRUCTOR_PASSWORD})
        self.assertIn(b"Login successful", response.data)
        self.assertEqual(self.client.get("/telemetry").status_code, 200)
        self.assertEqual(self.client.get("/report").status_code, 200)

    def test_student_cannot_access_telemetry(self):
        self.client.post("/secure", data={"csrf_token": self.token("/secure"), "username": app.DEMO_USERNAME, "password": app.DEMO_PASSWORD})
        self.assertEqual(self.client.get("/telemetry").status_code, 403)

    def test_quiz_scores_correct_answers(self):
        response = self.client.post("/quiz", data={"csrf_token": self.token("/quiz"), "q1": "parameters", "q2": "hash", "q3": "slow"})
        self.assertIn(b"Score: 3/3", response.data)


if __name__ == "__main__":
    unittest.main()
