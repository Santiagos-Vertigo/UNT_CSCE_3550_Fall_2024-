import unittest
import json
from main import app  # Ensure this points to your main.py

class TestJWKSService(unittest.TestCase):

    def setUp(self):
        # Create a test client
        self.app = app.test_client()
        self.app.testing = True

    # Home Page Endpoint Test
    def test_home_page(self):
        response = self.app.get('/')
        print(f"Home Page Response: {response.data}")  # Debugging the response data
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome to the JWKS and JWT server!', response.data)

    # Key Pair Generation Test
    def test_generate_key_pair(self):
        response = self.app.post('/generate', json={})
        print(f"Generate Key Pair Response: {response.data}")  # Debugging the response data
        self.assertEqual(response.status_code, 200)
        try:
            data = json.loads(response.data)
        except json.JSONDecodeError:
            self.fail("Response is not valid JSON")
        self.assertIn('kid', data)
        self.assertIn('public_key', data)
        self.assertIn('n', data['public_key'])

    # JWKS Endpoint Test
    def test_jwks_endpoint(self):
        # First, generate a key so the JWKS endpoint has something to return
        self.app.post('/generate', json={})
        response = self.app.get('/jwks')
        print(f"JWKS Endpoint Response: {response.data}")  # Debugging the response data
        self.assertEqual(response.status_code, 200)
        try:
            data = json.loads(response.data)
        except json.JSONDecodeError:
            self.fail("Response is not valid JSON")
        self.assertIn('keys', data)
        self.assertGreaterEqual(len(data['keys']), 1)

    # Auth Endpoint Test
    def test_auth_endpoint(self):
        # Generate a key first
        generate_response = self.app.post('/generate', json={})
        print(f"Generate Response for Auth: {generate_response.data}")  # Debugging the generate response
        try:
            kid = json.loads(generate_response.data)['kid']
        except json.JSONDecodeError:
            self.fail("Response is not valid JSON from /generate")
        
        # Request a token with the generated kid
        response = self.app.post('/auth', json={"kid": kid, "sub": "user"})
        print(f"Auth Endpoint Response: {response.data}")  # Debugging the auth response
        self.assertEqual(response.status_code, 200)
        try:
            data = json.loads(response.data)
        except json.JSONDecodeError:
            self.fail("Response is not valid JSON")
        self.assertIn('token', data)

    # Expired Key Auth Test
    def test_expired_key_auth(self):
        # Generate a key first
        generate_response = self.app.post('/generate', json={})
        print(f"Generate Response for Expired Auth: {generate_response.data}")  # Debugging the generate response
        try:
            kid = json.loads(generate_response.data)['kid']
        except json.JSONDecodeError:
            self.fail("Response is not valid JSON from /generate")
        
        # Request a token with the "expired" flag set
        response = self.app.post(f'/auth/expired?expired=true', json={"kid": kid, "sub": "user"})
        print(f"Expired Auth Response: {response.data}")  # Debugging the expired auth response
        self.assertEqual(response.status_code, 200)
        try:
            data = json.loads(response.data)
        except json.JSONDecodeError:
            self.fail("Response is not valid JSON")
        self.assertIn('token', data)

    # Expiration Time Test
    def test_expire_time_constant(self):
        from main import EXPIRE_TIME
        print(f"Expiration Time: {EXPIRE_TIME}")  # Debugging expiration time constant
        self.assertTrue(EXPIRE_TIME > 0)

if __name__ == '__main__':
    unittest.main()
