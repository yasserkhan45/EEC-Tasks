try:
    import unittest
    from app import app

except Exception as e:
    print ("Some Modules are missing {} ".format(e))

class FlaskTest(unittest.TestCase):
    
    def test_authors_status(self):
        tester = app.test_client(self)
        response = tester.get("/authors")
        statuscode = response.status_code
        self.assertEqual(statuscode, 200)
    
    def test_author_status(self):
        tester = app.test_client(self)
        response = tester.get("/author")
        statuscode = response.status_code
        self.assertEqual(statuscode, 200)

    def test_authors(self):
        tester = app.test_client(self)
        response = tester.get("/authors")
        self.assertEqual(response.content_type, "application/json")
    
    def test_author(self):
        tester = app.test_client(self)
        response = tester.get("/author")
        self.assertEqual(response.content_type, "application/json")
    
    def test_authors_data(self):
        tester = app.test_client(self)
        response = tester.get("/authors")
        self.assertTrue(b'message' in response.data)

    def test_author_data(self):
        tester = app.test_client(self)
        response = tester.get("/author")
        self.assertTrue(b'message' in response.data)
    

if __name__ == "__main__":
    unittest.main()
