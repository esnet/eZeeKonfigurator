from selenium import webdriver
import unittest


class HomePageTest(unittest.TestCase):

    def setUp(self):
        self.browser = webdriver.Firefox()

    def tearDown(self):
        self.browser.quit()

    def test_viewing_the_home_page(self):
        # Go to the homepage
        self.browser.get('http://localhost:8000')

        # Make sure the title is correct
        self.assertIn('eZeeKonfigurator', self.browser.title)

        # TODO
        self.fail('Test more things!')


if __name__ == "__main__":
    unittest.main(warnings='ignore')
