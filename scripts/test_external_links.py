import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
import external_links as links

class LinkTests(unittest.TestCase):
    def test_private_and_insecure_targets_are_rejected(self):
        with self.assertRaises(ValueError):links.validate_url('file:///etc/passwd')
        with self.assertRaises(ValueError):links.validate_url('http://example.com/')
        with patch.object(links.socket,'getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',443))]):
            with self.assertRaises(ValueError):links.validate_url('https://example.com/')

    @patch.object(links, 'validate_url')
    def test_head_rejection_falls_back_to_bounded_get(self, validate):
        response=Mock(status=206)
        context=Mock()
        context.__enter__=Mock(return_value=response)
        context.__exit__=Mock(return_value=False)
        opener=Mock()
        opener.open.side_effect=[HTTPError('https://example.com/',405,'',None,None),context]
        with patch.object(links,'build_opener',return_value=opener), patch.object(links.time,'sleep'):
            self.assertEqual(links.check_url('https://example.com/')[0],'verified')
        request=opener.open.call_args.args[0]
        self.assertEqual(request.method,'GET')
        self.assertEqual(request.headers['Range'],'bytes=0-0')

    @patch.object(links, 'validate_url')
    def test_timeouts_are_inconclusive_not_a_false_pass(self, validate):
        opener=Mock()
        opener.open.side_effect=URLError('timeout')
        with patch.object(links,'build_opener',return_value=opener),patch.object(links.time,'sleep'):
            self.assertEqual(links.check_url('https://example.com/')[0],'inconclusive')
        self.assertEqual(opener.open.call_count,3)

    @patch.object(links, 'validate_url')
    def test_404_is_broken(self, validate):
        opener=Mock()
        opener.open.side_effect=HTTPError('https://example.com/',404,'',None,None)
        with patch.object(links,'build_opener',return_value=opener):
            self.assertEqual(links.check_url('https://example.com/')[0],'broken')

if __name__=='__main__':unittest.main()
