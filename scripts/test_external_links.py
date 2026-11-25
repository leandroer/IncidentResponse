import socket
import unittest
from unittest.mock import MagicMock, Mock, patch

import external_links as links


def ipv4(address):
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (address, 443))


class LinkTests(unittest.TestCase):
    @patch.object(links.socket, 'socket')
    @patch.object(links.socket, 'getaddrinfo')
    def test_socket_uses_only_the_validated_address_and_original_tls_name(self, resolve, make_socket):
        resolve.return_value = [ipv4('93.184.216.34')]
        connection = links.PublicHTTPSConnection('example.com')
        connection._context = Mock()
        connection.connect()
        resolve.assert_called_once_with('example.com', 443, type=socket.SOCK_STREAM)
        raw = make_socket.return_value.__enter__.return_value
        raw.connect.assert_called_once_with(('93.184.216.34', 443))
        connection._context.wrap_socket.assert_called_once_with(raw, server_hostname='example.com')
        self.assertIs(connection.sock, connection._context.wrap_socket.return_value)

    @patch.object(links.socket, 'socket')
    @patch.object(links.socket, 'getaddrinfo')
    def test_mixed_address_answers_are_rejected_before_opening_a_socket(self, resolve, make_socket):
        resolve.return_value = [ipv4('93.184.216.34'), ipv4('127.0.0.1')]
        with self.assertRaises(ValueError):
            links.PublicHTTPSConnection('example.com').connect()
        make_socket.assert_not_called()

    @patch.object(links.socket, 'getaddrinfo')
    def test_rejects_ipv6_addresses_with_local_or_translated_destinations(self, resolve):
        for address in ('fec0::1', '64:ff9b::7f00:1', '::ffff:127.0.0.1', 'ff02::1'):
            resolve.return_value = [(socket.AF_INET6, socket.SOCK_STREAM,
                                     socket.IPPROTO_TCP, '', (address, 443, 0, 0))]
            with self.subTest(address=address), self.assertRaises(ValueError):
                links.public_addresses('example.com')

    @patch.object(links, 'PublicHTTPSConnection')
    def test_rejects_insecure_targets_and_redirects(self, connection):
        for url in ('file:///etc/passwd', 'http://example.com/', 'https://@example.com/'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                links.request_status(url, 'HEAD')
        connection.assert_not_called()
        response = connection.return_value.getresponse.return_value.__enter__.return_value
        response.status = 308
        response.getheader.return_value = 'http://example.com/'
        self.assertEqual(links.check_url('https://example.com/')[0], 'inconclusive')
        connection.assert_called_once()

    @patch.object(links, 'PublicHTTPSConnection')
    def test_every_https_redirect_opens_a_fresh_connection_and_get_uses_range(self, connection):
        first, second = Mock(), Mock()
        connection.side_effect = [first, second]
        for conn, status, location in ((first, 308, 'https://other.example/path?q=1#fragment'),
                                       (second, 206, None)):
            response = Mock(status=status)
            response.getheader.return_value = location
            conn.getresponse.return_value = MagicMock()
            conn.getresponse.return_value.__enter__.return_value = response
        self.assertEqual(links.request_status('https://example.com/', 'GET'), 206)
        self.assertEqual([call.args[0] for call in connection.call_args_list],
                         ['example.com', 'other.example'])
        method, path = second.request.call_args.args
        self.assertEqual((method, path), ('GET', '/path?q=1'))
        self.assertEqual(second.request.call_args.kwargs['headers']['Range'], 'bytes=0-0')
        first.close.assert_called_once()
        second.close.assert_called_once()

    @patch.object(links.time, 'sleep')
    @patch.object(links, 'request_status', side_effect=[405, 206])
    def test_head_rejection_falls_back_to_get(self, request, sleep):
        self.assertEqual(links.check_url('https://example.com/')[0], 'verified')
        self.assertEqual([call.args[1] for call in request.call_args_list], ['HEAD', 'GET'])

    @patch.object(links.time, 'sleep')
    @patch.object(links, 'request_status', side_effect=TimeoutError)
    def test_timeouts_are_inconclusive(self, request, sleep):
        self.assertEqual(links.check_url('https://example.com/')[0], 'inconclusive')
        self.assertEqual(request.call_count, 3)

    @patch.object(links, 'request_status', return_value=404)
    def test_404_is_broken(self, request):
        self.assertEqual(links.check_url('https://example.com/')[0], 'broken')


if __name__ == '__main__':
    unittest.main()
