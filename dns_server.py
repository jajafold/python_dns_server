import socket
import dnslib

ROOT = '192.203.230.10'
HOST = '0.0.0.0'
PORT = 12345


class DNS_Server:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((HOST, PORT))
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.pending_ips = [ROOT]

        self.__start()

    def __start(self):
        while True:
            _data, _addr = self.sock.recvfrom(1024)
            _response = self._get_response(_data)

            self.sock.sendto(_response, _addr)

    def _get_answer(self, data, ip) -> (bytes, str):
        self.sock.sendto(data, (ip, 53))

        return self.sock.recvfrom(1024)

    def _update_pending_ips(self, servers) -> list:
        for _server in servers:
            if _server.rtype == 1 and _server.rdata != []:
                self.pending_ips.append(str(_server.rdata))

        return self.pending_ips

    def _get_response(self, data: bytes):
        while True:
            _answer_bytes, _ = self._get_answer(data, self.ips.pop())
            _parsed_following = dnslib.DNSRecord.parse(_answer_bytes)

            self._update_pending_ips(_parsed_following.ar)

            if len(_parsed_following.rr) != 0:
                return _answer_bytes

            _temporary = self._update_pending_ips(_parsed_following.ar)

            if len(_temporary) > 0:
                self.pending_ips += _temporary
                continue

            _section = _parsed_following.auth

            if len(_section) > 0:
                _domain = str(_section[0].rdata)
                _data = dnslib.DNSRecord.question(_domain).pack()

                _response = self._get_response(_data)
                _parsed_response = dnslib.DNSRecord.parse(_response)

                if _parsed_response.header.a == 0:
                    return _answer_bytes

                self._update_pending_ips(_parsed_response.rr)

