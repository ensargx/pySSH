from socket import socket
from .message import Message
from .reader import Reader

from pyssh.util import mpint, uint32, byte
from pyssh._core import hostkey

from pyssh._core import packets, kex, encryption, mac

from typing import Dict, List
import secrets

class Client:
    def __init__(
        self,
        client_sock: socket,
        server_algorithms: Dict[str, List[bytes]],
        server_hostkeys: Dict[bytes, hostkey.HostKey],
        *args,
        **kwargs
    ):
        self.client_sock = client_sock
        self.server_banner = packets.pyssh_banner

        self.encryption_c2s: encryption.Encryption = encryption.EncryptionNone()
        self.encryption_s2c: encryption.Encryption = encryption.EncryptionNone()
        self.mac_c2s: mac.MAC = mac.MACNone()
        self.mac_s2c: mac.MAC = mac.MACNone()
        self.compression = None
        self.kex: kex.KeyExchange
        self.session_id = None
        self.client_banner = None
        self.hostkey: hostkey.HostKey
        self._sequence_number_c2s = 0
        self._sequence_number_s2c = 0
        self._recv_buffer = b''
        self.username: bytes

        return self.setup_connection(server_algorithms, server_hostkeys, *args, **kwargs)
    
    def recv(self) -> Reader:
        """
        Receives 1 packet from the client socket.
        Stores the rest of the data in self._recv_buffer.
        if self._recv_buffer is not empty, it will be used instead of receiving new data.
        """
        if self._recv_buffer:
            data = self._recv_buffer
            self._recv_buffer = b''
        else:
            data = self.client_sock.recv(4096)
        self._sequence_number_c2s = (self._sequence_number_c2s + 1) % (2**32)

        _pack_len = self.encryption_c2s.decrypt(data[:4])
        _pack_len_int = int.from_bytes(_pack_len, "big")

        if _pack_len_int + self.mac_c2s.mac_len + 4 < len(data):
            self._recv_buffer = data[_pack_len_int + self.mac_c2s.mac_len + 4:]
        _data = data[4:_pack_len_int + self.mac_c2s.mac_len + 4]

        _data, mac_sent = self.mac_c2s.parse(_data)
        _data = self.encryption_c2s.decrypt(_data)

        data = _pack_len + _data

        if not self.mac_c2s.verify(uint32(self._sequence_number_c2s) + data, mac_sent):
            raise Exception("MAC verification failed.")

        # TODO: Implement compression.. maybe

        pack = packets.ssh_packet(data)
        return Reader(pack.payload)
    
    def send(self, *messages: Message, **kwargs):
        """
        data = message.payload

        if self.encryption is not None:
            data = self.encryption.encrypt(data)

        if self.mac is not None:
            self.mac.sign(data)

        if self.compression is not None:
            data = self.compression.compress(data)

        packet = ssh_packet._create_packet(data)
        self.client_sock.send(bytes(packet))
        """

        raw_data = b''
        # For each message in messages:
        for message in messages:
            self._sequence_number_s2c = (self._sequence_number_s2c + 1) % (2**32)

            _payload = message.payload
            _cipher_block_size = self.encryption_s2c.cipher_block_size

            # Calculate padding length (RFC 4253, Section 6.1)
            # s.t. lentgh of (packet_length || padding_length || payload || random padding)
            # is a multiple of the cipher block size or 8, whichever is larger.
            # There MUST be at least four bytes of padding. The padding SHOULD consist of random bytes.
            # The maximum amount of padding is 255 bytes.
            _len_packet = len(_payload) + 5 # +1 for padding_length, +4 for packet_length
            _len_padding = _cipher_block_size - (_len_packet % _cipher_block_size)
            while _len_padding < 4: # maybe a lil bit math?
                _len_padding += _cipher_block_size
            
            _padding = secrets.token_bytes(_len_padding)
            _packet_length = _len_packet + _len_padding - 4 # -4 for padding_length itself

            _packet = uint32(_packet_length) + byte(_len_padding) + _payload + _padding
            _mac = self.mac_s2c.sign(uint32(self._sequence_number_s2c) + _packet)

            if self.compression is not None: # actually, compression is not implemented yet
                _packet = self.compression.compress(_packet) # TODO: Implement compression

            _packet_enc = self.encryption_s2c.encrypt(_packet)
            packet = _packet_enc + _mac

            raw_data += bytes(packet)

        self.client_sock.send(raw_data)

    def handler(self, _client):
        self._client = _client

    def setup_connection(self, server_algorithms, server_hostkeys):
        self.client_sock.send(self.server_banner)
        
        client_banner = self.client_sock.recv(4096)
        client_banner = packets.protocol_version_exchange(client_banner)
        if not client_banner:
            raise NotImplementedError("Protocol version exchange failed.")
        self.client_banner = client_banner

        server_kex_init = packets.key_exchange_init()
        server_kex_init = packets.ssh_packet.create_packet(server_kex_init)
        self.client_sock.send(bytes(server_kex_init))
        server_kex_init = Reader(server_kex_init.payload)

        client_kex_init = self.client_sock.recv(4096)
        client_kex_init = packets.ssh_packet(client_kex_init)
        client_kex_init = Reader(client_kex_init.payload)

        message_code = client_kex_init.read_byte()
        assert message_code == 20

        # İF MESSAGE CODE == 20
        cookie = client_kex_init.read_bytes(16)
        kex_algorithms = client_kex_init.read_name_list()
        server_host_key_algorithms = client_kex_init.read_name_list()
        encryption_algorithms_client_to_server = client_kex_init.read_name_list()
        encryption_algorithms_server_to_client = client_kex_init.read_name_list()
        mac_algorithms_client_to_server = client_kex_init.read_name_list()
        mac_algorithms_server_to_client = client_kex_init.read_name_list()
        compression_algorithms_client_to_server = client_kex_init.read_name_list()
        compression_algorithms_server_to_client = client_kex_init.read_name_list()
        languages_client_to_server = client_kex_init.read_name_list()
        languages_server_to_client = client_kex_init.read_name_list()
        first_kex_packet_follows = client_kex_init.read_boolean()
        reserved = client_kex_init.read_uint32()
        # pyright thinks reserved is unused, and it is, and gives warning, so we use it
        reserved = reserved
        # cookie is unused too, so we use it
        cookie = cookie

        kex_algorithm = kex.select_algorithm(kex_algorithms, server_algorithms["kex_algorithms"])
        if kex_algorithm is None:
            raise Exception("No supported key exchange algorithm found.") # TODO: Implement exception

        host_key_algorithm = hostkey.select_algorithm(server_host_key_algorithms)
        if host_key_algorithm is None:
            raise Exception("No supported host key algorithm found.") # TODO: Implement exception
        self.hostkey = server_hostkeys[host_key_algorithm]

        # Set encryption algorithms, TODO: Fix this, server algorithm should be used
        encryption_s2c = encryption.select_algorithm(encryption_algorithms_server_to_client, server_algorithms["encryption_algorithms_s2c"])
        if encryption_s2c is None:
            raise Exception("No supported encryption algorithm found.")
        encryption_c2s = encryption.select_algorithm(encryption_algorithms_client_to_server, server_algorithms["encryption_algorithms_c2s"])
        if encryption_c2s is None:
            raise Exception("No supported encryption algorithm found.")
        
        mac_s2c = mac.select_algorithm(mac_algorithms_server_to_client, server_algorithms["mac_algorithms_s2c"])
        if mac_s2c is None:
            raise Exception("No supported MAC algorithm found.")
        mac_c2s = mac.select_algorithm(mac_algorithms_client_to_server, server_algorithms["mac_algorithms_c2s"])
        if mac_c2s is None:
            raise Exception("No supported MAC algorithm found.")

        self.kex = kex_algorithm.protocol(self, client_kex_init=client_kex_init, server_kex_init=server_kex_init)

        initial_iv_c2s = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"A" + self.kex.session_id)
        initial_iv_s2c = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"B" + self.kex.session_id)
        encryption_key_c2s = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"C" + self.kex.session_id)
        encryption_key_s2c = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"D" + self.kex.session_id)
        integrity_key_c2s = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"E" + self.kex.session_id)
        integrity_key_s2c = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"F" + self.kex.session_id)

        # Encryption is now enabled
        self.encryption_c2s = encryption_c2s(encryption_key_c2s, initial_iv_c2s)
        self.encryption_s2c = encryption_s2c(encryption_key_s2c, initial_iv_s2c)

        # MAC is now enabled
        self.mac_c2s = mac_c2s(integrity_key_c2s)
        self.mac_s2c = mac_s2c(integrity_key_s2c)

        # return self.user_auth()

    def user_auth(self, auth_handler):
        # SERVICE-REQUEST starts                    # RFC 4253
        data = self.recv()
        service_request = data.read_byte()
        service_name = data.read_string()
        assert service_request == 5                 # SSH_MSG_SERVICE_REQUEST
        assert service_name == b"ssh-userauth"      # SSH_MSG_SERVICE_REQUEST
        reply = Message()
        reply.write_byte(6)                         # SSH_MSG_SERVICE_ACCEPT
        reply.write_string(b"ssh-userauth")         # SSH_MSG_SERVICE_ACCEPT
        self.send(reply)
        # SERVICE-REQUEST ends

        authenticating = True
        isAuthenticated = False
        available_methods = [name.encode() for name in auth_handler.keys() if name != "none"]

        # USERAUTH_REQUEST starts                   # RFC 4252
        
        while authenticating and not isAuthenticated:
            data = self.recv()
            userauth_request = data.read_byte()
            user_name = data.read_string()
            self.username = user_name
            service_name = data.read_string()
            method_name = data.read_string()
            assert userauth_request == 50
            assert service_name == b"ssh-connection"

            """
            print("[DEBUG]: method_name:", method_name)
            print("[DEBUG]: available_methods:", available_methods)
            print("[DEBUG]: auth_handler:", auth_handler)
            """

            if method_name == b"none" and "none" in auth_handler:
                isAuthenticated = auth_handler["none"](user_name)
            elif method_name == b"password" and "password" in auth_handler:
                bool_as_byte = data.read_byte()
                password = data.read_string()
                print("[DEBUG]: password auth")
                isAuthenticated = auth_handler["password"](user_name, password)
            elif method_name == b"publickey" and "publickey" in auth_handler:
                isAuthenticated = auth_handler["publickey"](self, user_name)
            elif method_name == b"hostbased" and "hostbased" in auth_handler:
                isAuthenticated = auth_handler["hostbased"](self, user_name)
            elif method_name == b"keyboard_interactive" and b"keyboard_interactive" in auth_handler:
                isAuthenticated = auth_handler["keyboard_interactive"](self, user_name)
            else:
                userauth_failure = Message()
                userauth_failure.write_byte(51)
                userauth_failure.write_name_list(available_methods)
                userauth_failure.write_byte(0)
                self.send(userauth_failure)
                continue

            if isAuthenticated:
                userauth_success = Message()
                userauth_success.write_byte(52)
                self.send(userauth_success)
                authenticating = False
            else:
                userauth_failure = Message()
                userauth_failure.write_byte(51)
                userauth_failure.write_name_list(available_methods)
                userauth_failure.write_byte(0)
                self.send(userauth_failure)

        # USERAUTH_REQUEST ends

        return isAuthenticated

        data = self.recv()
        userauth_request = data.read_byte()
        user_name = data.read_string()
        self.username = user_name
        print("[DEBUG]: username:", user_name)
        service_name = data.read_string()
        method_name = data.read_string()
        assert userauth_request == 50
        assert service_name == b"ssh-connection"    # SSH_MSG_USERAUTH_REQUEST
        assert method_name == b"none"
        print("[DEBUG]: method_name:", method_name)

        userauth_failure = Message()
        userauth_failure.write_byte(51)             # SSH_MSG_USERAUTH_FAILURE
        userauth_failure.write_name_list([b"publickey", b"password"])
        userauth_failure.write_byte(0)
        self.send(userauth_failure)

        auth_banner = Message()
        auth_banner.write_byte(53)                  # SSH_MSG_USERAUTH_BANNER
        auth_banner.write_string(b"Welcome to pyssh!")
        auth_banner.write_string(b"")
        self.send(auth_banner)

        data = self.recv()
        userauth_request = data.read_byte()
        user_name = data.read_string()
        service_name = data.read_string()
        method_name = data.read_string()
        assert userauth_request == 50
        assert service_name == b"ssh-connection"    # SSH_MSG_USERAUTH_REQUEST
        while method_name != b"password":
            print("[DEBUG]: method_name:", method_name)
            userauth_failure = Message()
            userauth_failure.write_byte(51)         # SSH_MSG_USERAUTH_FAILURE
            userauth_failure.write_name_list([b"publickey", b"password"])
            userauth_failure.write_byte(0)
            self.send(userauth_failure)
            data = self.recv()
            userauth_request = data.read_byte()
            user_name = data.read_string()
            service_name = data.read_string()
            method_name = data.read_string()
            assert userauth_request == 50
            assert service_name == b"ssh-connection"
        print("[DEBUG]: method_name:", method_name)

        boolean_as_byte = data.read_byte()
        print("[DEBUG]: boolean_as_byte:", boolean_as_byte)
        print(boolean_as_byte == 0)
        print(boolean_as_byte)
        password = data.read_string()
        print("[DEBUG]: password:", password)

        if password == b"password":
            userauth_success = Message()
            userauth_success.write_byte(52)         # SSH_MSG_USERAUTH_SUCCESS
            self.send(userauth_success)
        else:
            userauth_failure = Message()
            userauth_failure.write_byte(51)
            self.send(userauth_failure)

        # USERAUTH_REQUEST ends

    def get_send(self):
        def send_char(char: bytes):
            message = Message()
            message.write_byte(94)
            message.write_uint32(0)
            message.write_string(char)
            self.send(message)
        return send_char

    def get_recv(self):
        def recv_char():
            data = self.recv()
            message_code = data.read_byte()
            assert message_code == 94
            recipient_channel = data.read_uint32()
            char = data.read_string()
            return char
        return recv_char
    
    def loop(self):
        """
        Client loop. All Encrypted and MAC'd packets are handled here.
        The loop will start after the key exchange is done.

            SSH_MSG_DISCONNECT             1
            SSH_MSG_IGNORE                 2
            SSH_MSG_UNIMPLEMENTED          3
            SSH_MSG_DEBUG                  4
            SSH_MSG_SERVICE_REQUEST        5
            SSH_MSG_SERVICE_ACCEPT         6
        """
        # CHANNEL_OPEN starts                       # RFC 4254  Section 5.1
        data = self.recv()
        channel_open = data.read_byte()
        channel_type = data.read_string()
        sender_channel = data.read_uint32()
        initial_window_size = data.read_uint32()
        maximum_packet_size = data.read_uint32()
        assert channel_open == 90
        assert channel_type == b"session"
        print("[DEBUG]: sender_channel:", sender_channel)
        print("[DEBUG]: initial_window_size:", initial_window_size)
        print("[DEBUG]: maximum_packet_size:", maximum_packet_size)
        channel_open_confirmation = Message()
        channel_open_confirmation.write_byte(91)
        channel_open_confirmation.write_uint32(sender_channel)
        channel_open_confirmation.write_uint32(0)
        channel_open_confirmation.write_uint32(32768)
        channel_open_confirmation.write_uint32(32768)
        self.send(channel_open_confirmation)
        # CHANNEL_OPEN ends

        # PSOUDE-TERMINAL starts                    # RFC 4254  Section 6.2
        data = self.recv()
        channel_request = data.read_byte()
        recipient_channel = data.read_uint32()
        ptty_req = data.read_string()
        want_reply = data.read_boolean()
        term_env = data.read_string()
        terminal_width_chars = data.read_uint32()
        terminal_height_rows = data.read_uint32()
        terminal_width_pixels = data.read_uint32()
        terminal_height_pixels = data.read_uint32()
        terminal_modes = data.read_string()
        assert channel_request == 98
        assert ptty_req == b"pty-req"
        print("[DEBUG]: want_reply:", want_reply)
        print("[DEBUG]: term_env:", term_env)
        print("[DEBUG]: terminal_width_chars:", terminal_width_chars)
        print("[DEBUG]: terminal_height_rows:", terminal_height_rows)
        print("[DEBUG]: terminal_width_pixels:", terminal_width_pixels)
        print("[DEBUG]: terminal_height_pixels:", terminal_height_pixels)
        print("[DEBUG]: terminal_modes:", terminal_modes)
        channel_success = Message()
        channel_success.write_byte(99)
        channel_success.write_uint32(recipient_channel)
        self.send(channel_success)
        # PSOUDE-TERMINAL ends

        # SHELL starts                             # RFC 4254  Section 6.5
        data = self.recv()
        print("[DEBUG]: SHELL starts")
        channel_request = data.read_byte()
        assert channel_request == 98
        recipient_channel = data.read_uint32()
        shell_req = data.read_string()
        want_reply = data.read_boolean()
        while shell_req == b"env":
            print("[DEBUG]: env request")
            env_name = data.read_string()
            env_value = data.read_string()
            print("[DEBUG]: env_name:", env_name)
            print("[DEBUG]: env_value:", env_value)
            channel_success = Message()
            channel_success.write_byte(99)
            channel_success.write_uint32(recipient_channel)
            self.send(channel_success)
            data = self.recv()
            channel_request = data.read_byte()
            assert channel_request == 98
            recipient_channel = data.read_uint32()
            shell_req = data.read_string()
            want_reply = data.read_boolean()
        assert shell_req == b"shell", "Expected shell request, got: " + shell_req.decode("utf-8")
        print("[DEBUG]: want_reply:", want_reply)
        # SHELL ends

        print("[DEBUG]: loop ends")

        terminal = TerminalEmulator()

        def send_chars(char: bytes):
            message = Message()
            message.write_byte(94)
            message.write_uint32(0)
            message.write_string(char)
            self.send(message)

        def recv_chars():
            data = self.recv()
            message_code = data.read_byte()
            assert message_code == 94
            recipient_channel = data.read_uint32()
            char = data.read_string()
            return char

        # Wellcome message if client implemented 
        if hasattr(self._client, "wellcome_message"):
            # if wellcome_message is a function
            if callable(self._client.wellcome_message):
                wellcome = self._client.wellcome_message()
            else:
                wellcome = self._client.wellcome_message
            # send wellcome message to the client
            message = Message()
            message.write_byte(94)
            message.write_uint32(0)
            message.write_string(wellcome)
            self.send(message)

        line = b""
        disc = False
        while not disc:
            chars = recv_chars()
            self._client.handler(chars)
            continue
            for char in chars:
                char = byte(char)
                if char == b"\x03":
                    print("[DEBUG]: CTRL+C")
                    break
                elif char == b"\x1b":
                    print("[DEBUG]: ESCAPE")
                    pass
                elif char == b"q":
                    disc = True
                    break
                elif char == b"\x7f":
                    # delete key
                    print("[DEBUG]: DELETE")
                    line = line[:-1]
                    send_chars(b"\x1b[D" + terminal.CLEAR_LINE + b"\r" + prompt + line)
                elif char == b"\r":
                    # send the message to other clients ...
                    print("[DEBUG]: send message:", line)
                    received = user_name + b": " + line
                    to_sent = terminal.CLEAR_LINE + b"\r" + received + terminal.NEWLINE + prompt
                    send_chars(to_sent)
                    line = b""
                elif char == b"t":
                    # testing purposes
                    received = b"alice: How are you?"
                    # to sent : clear line + carraige return + prompt + received + line
                    to_sent = terminal.CLEAR_LINE + b"\r" + received + terminal.NEWLINE + prompt + line
                    send_chars(to_sent)
                else:
                    line += char
                    send_chars(char)
                    print("[DEBUG]: received char:", char)

            if char and char == b"\x03":
                break
        print("[DEBUG]: loop ends")

        # CHANNEL_CLOSE starts                      # RFC 4254  Section 5.#!/usr/bin/env python3
        bye = Message()
        bye.write_byte(97)
        bye.write_uint32(0)
        self.send(bye)
        print("[DEBUG]: CHANNEL_CLOSE ends")
        # CHANNEL_CLOSE ends
                    

class TerminalEmulator:
    NEWLINE = b"\r\n"
    CLEAR_SCREEN = b"\x1b[2J"
    CLEAR_LINE = b"\x1b[2K"
    CURSOR_HOME = b"\x1b[H"
    CURSOR_UP = b"\x1b[A"
    CURSOR_DOWN = b"\x1b[B"
    CURSOR_LEFT = b"\x1b[D"
    CURSOR_RIGHT = b"\x1b[C"
    CURSOR_SAVE = b"\x1b[s"
    CURSOR_RESTORE = b"\x1b[u"
    CURSOR_HIDE = b"\x1b[?25l"
    CURSOR_SHOW = b"\x1b[?25h"
    DELETE_KEY = b"\x7f"

    @staticmethod
    def parse_chars(chars: bytes):
        # check for escape sequences
        if chars[:2] == b"\x1b[":
            if chars[-1] == b"A":
                return TerminalEmulator.CURSOR_UP
            elif chars[-1] == b"B":
                return TerminalEmulator.CURSOR_DOWN
            elif chars[-1] == b"C":
                return TerminalEmulator.CURSOR_RIGHT
            elif chars[-1] == b"D":
                return TerminalEmulator.CURSOR_LEFT
            elif chars[-1] == b"J":
                return TerminalEmulator.CLEAR_SCREEN
            elif chars[-1] == b"K":
                return TerminalEmulator.CLEAR_LINE
            elif chars[-1] == b"H":
                return TerminalEmulator.CURSOR_HOME

        return chars
