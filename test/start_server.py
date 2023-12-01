import socket
import pyssh
import base64

from pyssh._core import kex

from pyssh._core._util import mpint, string, byte

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.backends import default_backend

from pyssh._core.hash import Hash
from pyssh._core import Message
from pyssh._core import Reader

from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1

private_key = RSA.import_key(open("/home/ensargok/keys/id_rsa.pem").read())
public_key = RSA.import_key(open("/home/ensargok/keys/id_rsa.pub").read())

def hash_and_sign(data):
    return pkcs1_15.new(private_key).sign(SHA1.new(data))

def sign_with_rsa(data):
    return pkcs1_15.new(private_key).sign(data)

import os
def sign_with_key(data):
    with open("/tmp/data", "wb") as f:
        f.write(data)

    os.system('openssl dgst -sha1 -sign /tmp/id_rsa.pem -out /tmp/signature.bin /tmp/data')

    with open("/tmp/signature.bin", "rb") as f:
        signature = f.read()

    os.system("rm /tmp/data")
    os.system("rm /tmp/signature.bin")

    return signature

def decrypt_aes128_ctr_with_rsa(data, symetric_key, private_key: RSA.RsaKey):
    cipher = Cipher(algorithms.AES(symetric_key), modes.CTR(b'\x00' * 16), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data) + decryptor.finalize()
    return decrypted_data

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 22))

    sock.listen(1)

    print('Listening at', sock.getsockname())
    client, addr = sock.accept()
    print('Connection from', addr)

    # Send data to client
    server_banner = pyssh._core._packets._default_packets._get_pyssh_banner()
    client.send(server_banner)

    # Get data from client
    client_banner = client.recv(1024)
    client_banner = pyssh._core._conn_setup._protocol_version_exchange(client_banner)
    if not client_banner:
        print("Protocol version exchange failed.")

    server_kex_init = pyssh._core._packets._default_packets._get_key_exchange_init()
    server_kex_init = pyssh._core._core_classes._core_packet._create_packet(server_kex_init)
    client.send(bytes(server_kex_init))

    data = client.recv(4096)
    client_kex_init = pyssh._core._core_classes._core_packet(data)
    client_kex_init2 = pyssh._core._core_classes._core_packet(data)
    client_kex_init_2 = pyssh._core.Reader(client_kex_init2.payload)
    SSH_MSG_KEXINIT = client_kex_init_2.read_byte()
    assert SSH_MSG_KEXINIT == 20
    cookie = client_kex_init_2.read_bytes(16)
    kex_algorithms = client_kex_init_2.read_name_list()
    server_host_key_algorithms = client_kex_init_2.read_name_list()
    encryption_algorithms_client_to_server = client_kex_init_2.read_name_list()
    encryption_algorithms_server_to_client = client_kex_init_2.read_name_list()
    mac_algorithms_client_to_server = client_kex_init_2.read_name_list()
    mac_algorithms_server_to_client = client_kex_init_2.read_name_list()
    compression_algorithms_client_to_server = client_kex_init_2.read_name_list()
    compression_algorithms_server_to_client = client_kex_init_2.read_name_list()
    languages_client_to_server = client_kex_init_2.read_name_list()
    languages_server_to_client = client_kex_init_2.read_name_list()
    first_kex_packet_follows = client_kex_init_2.read_boolean()
    reserved = client_kex_init_2.read_uint32()

    for algorithm in kex_algorithms:
        if algorithm == b"diffie-hellman-group14-sha1":
            print("diffie-hellman-group14-sha1")
            kex_algorithm = kex.DHGroup14SHA1()
            break



    # Get DH_G14_SHA1 from client
    dh_g14_sha1 = pyssh._core._core_classes._core_packet(client.recv(4096))
    dh_g14_sha1 = pyssh._core.Reader(dh_g14_sha1.payload)
    SSH_MSG_KEXDH_INIT = dh_g14_sha1.read_byte()
    assert SSH_MSG_KEXDH_INIT == 30
    client_dh_e = dh_g14_sha1.read_mpint()



    kex_algorithm.generate_y()
    kex_algorithm.receive_e(client_dh_e)
    f = kex_algorithm.compute_f()
    k = kex_algorithm.compute_k()
    server_host_key = string("ssh-rsa") + mpint(public_key.e) + mpint(public_key.n)
    concat = \
        string(client_banner.rstrip(b'\r\n')) + \
        string(server_banner.rstrip(b'\r\n')) + \
        string(client_kex_init.payload) + \
        string(server_kex_init.payload) + \
        string(server_host_key) + \
        mpint(client_dh_e) + \
        mpint(f) + \
        mpint(k)
    
    H = kex_algorithm.generate_h(concat)
    sign = sign_with_key(H)
    signature = string("ssh-rsa") + string(sign)

    server_dh_response = Message()
    server_dh_response.write_byte(31) # SSH_MSG_KEXDH_REPLY
    server_dh_response.write_string(server_host_key)
    server_dh_response.write_mpint(f)
    server_dh_response.write_string(signature)    

    server_dh_response = pyssh._core._core_classes._core_packet._create_packet(server_dh_response.payload)
    client.send(bytes(server_dh_response))
    data = client.recv(4096)

    print()


if __name__ == '__main__':
    main()
