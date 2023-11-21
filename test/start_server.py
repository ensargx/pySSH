import socket
import pyssh
import base64

import hashlib
def sha1(data):
    return hashlib.sha1(data).digest()

import os
def sign_with_key(data):
    with open("/tmp/data", "wb") as f:
        f.write(data)

    os.system('ssh-keygen -Y sign -f /home/ensargok/keys/id_rsa -n file /tmp/data')

    with open("/tmp/data.sig", "rb") as f:
        data = f.read()

    os.system("rm /tmp/data")
    os.system("rm /tmp/data.sig")

    return data

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
    client_string = client.recv(1024)
    if not pyssh._core._conn_setup._protocol_version_exchange(client_string):
        print("Protocol version exchange failed.")

    server_kex_init = pyssh._core._packets._default_packets._get_key_exchange_init()
    server_kex_init = pyssh._core._core_classes._core_packet._create_packet(server_kex_init)
    client.send(bytes(server_kex_init))

    client_kex_init = pyssh._core._core_classes._core_packet(client.recv(4096))

    """
    This group is assigned id 14.

    This prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }

    Its hexadecimal value is:

        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
        C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
        83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
        E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
        DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
        15728E5A 8AACAA68 FFFFFFFF FFFFFFFF

    The generator is: 2.
    """
    dh_g14_sha1_prime = [
        "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1",
        "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD",
        "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245",
        "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED",
        "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D",
        "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F",
        "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D",
        "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B",
        "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9",
        "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510",
        "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"
    ]
    dh_g14_sha1_prime = "".join(dh_g14_sha1_prime)
    dh_g14_sha1_prime = int(dh_g14_sha1_prime.replace(" ", ""), 16)
    dh_g14_sha1_generator = 2


    # Get data from client
    dh_g14_sha1 = pyssh._core._core_classes._core_packet(client.recv(4096))
    massage_code = dh_g14_sha1.payload[0] # should be 30
    multi_precision_integer_len = int.from_bytes(dh_g14_sha1.payload[1:5], byteorder="big")
    ch_client_e = int.from_bytes(dh_g14_sha1.payload[5:5+multi_precision_integer_len], byteorder="big")

    print("massage_code:", massage_code)
    print("multi_precision_integer_len:", multi_precision_integer_len)
    print("ch_client_e:", ch_client_e)
    # e = g^x mod p.  C sends e to S.

    """
    S generates a random number y (0 < y < q) and computes
    f = g^y mod p.  S receives e.  It computes K = e^y mod p,
    H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
    (these elements are encoded according to their types; see below),
    and signature s on H with its private host key.  S sends
    (K_S || f || s) to C.  The signing operation may involve a
    second hashing operation.
    """
    y = 0x1234567890abcdef
    ch_server_f = pow(dh_g14_sha1_generator, y, dh_g14_sha1_prime)
    K = pow(ch_client_e, y, dh_g14_sha1_prime)
    I_C = bytes(dh_g14_sha1)
    I_S = bytes(server_kex_init)
    K_S = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDghTrs2T3N3vQfyUwAmAra+pj6+ZVvRkaFyc2XqeoAIfD597U8HMeICBREOaPlC+ezEGgbyp9N1adbYWiaAfxkAN23NlTqbxsKppeD7H1wdtBdKg/aOjwHP4F8C5ebZCKzDZys9QUTvFqv6cLrsZRuGGTGVtDqWtCS70Y4mCS2TZoi7n50IVBba+C/4mHUL0uStjTlkdnGj2WtZ11F0KmUhy1anzO+7V32ucesXWMdXc+HQPFhUi3DSEfsn21EWbtweTMMx/mN0UU/372ZupPYQK4N1WJgvkcO+9+uxQA1XRMyB6GGf0N4XbmURE/zC3nLI1anWNlBluZa6e0nccqK4dzEKFaPgqnlskZkOv+5q/fcap1q7z99cwTcq9Mslyj57qFfZS1OyUe8OPdv5o7C5lo1ZH66YZ09TbvY9++q4cK5+YsQQKoD8eh3F8NIlIl9AHhH9na7xUxolMxAvvV2M5XclxL1WZ7oWW/wOQ9Ybqyn+Z+lruk8s+FljZyEq/s="
    V_C = b"SSH-2.0-OpenSSH_for_Windows_8.1"
    V_S = b"SSH-2.0-pySSH_0.1"
    # servers public key = K_S

    len_e = ch_client_e.bit_length() // 8 + 1
    mpint_e = len_e.to_bytes(4, byteorder="big") + ch_client_e.to_bytes(len_e, byteorder="big")
    bytes_e = ch_client_e.to_bytes(len_e, byteorder="big")

    len_f = ch_server_f.bit_length() // 8 + 1
    mpint_f = len_f.to_bytes(4, byteorder="big") + ch_server_f.to_bytes(len_f, byteorder="big")
    bytes_f = ch_server_f.to_bytes(len_f, byteorder="big")

    len_k = K.bit_length() // 8 + 1
    byte_k = K.to_bytes(len_k, byteorder="big")

    # H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
    H = sha1(V_C + V_S + I_C + I_S + K_S + bytes_e + bytes_f + byte_k)

    # s = sign(H)
    # sign = pyssh._core._crypto._signing._signing()
    s = sign_with_key(H)

    len_ks = len(K_S).to_bytes(4, byteorder="big")

    id_rsa_pub_b64 = "AAAAB3NzaC1yc2EAAAADAQABAAABgQDghTrs2T3N3vQfyUwAmAra+pj6+ZVvRkaFyc2XqeoAIfD597U8HMeICBREOaPlC+ezEGgbyp9N1adbYWiaAfxkAN23NlTqbxsKppeD7H1wdtBdKg/aOjwHP4F8C5ebZCKzDZys9QUTvFqv6cLrsZRuGGTGVtDqWtCS70Y4mCS2TZoi7n50IVBba+C/4mHUL0uStjTlkdnGj2WtZ11F0KmUhy1anzO+7V32ucesXWMdXc+HQPFhUi3DSEfsn21EWbtweTMMx/mN0UU/372ZupPYQK4N1WJgvkcO+9+uxQA1XRMyB6GGf0N4XbmURE/zC3nLI1anWNlBluZa6e0nccqK4dzEKFaPgqnlskZkOv+5q/fcap1q7z99cwTcq9Mslyj57qFfZS1OyUe8OPdv5o7C5lo1ZH66YZ09TbvY9++q4cK5+YsQQKoD8eh3F8NIlIl9AHhH9na7xUxolMxAvvV2M5XclxL1WZ7oWW/wOQ9Ybqyn+Z+lruk8s+FljZyEq/s="
    id_rsa_byte = base64.b64decode(id_rsa_pub_b64)
    id_rsa_len = len(id_rsa_byte).to_bytes(4, byteorder="big")
    
    payload = b"\x1F" + id_rsa_len + id_rsa_byte + mpint_f

    signature = sign_with_key(H) 
    len_s = len(signature).to_bytes(4, byteorder="big")
    payload += len_s + signature

    payload = pyssh._core._core_classes._core_packet._create_packet(payload)
    client.send(bytes(payload))

    print()


if __name__ == '__main__':
    main()