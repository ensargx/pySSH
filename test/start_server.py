import socket
import pyssh

import hashlib
def sha1(data):
    return hashlib.sha1(data).digest()

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
    V_C = b"SSH-2.0-OpenSSH_for_Windows_8.1"
    V_S = b"SSH-2.0-pySSH_0.1"
    # servers public key = K_S
    public_key = b"2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b434151454174587559545744503575514d43526c54745441730a6b4d6a77766c56694a586a45786a373376626a6b30454f586351704964482f79494b616253464a552f46434c4970444d4d4d547644414c4d6a7a485566564c370a30494b79362f453450327478707435516f6c46766d2f5a50726a4d627a764a70506e6c3654757a306c496d556e684742576e365876554870736d4c6e2f392f550a7454546b78467a4f574d6a4d4d33434577585248386d6862636152572b716b6b4d52555241616f76755557714747376c654c323175586468746d54744b4844670a76437464374d6e3338636c572b65343250666f32736b457173376451694963367769364b6a50524d4a362f6b2f52576b737065346c514e4939714a6d763550560a6e45726943504c4d2f61734877397654773243556c78746c67593764344d382b4c744b30627a6846616c2f4834314d576834516e49725942486c4e77474d6c640a63514944415141420a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a"
    certificate = b"2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d494944745443434170304346415453515247644a315a4e66476c7255546d4d68585669755648334d413047435371475349623344514542437755414d4947570a4d517377435159445651514745774a55556a45554d424947413155454341774c7734544373484e3059573569645777784644415342674e564241634d43384f450a7772427a64474675596e56734d524577447759445651514b44416846626e4e68636b6476617a45524d41384741315545437777495257357a59584a48623273780a4554415042674e5642414d4d4345567563324679523239724d5349774941594a4b6f5a496876634e41516b4246684e6c626e4e68636e686e623274415a3231680a61577775593239744d4234584454497a4d5445784e7a457a4e446b794e316f58445449304d5445784e6a457a4e446b794e316f77675a5978437a414a42674e560a42415954416c52534d525177456759445651514944417644684d4b7763335268626d4a31624445554d424947413155454277774c7734544373484e30595735690a645777784554415042674e5642416f4d4345567563324679523239724d524577447759445651514c44416846626e4e68636b6476617a45524d413847413155450a417777495257357a59584a4862327378496a416742676b71686b694739773042435145574532567563324679654764766130426e625746706243356a623230770a676745694d4130474353714753496233445145424151554141344942447741776767454b416f4942415143316535684e594d2f6d3541774a47564f314d4379510a7950432b5657496c654d544750766539754f545151356478436b6830662f496770707449556c5438554973696b4d7777784f384d417379504d645239557676510a67724c723854672f6133476d336c436955572b62396b2b754d78764f386d6b2b6558704f37505355695a5365455946616670653951656d795975662f333953310a4e4f5445584d3559794d777a63495442644566796146747870466236715351784652454271692b3552616f596275563476625735643247325a4f306f634f43380a4b3133737966667879566235376a59392b6a61795153717a74314349687a72434c6f714d3945776e722b5439466153796c37695641306a326f6d612f6b3957630a5375494938737a397177664432395044594a5358473257426a7433677a7a3475307252764f4556715838666a55786148684363697467456555334159795631780a41674d42414145774451594a4b6f5a496876634e4151454c425141446767454241466e394b794278345579572f65415a4b3159575663423774397a4f456231590a4b544634444f695a754b7a5846524f5136374f6d72674d5150307178476b7971475a7847446b796a537a4a44506859774a41476553563063457a50765550712f0a744a43587832733236652b55696b7536575357627274362f33305a7352545447727830324f4a4d444c594a567056446e41456b6351614c6f2f63692f536b73780a656c55746547724f526169784c45543961414356314636766b44386434376b7a5a547461715a762b4c41552f416c7246594a5365514a56566d746b4b4b2b31510a4b552f4b42414e4e4a48472b353252413759345656556241652b686777584c6561627a526650305a72514436716c4e3572714478784b33366c7179694d4b2b310a2f6b7464654b57686d727863667259706a312f7a786c51484f6c534f4f676b676f2b2f545456545136756665314b426c68417a674146773d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a"
    K_S = public_key

    len_e = ch_client_e.bit_length() // 8 + 1
    mpint_e = len_e.to_bytes(4, byteorder="big") + ch_client_e.to_bytes(len_e, byteorder="big")

    len_f = ch_server_f.bit_length() // 8 + 1
    mpint_f = len_f.to_bytes(4, byteorder="big") + ch_server_f.to_bytes(len_f, byteorder="big")

    len_k = K.bit_length() // 8 + 1
    byte_k = K.to_bytes(len_k, byteorder="big")
    H = sha1(V_C + V_S + client_kex_init.payload + server_kex_init.payload + K_S + mpint_e + mpint_f + byte_k)

    payload = b"\x1E"
    payload += public_key + certificate
    # len_f = len(ch_server_f).to_bytes(4, byteorder="big")
    len_f = ch_server_f.bit_length() // 8 + 1
    bytes_f = ch_server_f.to_bytes(len_f, byteorder="big")

    payload += len_f.to_bytes(4, byteorder="big") + bytes_f
    payload += H

    packet = pyssh._core._core_classes._core_packet._create_packet(payload)
    client.send(bytes(packet))

    print()


if __name__ == '__main__':
    main()