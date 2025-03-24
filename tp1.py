import socket
import sys
import struct

# SERVER: pugna.snes.dcc.ufmg.br (150.164.213.243, 2804:1f4a:dcc:ff03::1)
# port: 51001


def getUDPSocket(server_address, port):
    addrinfo = socket.getaddrinfo(server_address, None)
    family = addrinfo[0][0]

    client_socket = socket.socket(family, socket.SOCK_DGRAM)

    client_socket.connect((server_address, port))

    return client_socket


def packedToFormattedSAS(packed_sas):
    _, id, nonce, token = struct.unpack("!H12sI64s", packed_sas)
    return f"{id.decode("ascii")}:{nonce}:{token.decode("ascii")}"


def formattedToPackedSAS(code, formatted_sas):
    id, nonce, token = formatted_sas.split(":")
    return struct.pack(
        "!H12sI64s",
        int(code),
        bytes(id.ljust(12), encoding="ascii"),
        int(nonce),
        bytes(token, encoding="ascii"),
    )


def getITStatusFromResponse(packed_response):
    unpacked = struct.unpack("!H12sI64ss", packed_response)
    print(unpacked, unpacked[-1], unpacked[-1].decode())
    return unpacked[-1].decode()


if len(sys.argv) < 4:
    print("Usage: python tp1.py <server_address> <port> <command>")
    sys.exit(1)

server_address = sys.argv[1]
port = int(sys.argv[2])

command = sys.argv[3]

command_args = sys.argv[4:]

if command == "itr":
    if len(command_args) != 2:
        print("Usage: itr <id> <nonce>")
        sys.exit(1)

    user_id = command_args[0]
    user_nonce = command_args[1]

    client_socket = getUDPSocket(server_address, port)

    # !H12sI:
    # ! -> network byte order
    # H -> unsigned short (2 bytes)
    # 12s -> 12 bytes string
    # I -> unsigned int (4 bytes)
    message = struct.pack(
        "!H12sI", 1, bytes(user_id.ljust(12), encoding="ascii"), int(user_nonce)
    )

    client_socket.send(message)

    response = client_socket.recv(82)

    print(packedToFormattedSAS(response))

    client_socket.close()
    pass
elif command == "itv":
    if len(command_args) != 1:
        print("Usage: itv <SAS>")
        sys.exit(1)

    sas = command_args[0]

    client_socket = getUDPSocket(server_address, port)

    # 3 -> code for Individual Token Validation
    message = formattedToPackedSAS(3, sas)

    client_socket.send(message)

    response = client_socket.recv(83)

    print(getITStatusFromResponse(response))

    client_socket.close()
    pass
elif command == "gtr":
    # TODO: gtr <N> <SAS-1> <SAS-2> ... <SAS-N>
    pass
elif command == "gtv":
    # TODO: gtv <GAS>
    pass
else:
    print("Invalid command")
    sys.exit(1)
