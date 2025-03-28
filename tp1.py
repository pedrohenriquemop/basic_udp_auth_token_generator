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


def packedToFormattedSAS(packed_sas, code_included=True):
    id, nonce, token = struct.unpack(
        "!12sI64s", packed_sas[2:] if code_included else packed_sas
    )
    return f"{id.decode("ascii").strip()}:{nonce}:{token.decode("ascii")}"


def packedToFormattedGAS(packed_gas):
    code, n = struct.unpack("!HH", packed_gas[:4])
    if code != 6:
        raise "Invalid code for Group Token Response"

    formatted_sas_list = []

    for i in range(n):
        formatted_sas_list.append(
            packedToFormattedSAS(packed_gas[4 + i * 80 : 4 + (i + 1) * 80], False)
        )

    token = struct.unpack("!64s", packed_gas[4 + n * 80 :])[0].decode("ascii")

    return f"{'+'.join(formatted_sas_list)}+{token}"


def formattedToPackedSAS(id, nonce, token):
    return struct.pack(
        "!12sI64s",
        bytes(id.ljust(12), encoding="ascii"),
        int(nonce),
        bytes(token, encoding="ascii"),
    )


def getNFromFormattedGas(formatted_gas):
    return len(formatted_gas.split("+")) - 1


def formattedToPackedGAS(formatted_gas):
    n = getNFromFormattedGas(formatted_gas)
    *formatted_sas_list, token = formatted_gas.split("+")

    packed_sas_list_bytes = b""
    for formatted_sas in formatted_sas_list:
        packed_sas_list_bytes += formattedToPackedSAS(*formatted_sas.split(":"))

    return (
        struct.pack("!H", int(n))
        + packed_sas_list_bytes
        + struct.pack("64s", bytes(token, encoding="ascii"))
    )


def packItvStruct(code, formatted_sas):
    id, nonce, token = formatted_sas.split(":")
    return struct.pack(
        "!H",
        int(code),
    ) + formattedToPackedSAS(id, nonce, token)


def packGtrStruct(code, n, formatted_sas_list):
    packedBytes = struct.pack("!HH", int(code), int(n))
    for formatted_sas in formatted_sas_list:
        id, nonce, token = formatted_sas.split(":")
        packedBytes += formattedToPackedSAS(id, nonce, token)

    return packedBytes


def packGtvStruct(code, formatted_gas):
    return struct.pack("!H", int(code)) + formattedToPackedGAS(formatted_gas)


def getITStatusFromResponse(packed_response):
    # TODO: check if the response ID is valid (receive it as a parameter and compare)
    unpacked = struct.unpack("!H12sI64sB", packed_response)
    return unpacked[-1]


def getGTStatusFromResponse(packed_response):
    # TODO: check if the response ID is valid (receive it as a parameter and compare)
    return packed_response[-1]


def main():
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
    elif command == "itv":
        if len(command_args) != 1:
            print("Usage: itv <SAS>")
            sys.exit(1)

        sas = command_args[0]

        client_socket = getUDPSocket(server_address, port)

        # 3 -> code for Individual Token Validation
        message = packItvStruct(3, sas)

        client_socket.send(message)

        response = client_socket.recv(83)

        print(getITStatusFromResponse(response))

        client_socket.close()
    elif command == "gtr":
        if len(command_args) < 2:
            print("Usage: gtr <N> <SAS-1> <SAS-2> ... <SAS-N>")
            sys.exit(1)

        sas_amount = int(command_args[0])
        sas_list = command_args[1:]

        client_socket = getUDPSocket(server_address, port)

        # 5 -> code for Group Token Request
        message = packGtrStruct(5, sas_amount, sas_list)

        client_socket.send(message)

        response = client_socket.recv(4 + 80 * sas_amount + 64)

        print(packedToFormattedGAS(response))

        client_socket.close()
    elif command == "gtv":
        if len(command_args) != 1:
            print("Usage: gtv <GAS>")
            sys.exit(1)

        gas = command_args[0]

        client_socket = getUDPSocket(server_address, port)

        # 7 -> code for Group Token Validation
        message = packGtvStruct(7, gas)

        client_socket.send(message)

        n = getNFromFormattedGas(gas)

        response = client_socket.recv(69 + 80 * n)

        print(getGTStatusFromResponse(response))

        client_socket.close()
    else:
        print("Invalid command")
        sys.exit(1)


main()
