import socket
import sys
import struct
from enum import Enum

# SERVER: pugna.snes.dcc.ufmg.br (150.164.213.243, 2804:1f4a:dcc:ff03::1)
# port: 51001
#
# Usage:
# python3 tp1.py <address> <port> <command> <args>
#
# Commands:
# itr <id> <nonce> (returns <SAS>)
# itv <SAS> (returns <status>, 0 for valid, != 0 for invalid)
# gtr <N> <SAS-1> <SAS-2> ... <SAS-N> (returns <GAS>)
# gtv <GAS> (returns <status>, 0 for valid, != 0 for invalid)

MAX_RETRIES = 3
TIMEOUT_SECONDS = 5


class RequestCode(Enum):
    INDIVIDUAL_TOKEN_REQUEST = 1
    INDIVIDUAL_TOKEN_VALIDATION = 3
    GROUP_TOKEN_REQUEST = 5
    GROUP_TOKEN_VALIDATION = 7


class ResponseCode(Enum):
    INDIVIDUAL_TOKEN_RESPONSE = 2
    INDIVIDUAL_TOKEN_STATUS = 4
    GROUP_TOKEN_RESPONSE = 6
    GROUP_TOKEN_STATUS = 8


class ErrorCode(Enum):
    INVALID_MESSAGE_CODE = 1
    INCORRECT_MESSAGE_LENGTH = 2
    INVALID_PARAMETER = 3
    INVALID_SINGLE_TOKEN = 4
    ASCII_DECODE_ERROR = 5


class ExpectedResponseSize(Enum):
    INDIVIDUAL_TOKEN_RESPONSE = 82
    INDIVIDUAL_TOKEN_STATUS = 83
    GROUP_TOKEN_RESPONSE = lambda sas_amount: 4 + 80 * sas_amount + 64
    GROUP_TOKEN_STATUS = lambda n: 69 + 80 * n


CODE_ID_NONCE_STRUCT_FORMAT = "!H12sI"
SAS_STRUCT_FORMAT = "!12sI64s"
CODE_STRUCT_FORMAT = "!H"
N_STRUCT_FORMAT = "!H"
CODE_N_STRUCT_FORMAT = "!HH"
TOKEN_STRUCT_FORMAT = "!64s"


def create_socket(server_address, port):
    addrinfo = socket.getaddrinfo(server_address, None)
    family = addrinfo[0][0]
    client_socket = socket.socket(family, socket.SOCK_DGRAM)
    client_socket.settimeout(TIMEOUT_SECONDS)
    client_socket.connect((server_address, port))
    return client_socket


def send_with_retry(client_socket, message, expected_response_size):
    for attempt in range(MAX_RETRIES):
        try:
            client_socket.send(message)
            response = client_socket.recv(expected_response_size)
            return response
        except socket.timeout:
            print(f"Timed out. Attempt {attempt + 1} of {MAX_RETRIES}")
    raise TimeoutError("Limit of retries reached.")


def verify_response_code(response, expected_code):
    if len(response) < 2:
        raise RuntimeError("Invalid response")
    unpacked = struct.unpack(CODE_STRUCT_FORMAT, response[:2])
    if unpacked[0] != expected_code:
        print(unpacked[0], expected_code)
        if unpacked[0] == 256:
            raise_error_message(unpacked[0])
            return
        raise RuntimeError("Invalid response code")


def raise_error_message(error_code):
    if error_code in ErrorCode.__members__:
        error_message = ErrorCode(error_code).name
        raise RuntimeError(f"Server error: {error_message}")
    else:
        raise RuntimeError("Invalid error code")


def packedToFormattedSAS(packed_sas, code_included=True):
    id, nonce, token = struct.unpack(
        SAS_STRUCT_FORMAT, packed_sas[2:] if code_included else packed_sas
    )
    return f"{id.decode("ascii").strip()}:{nonce}:{token.decode("ascii")}"


def packedToFormattedGAS(packed_gas):
    code, n = struct.unpack(CODE_N_STRUCT_FORMAT, packed_gas[:4])
    if code != 6:
        raise "Invalid code for Group Token Response"

    formatted_sas_list = []

    for i in range(n):
        formatted_sas_list.append(
            packedToFormattedSAS(packed_gas[4 + i * 80 : 4 + (i + 1) * 80], False)
        )

    token = struct.unpack(TOKEN_STRUCT_FORMAT, packed_gas[4 + n * 80 :])[0].decode(
        "ascii"
    )

    return f"{'+'.join(formatted_sas_list)}+{token}"


def formattedToPackedSAS(id, nonce, token):
    return struct.pack(
        SAS_STRUCT_FORMAT,
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
        struct.pack(N_STRUCT_FORMAT, int(n))
        + packed_sas_list_bytes
        + struct.pack(TOKEN_STRUCT_FORMAT, bytes(token, encoding="ascii"))
    )


def packItrStruct(user_id, user_nonce):
    return struct.pack(
        CODE_ID_NONCE_STRUCT_FORMAT,
        RequestCode.INDIVIDUAL_TOKEN_REQUEST.value,
        bytes(user_id.ljust(12), encoding="ascii"),
        int(user_nonce),
    )


def packItvStruct(formatted_sas):
    id, nonce, token = formatted_sas.split(":")
    return struct.pack(
        CODE_STRUCT_FORMAT,
        RequestCode.INDIVIDUAL_TOKEN_VALIDATION.value,
    ) + formattedToPackedSAS(id, nonce, token)


def packGtrStruct(n, formatted_sas_list):
    packedBytes = struct.pack(
        CODE_N_STRUCT_FORMAT, RequestCode.GROUP_TOKEN_REQUEST.value, int(n)
    )
    for formatted_sas in formatted_sas_list:
        id, nonce, token = formatted_sas.split(":")
        packedBytes += formattedToPackedSAS(id, nonce, token)

    return packedBytes


def packGtvStruct(formatted_gas):
    return struct.pack(
        CODE_STRUCT_FORMAT, RequestCode.GROUP_TOKEN_VALIDATION.value
    ) + formattedToPackedGAS(formatted_gas)


def getITStatusFromResponse(packed_response):
    # TODO: check if the response ID is valid (receive it as a parameter and compare)
    return packed_response[-1]


def getGTStatusFromResponse(packed_response):
    # TODO: check if the response ID is valid (receive it as a parameter and compare)
    return packed_response[-1]


def handleCommandResponse(
    client_socket, message, expected_response_size, expected_code, format_response_func
):
    try:
        response = send_with_retry(client_socket, message, expected_response_size)
        verify_response_code(response, expected_code)
        print(format_response_func(response))
    except RuntimeError as e:
        print(e)
        sys.exit(1)
    finally:
        client_socket.close()


def handleItrCommand(server_address, port, command_args):
    if len(command_args) != 2:
        print("Usage: itr <id> <nonce>")
        sys.exit(1)

    user_id = command_args[0]
    user_nonce = command_args[1]

    client_socket = create_socket(server_address, port)

    message = packItrStruct(
        user_id,
        user_nonce,
    )

    handleCommandResponse(
        client_socket,
        message,
        ExpectedResponseSize.INDIVIDUAL_TOKEN_RESPONSE.value,
        ResponseCode.INDIVIDUAL_TOKEN_RESPONSE.value,
        packedToFormattedSAS,
    )


def handleItvCommand(server_address, port, command_args):
    if len(command_args) != 1:
        print("Usage: itv <SAS>")
        sys.exit(1)

    sas = command_args[0]

    client_socket = create_socket(server_address, port)

    message = packItvStruct(sas)

    handleCommandResponse(
        client_socket,
        message,
        ExpectedResponseSize.INDIVIDUAL_TOKEN_STATUS.value,
        ResponseCode.INDIVIDUAL_TOKEN_STATUS.value,
        getITStatusFromResponse,
    )


def handleGtrCommand(server_address, port, command_args):
    if len(command_args) < 2:
        print("Usage: gtr <N> <SAS-1> <SAS-2> ... <SAS-N>")
        sys.exit(1)

    sas_amount = int(command_args[0])
    sas_list = command_args[1:]

    client_socket = create_socket(server_address, port)

    message = packGtrStruct(sas_amount, sas_list)

    handleCommandResponse(
        client_socket,
        message,
        ExpectedResponseSize.GROUP_TOKEN_RESPONSE(sas_amount),
        ResponseCode.GROUP_TOKEN_RESPONSE.value,
        packedToFormattedGAS,
    )


def handleGtvCommand(server_address, port, command_args):
    if len(command_args) != 1:
        print("Usage: gtv <GAS>")
        sys.exit(1)

    gas = command_args[0]

    client_socket = create_socket(server_address, port)

    message = packGtvStruct(gas)

    n = getNFromFormattedGas(gas)

    handleCommandResponse(
        client_socket,
        message,
        ExpectedResponseSize.GROUP_TOKEN_STATUS(n),
        ResponseCode.GROUP_TOKEN_STATUS.value,
        getGTStatusFromResponse,
    )


def main():
    if len(sys.argv) < 4:
        print("Usage: python tp1.py <server_address> <port> <command>")
        sys.exit(1)

    server_address = sys.argv[1]
    port = int(sys.argv[2])

    command = sys.argv[3]

    command_args = sys.argv[4:]

    if command == "itr":
        handleItrCommand(server_address, port, command_args)
    elif command == "itv":
        handleItvCommand(server_address, port, command_args)
    elif command == "gtr":
        handleGtrCommand(server_address, port, command_args)
    elif command == "gtv":
        handleGtvCommand(server_address, port, command_args)
    else:
        print("Invalid command")
        sys.exit(1)


main()
