import socket
import struct
import argparse


class IndividualTokenRequest:
    def __init__(self, id: str, nonce: int):
        self.type: int = 1
        self.id: str = id
        self.nonce: int = nonce


class IndividualTokenResponse:
    def __init__(self, type: int, id: str, nonce: int, token: str):
        self.type: int = type
        self.id: str = id
        self.nonce: int = nonce
        self.token: str = token

    def getStringSAS(self) -> str:
        return f"{self.id}:{self.nonce}:{self.token}"


class IndividualTokenValidation:
    def __init__(self, id: str, nonce: int, token: str):
        self.type: int = 3
        self.id: str = id
        self.nonce: int = nonce
        self.token: str = token


class IndividualTokenStatus:
    def __init__(self, type: int, id: str, nonce: int, token: str, status: int):
        self.type: int = type
        self.id: str = id
        self.nonce: int = nonce
        self.token: str = token
        self.status: int = status


class GroupTokenRequest:
    def __init__(self, n: int, group: list[tuple[str, int, str]]):
        self.type: int = 5
        self.n: int = n
        self.group: list[tuple[str, int, str]] = group


class GroupTokenResponse:
    def __init__(
        self, type: int, n: int, group: list[tuple[str, int, str]], token: str
    ):
        self.type: int = type
        self.n: int = n
        self.group: list[tuple[str, int, str]] = group
        self.token: str = token

    def getStringGAS(self) -> str:
        return f"{'+'.join([f'{sas[0]}:{sas[1]}:{sas[2]}' for sas in self.group])}+{self.token}"


class GroupTokenValidation:
    def __init__(self, n: int, group: list[tuple[str, int, str]], token: str):
        self.type: int = 7
        self.n: int = n
        self.group: list[tuple[str, int, str]] = group
        self.token: str = token


class GroupTokenStatus:
    def __init__(
        self,
        type: int,
        n: int,
        group: list[tuple[str, int, str]],
        token: str,
        status: int,
    ):
        self.type: int = type
        self.n: int = n
        self.group: list[tuple[str, int, str]] = group
        self.token: str = token
        self.status: int = status


def initParser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Basic UDP Authentication Token Generator used in the Computer Networks course at UFMG."
    )

    parser.add_argument(
        "host",
        metavar="host",
        type=str,
        help="Authentication server host, as an IPv4/IPv6 address or as a hostname",
    )

    parser.add_argument(
        "port",
        metavar="port",
        type=int,
        help="Authentication server port",
    )

    parser.add_argument(
        "command",
        metavar="command",
        type=str,
        choices=["itr", "itv", "gtr", "gtv"],
        help="Command to be executed. Available options: itr, itv, gtr, gtv",
    )

    parser.add_argument(
        "options",
        metavar="options",
        type=str,
        nargs="+",
        help="Options for the selected command",
    )

    return parser


def validateArgs(args: argparse.Namespace) -> None:
    match args.command:
        case "itr":
            if len(args.options) != 2:
                raise Exception("Expected usage: itr <id> <nonce>")
        case "itv":
            if len(args.options) != 1:
                raise Exception("Expected usage: itv <SAS>")
        case "gtr":
            if len(args.options) == 1:
                raise Exception("Expected usage: gtr <N> <SAS-1> <SAS-2> ... <SAS-N>")
        case "gtv":
            if len(args.options) != 1:
                raise Exception("Expected usage: gtv <GAS>")


def getServerErrorMsg(code: int) -> str:
    authServerErrorMsg: list[str] = [
        "INVALID_MESSAGE_CODE",
        "INCORRECT_MESSAGE_LENGTH",
        "INVALID_PARAMETER",
        "INVALID_SINGLE_TOKEN",
        "ASCII_DECODE_ERROR",
    ]

    if code > len(authServerErrorMsg) or code < 1:
        return "UNKNOWN_ERROR_CODE"

    return authServerErrorMsg[code - 1]


# Adapted from: https://docs.python.org/3/library/socket.html#creating-sockets
def initConnection(host: str, port: int) -> socket.socket:
    sock: socket.socket = None

    # This will resolve any hostname, and check for IPv4 and IPv6 addresses
    # The first socket to get a successful connection is returned
    # Note: using SOCK_DGRAM for UDP

    for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM):
        af, socktype, proto, canonname, sa = res

        try:
            sock = socket.socket(af, socktype, proto)
        except OSError as msg:
            print(f"WARNING: Attempt at creating socket failed. {msg}")

            sock = None
            continue
        try:
            sock.connect(sa)
        except OSError as msg:
            print(f"WARNING: Attempt at connecting socket to {sa} failed. {msg}")

            sock.close()
            sock = None
            continue
        break

    if sock is None:
        print("ERROR: Could not open a valid socket")
        exit(1)

    return sock


def sendPayload(
    sock: socket.socket,
    payload: bytes,
    bufSize: int = 4096,
    timeoutSec: float = 6.0,
    attempts: int = 5,
) -> bytes:
    res: bytes = bytes()

    sock.settimeout(timeoutSec)

    while attempts:
        try:
            sock.send(payload)
            res = sock.recv(bufSize)
            break
        except socket.timeout:
            attempts -= 1
        except OSError as msg:
            print(f"ERROR: Could not send and/or receive data. {msg}")
            exit(2)

    if len(res) == 0:
        print("ERROR: No response from the server")
        exit(3)

    # Check for server errors
    if len(res) == 4:
        type, code = struct.unpack("!hh", res)

        if type == 256:
            print(
                f"ERROR: Auth server returned an error. [{code}] {getServerErrorMsg(code)}"
            )
            exit(4)

    return res


def sendIndividualTokenRequest(
    sock: socket.socket, itr: IndividualTokenRequest
) -> IndividualTokenResponse:
    # Prepare data
    # h   -> 2 byte type integer
    # 12s -> 12 byte no-align ID ASCII
    # i   -> 4 byte nonce integer
    payload: bytes = struct.pack(
        "!h12si",
        itr.type,
        bytes(itr.id.ljust(12), encoding="ascii"),
        itr.nonce
    )

    # Send
    res: bytes = sendPayload(sock, payload)

    # No errors, return parsed result
    raw: tuple[int, bytes, int, bytes] = struct.unpack("!h12si64s", res)

    return IndividualTokenResponse(
        raw[0], raw[1].decode("ascii").strip(), raw[2], raw[3].decode("ascii")
    )


def sendIndividualTokenValidation(
    sock: socket.socket, itv: IndividualTokenValidation
) -> IndividualTokenStatus:
    # Prepare data
    # h   -> 2 byte type integer
    # 12s -> 12 byte ID ASCII
    # i   -> 4 byte nonce integer
    # 64s -> 12 byte token ASCII
    # b   -> 1 byte status
    payload: bytes = struct.pack(
        "!h12si64s",
        itv.type,
        bytes(itv.id.ljust(12), encoding="ascii"),
        itv.nonce,
        bytes(itv.token, encoding="ascii"),
    )

    # Send
    res: bytes = sendPayload(sock, payload)

    # No errors, return parsed result
    raw: tuple[int, bytes, int, bytes, int] = struct.unpack("!h12si64sb", res)

    return IndividualTokenStatus(
        raw[0], raw[1].decode("ascii").strip(), raw[2], raw[3].decode("ascii"), raw[4]
    )


def sendGroupTokenRequest(
    sock: socket.socket, gtr: GroupTokenRequest
) -> GroupTokenResponse:
    # Prepare data
    # h   -> 2 byte type integer
    # h   -> 2 byte n integer
    # 80*ns -> 80*n byte sas

    # Build SASes chunk
    sasChunk: bytes = bytes()

    for sas in gtr.group:
        sasChunk += struct.pack(
            "!12si64s",
            bytes(sas[0].ljust(12), encoding="ascii"),
            sas[1],
            bytes(sas[2], encoding="ascii"),
        )

    payload: bytes = struct.pack(f"!hh{80*gtr.n}s", gtr.type, gtr.n, sasChunk)

    # Send
    res: bytes = sendPayload(sock, payload)

    # No errors, return parsed result
    raw: tuple[int, int, bytes, bytes] = struct.unpack(f"!hh{80*gtr.n}s64s", res)

    group: list[tuple[str, int, str]] = list()

    # Extract and parse each SAS individually (one SAS every 80 bytes)
    for sas in [raw[2][80 * i : 80 * (i + 1)] for i in range(gtr.n)]:
        rawSas: tuple[bytes, int, bytes] = struct.unpack("!12si64s", sas)

        group.append(
            (rawSas[0].decode("ascii").strip(), rawSas[1], rawSas[2].decode("ascii"))
        )

    return GroupTokenResponse(raw[0], raw[1], group, raw[3].decode("ascii"))


def sendGroupTokenValidation(
    sock: socket.socket, gtv: GroupTokenValidation
) -> GroupTokenStatus:
    # Prepare data
    # h   -> 2 byte type integer
    # h   -> 2 byte n integer
    # 80*ns -> 80*n byte sas
    # b   -> 1 byte status

    # Build SASes chunk
    sasChunk: bytes = bytes()

    for sas in gtv.group:
        sasChunk += struct.pack(
            "!12si64s",
            bytes(sas[0].ljust(12), encoding="ascii"),
            sas[1],
            bytes(sas[2], encoding="ascii"),
        )

    payload: bytes = struct.pack(
        f"!hh{80*gtv.n}s64s",
        gtv.type,
        gtv.n,
        sasChunk,
        bytes(gtv.token, encoding="ascii"),
    )

    # Send
    res: bytes = sendPayload(sock, payload)

    # No errors, return parsed result
    raw: tuple[int, int, bytes, bytes, int] = struct.unpack(f"!hh{80*gtv.n}s64sb", res)

    group: list[tuple[str, int, str]] = list()

    # Extract and parse each SAS individually (one SAS every 80 bytes)
    for sas in [raw[2][80 * i : 80 * (i + 1)] for i in range(gtv.n)]:
        rawSas: tuple[bytes, int, bytes] = struct.unpack("!12si64s", sas)

        group.append(
            (rawSas[0].decode("ascii").strip(), rawSas[1], rawSas[2].decode("ascii"))
        )

    return GroupTokenStatus(raw[0], raw[1], group, raw[3].decode("ascii"), raw[4])


if __name__ == "__main__":
    # Get args
    parser = initParser()
    args = parser.parse_args()
    validateArgs(args)

    # Connect
    sock: socket.socket = initConnection(args.host, args.port)

    # Perform command
    match args.command:
        case "itr":
            itres = sendIndividualTokenRequest(
                sock, IndividualTokenRequest(args.options[0], int(args.options[1]))
            )

            print(itres.getStringSAS())
        case "itv":
            data: list[str] = args.options[0].split(":")

            its = sendIndividualTokenValidation(
                sock, IndividualTokenValidation(data[0], int(data[1]), data[2])
            )

            print(its.status)
        case "gtr":
            n: int = int(args.options[0])

            group: list[tuple[str, int, str]] = list()

            for sas in args.options[1:]:
                data: list[str] = sas.split(":")
                group.append((data[0], int(data[1]), data[2]))

            gtres = sendGroupTokenRequest(sock, GroupTokenRequest(n, group))

            print(gtres.getStringGAS())
        case "gtv":
            input: list[str] = args.options[0].split("+")

            group: list[tuple[str, int, str]] = list()

            for sas in input[:-1]:
                data: list[str] = sas.split(":")
                group.append((data[0], int(data[1]), data[2]))

            gts = sendGroupTokenValidation(
                sock, GroupTokenValidation(len(group), group, input[-1])
            )

            print(gts.status)

    # Clean up
    sock.close()
