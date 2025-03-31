import array
import logging
import socket
import uuid
from threading import get_ident
from enum import IntEnum, StrEnum
import pydantic
import struct
from itertools import cycle, count
import base64

MSGLEN = 32_768
TIMEOUT_SEC = 20

RCON_PROTOCOL_VERSION = 2
RESPONSE_HEADER_SIZE = 8
HEADER_BIT_FORMAT = "<II"


logger = logging.getLogger(__name__)


# Similar to but distinct from HTTP status codes
class RconResponseStatusCode(IntEnum):
    """The game server status codes for requests"""

    OK = 200
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    SERVER_ERROR = 500


class HLLAuthError(Exception):
    pass


class ServerInformationCommands(StrEnum):
    """Valid content body names for the ServerInformation command"""

    PLAYERS = "players"
    SESSION = "session"
    SERVER_CONFIG = "server_config"
    MAP_ROTATION = "map_rotation"


class ContentBody(pydantic.BaseModel):
    """Models the `ContentBody` field on a request to the game server

    Some commands such as `ServerInformation` require a JSON object payload
    to determine which specific command to run (i.e. query players,
    serverconfig (v1 gamestate), etc.)

    In all cases this object is serialized to a JSON string regardless of
    the specific command format
    """

    name: ServerInformationCommands = pydantic.Field(serialization_alias="Name")
    value: str | None = pydantic.Field(default=None, serialization_alias="Value")


class RconRequest(pydantic.BaseModel):
    """The format the game server expects for a RCON request"""

    auth: str = pydantic.Field(serialization_alias="AuthToken")
    version: int = pydantic.Field(
        default=RCON_PROTOCOL_VERSION, serialization_alias="Version"
    )
    command: str = pydantic.Field(serialization_alias="Name")
    body: ContentBody | str | None = pydantic.Field(serialization_alias="ContentBody")

    class Config:
        populate_by_name = True

    @pydantic.field_serializer("body")
    def serialize_body(self, body: ContentBody | str | None):
        """The server always expects a string for the content body"""
        if body is None:
            return ""
        elif isinstance(body, ContentBody):
            return body.model_dump_json()
        elif isinstance(body, str):
            return body
        else:
            raise ValueError(f"Invalid body type: {type(body)}")


class RconResponse(pydantic.BaseModel):
    """The format the game server returns from a RCON request"""

    status_code: int = pydantic.Field(validation_alias="statusCode")
    status_msg: str = pydantic.Field(validation_alias="statusMessage")
    version: int = pydantic.Field(validation_alias="version")
    command: str = pydantic.Field(validation_alias="name")
    content: str = pydantic.Field(validation_alias="contentBody")

    class Config:
        populate_by_name = True


class HLLConnectionV2:
    """Manages a TCP socket connection over the RCON V2 protocol"""

    # Keep track of each individual request made so when the protocol
    # is updated we can make concurrent requests easier
    __request_id = count(start=1)

    # The game server will send an 8 byte little endian response header

    def __init__(self, protocol_version: int = RCON_PROTOCOL_VERSION) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(TIMEOUT_SEC)
        self.protocol_version = protocol_version
        self.xor_key: bytes | None = None
        self.auth_token: str | None = None
        # V2 currently returns a XOR key after the initial request for V1 compatibility
        # and we need to keep track so we can dump those initial 4 bytes
        self.v1_xor_key_received: bool = False
        self.id = next(self.__request_id)

    def _xor_encode(
        self, message: str | bytes | bytearray, encoding: str = "utf-8"
    ) -> bytes:
        """XOR encrypt the given message with the given XOR key"""

        # The initial request to the server isn't XOR encoded because
        # we don't have the key yet
        if not self.xor_key:
            if isinstance(message, str):
                return message.encode()
            return message

        if isinstance(message, str):
            message = message.encode(encoding=encoding)

        return bytes(
            [
                message_char ^ xor_char
                for message_char, xor_char in zip(message, cycle(self.xor_key))
            ]
        )

    def _xor_decode(self, cipher_text: str | bytes | bytearray) -> str:
        """XOR decrypt the given cipher text with the given XOR key"""
        return self._xor_encode(cipher_text).decode("utf-8")

    def encode(self, request: RconRequest) -> bytes:
        """Serialize and XOR encode the requested command"""
        # TODO: They (should) add a header to requests and not just responses
        # and we will add it here
        body = request.model_dump_json(by_alias=True)
        return self._xor_encode(body)

    def request(self, command: str, body: ContentBody) -> RconResponse:
        """Make a request to the game server"""
        if not body:
            body = ""

        if self.auth_token is None:
            raise HLLAuthError

        return self.send(RconRequest(command=command, body=body, auth=self.auth_token))

    def send(self, request: RconRequest) -> RconResponse:
        """Encode/send the request to the game server"""

        logger.debug("sending request=%s", request)
        payload: bytes = self.encode(request)
        self.socket.sendall(payload)

        # The game server still sends the V1 XOR key which needs to be ignored
        if not self.v1_xor_key_received:
            _ = self.socket.recv(4)
            self.v1_xor_key_received = True

        # The response header is always a fixed 8 bytes
        header = bytearray()
        while len(header) < RESPONSE_HEADER_SIZE:
            chunk = self.socket.recv(RESPONSE_HEADER_SIZE - len(header))
            header.extend(chunk)

        # TODO: Once the protocol supports request IDs, use the response ID to match request -> response
        response_id, content_length = struct.unpack(HEADER_BIT_FORMAT, header)
        logger.debug("response_id=%s content_length=%s", response_id, content_length)

        raw_content = bytearray()
        # Receive content_length bytes
        while len(raw_content) < content_length:
            chunk = self.socket.recv(content_length - len(raw_content))
            raw_content.extend(chunk)

        content = self._xor_decode(raw_content)
        # Validate the response format or bubble up a ValidationError
        return RconResponse.model_validate_json(content)

    def connect(self, host: str, port: int, password: str):
        """Connect to the game server; authenticate and set the XOR key for future requests"""
        self.socket.connect((host, int(port)))

        # Once a socket connection is open the game server will return a XOR key
        command = RconRequest(command="ServerConnect", auth="", body=None)
        response = self.send(command)
        self.xor_key = base64.b64decode(response.content)
        logger.debug("XOR key=%s", self.xor_key)

        # Once we login the game server returns an auth token used on every subsequent request
        command = RconRequest(command="Login", auth="", body=password)
        response = self.send(command)
        logger.debug("response=%s", response)
        self.auth_token = response.content

    def close(self) -> None:
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            logger.debug("Unable to send socket shutdown")
        finally:
            self.socket.close()


# TODO: replace this with a V2 connection once V2 is production ready
class HLLConnection:
    """demonstration class only
    - coded for clarity, not efficiency
    """

    def __init__(self) -> None:
        self.xorkey = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(TIMEOUT_SEC)
        self.id = f"{get_ident()}-{uuid.uuid4()}"

    def connect(self, host, port, password: str):
        self.sock.connect((host, port))
        self.xorkey = self.sock.recv(MSGLEN)
        self.send(f"login {password}".encode())
        result = self.receive()
        if result != b"SUCCESS":
            raise HLLAuthError("Invalid password")

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            logger.debug("Unable to send socket shutdown")
        self.sock.close()

    def send(self, msg) -> int:
        xored = self._xor(msg)
        sent = self.sock.send(xored)
        if sent != len(msg):
            raise RuntimeError("socket connection broken")
        return sent

    def _xor(self, msg) -> bytes:
        n = []
        if not self.xorkey:
            raise RuntimeError("The game server did not return a key")
        for i in range(len(msg)):
            n.append(msg[i] ^ self.xorkey[i % len(self.xorkey)])

        return array.array("B", n).tobytes()

    def receive(self, msglen=MSGLEN) -> bytes:
        buff = self.sock.recv(msglen)
        msg = self._xor(buff)

        while len(buff) >= msglen:
            try:
                buff = self.sock.recv(msglen)
            except socket.timeout:
                break
            msg += self._xor(buff)

        return msg
