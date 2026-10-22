from __future__ import annotations

import asyncio
import socket
import uuid


class CallbackServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8989):
        self.host = host
        self.port = port
        self.received: set[str] = set()
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> bool:
        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                request_line = await reader.readline()
                parts = request_line.decode("utf-8", "ignore").split()
                if len(parts) >= 2:
                    path = parts[1].lstrip("/")
                    token = path.split("/")[0]
                    if token:
                        self.received.add(token)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        try:
            self._server = await asyncio.start_server(handler, self.host, self.port)
            return True
        except OSError:
            return False

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    def got(self, token: str) -> bool:
        return token in self.received

    @staticmethod
    def new_token() -> str:
        return uuid.uuid4().hex[:12]


class DnsCallbackServer:
    """Minimal UDP DNS server that records queried names."""

    def __init__(self, host: str = "0.0.0.0", port: int = 5353):
        self.host = host
        self.port = port
        self.received: set[str] = set()
        self._transport: asyncio.DatagramTransport | None = None

    async def start(self) -> bool:
        loop = asyncio.get_event_loop()

        class Protocol(asyncio.DatagramProtocol):
            def __init__(self, outer):
                self.outer = outer

            def datagram_received(self, data, addr):
                try:
                    # Parse header
                    if len(data) < 12:
                        return
                    tid = data[:2]
                    flags = b"\x81\x80"
                    qdcount = data[4:6]
                    # Parse question
                    offset = 12
                    labels = []
                    while offset < len(data) and data[offset] != 0:
                        length = data[offset]
                        labels.append(data[offset + 1:offset + 1 + length].decode("utf-8", "ignore"))
                        offset += 1 + length
                    qname = ".".join(labels)
                    if qname:
                        self.outer.received.add(qname)
                    # Build response: copy question, add A record 127.0.0.1
                    question_end = offset + 1 + 4  # null + qtype + qclass
                    question = data[12:question_end]
                    header = tid + flags + qdcount + b"\x00\x01" + b"\x00\x00\x00\x00"
                    # Answer: name pointer to question, type A, class IN, ttl, rdlength 4, rdata
                    answer = b"\xc0\x0c" + b"\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton("127.0.0.1")
                    response = header + question + answer
                    self.transport.sendto(response, addr)
                except Exception:
                    pass

        try:
            self._transport, _ = await loop.create_datagram_endpoint(
                lambda: Protocol(self), local_addr=(self.host, self.port)
            )
            return True
        except OSError:
            return False

    async def stop(self) -> None:
        if self._transport:
            self._transport.close()
            self._transport = None

    def got(self, name: str) -> bool:
        return any(name in item for item in self.received)