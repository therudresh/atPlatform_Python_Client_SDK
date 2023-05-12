from typing import Union, Tuple, overload, ByteString, Optional

class ChaCha20Poly1305Cipher:
    nonce: bytes

    def __init__(self, key: ByteString, nonce: ByteString) -> None: ...
    def update(self, data: ByteString) -> None: ...
    @overload
    def encrypt(self, plaintext: ByteString) -> bytes: ...
    @overload
    def encrypt(self, plaintext: ByteString, output: Union[bytearray, memoryview]) -> None: ...
    @overload
    def decrypt(self, plaintext: ByteString) -> bytes: ...
    @overload
    def decrypt(self, plaintext: ByteString, output: Union[bytearray, memoryview]) -> None: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    def verify(self, received_mac_tag: ByteString) -> None: ...
    def hexverify(self, received_mac_tag: str) -> None: ...
    def encrypt_and_digest(self, plaintext: ByteString) -> Tuple[bytes, bytes]: ...
    def decrypt_and_verify(self, ciphertext: ByteString, received_mac_tag: ByteString) -> bytes: ...

def new(key: ByteString, nonce: Optional[ByteString] = ...) -> ChaCha20Poly1305Cipher: ...

block_size: int
key_size: int
