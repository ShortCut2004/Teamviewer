from typing import Union, Optional

from crypto.Hash.cSHAKE128 import cSHAKE_XOF

Buffer = Union[bytes, bytearray, memoryview]

def new(data:     Optional[Buffer] = ...,
        custom:   Optional[Buffer] = ...) -> cSHAKE_XOF: ...
