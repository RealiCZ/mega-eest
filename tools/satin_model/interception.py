"""The transaction's own `keylessDeploy` call: the decoder's conditions (`SATIN-ICPT-006`) and the
deployment's first steps (`SATIN-KEY-005`)."""

from __future__ import annotations

from .constants import KEYLESS_DEPLOY_OVERHEAD_GAS, MALFORMED_ENCODING, MAX_U64, NO_ETHER_TRANSFER
from .records import fmt, Unmodelled


def keyless_arguments(data: bytes):
    """SATIN-ICPT-006's five conditions on the input after the selector: the `bytes` argument, or
    None when KeylessDeploy's decoder refuses the arguments."""
    body = data[4:]
    if len(body) < 64:  # 1: a head of two words
        return None
    offset = int.from_bytes(body[0:32], "big")
    if offset > MAX_U64 or offset + 32 > len(body):  # 2, and the length word must be in the input
        return None
    length = int.from_bytes(body[offset:offset + 32], "big")
    if length > MAX_U64 or offset + 32 + length > len(body):  # 3 and 4
        return None
    return body[offset + 32:offset + 32 + length]  # 5: nothing more is required


def rlp_decodes_as_list(b: bytes) -> bool:
    """Whether `b` is exactly one RLP list (no trailing byte): the shape a signed legacy transaction
    needs before its fields are read."""
    if not b or b[0] < 0xC0:
        return False
    if b[0] <= 0xF7:
        return 1 + (b[0] - 0xC0) == len(b)
    n = b[0] - 0xF7
    if len(b) < 1 + n:
        return False
    return 1 + n + int.from_bytes(b[1:1 + n], "big") == len(b)


class InterceptionMixin:
    """The transaction's own `keylessDeploy` call: the decoder's conditions (`SATIN-ICPT-006`) and the"""

    def keyless_call(self, frame):
        """The transaction's own `CALL` to KeylessDeploy that SATIN-ICPT-006 recognizes: steps 1 to 3 of
        the deployment, as far as the refusals of this model's cases."""
        d, tx = self.d, self.tx
        argument = keyless_arguments(tx.data)
        offset = int.from_bytes(tx.data[4:36], "big")
        d.add("outcome", f"the transaction's own CALL to KeylessDeploy carries keylessDeploy's selector, and its arguments meet "
              f"the decoder's conditions (offset {offset}, {len(argument)} bytes of the first argument within the input): "
              "recognized, which is part of interception, before the frame start", "SATIN-ICPT-006", "SATIN-ICPT-007")
        self.charge_regular(frame, KEYLESS_DEPLOY_OVERHEAD_GAS, "KEYLESS_DEPLOY_OVERHEAD_GAS")
        d.add("gasLedgers", f"step 1: KEYLESS_DEPLOY_OVERHEAD_GAS {fmt(KEYLESS_DEPLOY_OVERHEAD_GAS)} regular gas; a refusal "
              "after it reverts the call, and the regular gas it spent stays spent", "SATIN-KEY-004", "SATIN-KEY-005")
        if tx.value:
            d.add("outcome", f"step 2: the call carries value {tx.value}: it reverts with NoEtherTransfer() before any value "
                  "moves and before any frame is built", "SATIN-KEY-005", "SATIN-KEY-018")
            return "revert", NO_ETHER_TRANSFER
        if rlp_decodes_as_list(argument):
            raise Unmodelled("a keyless deployment past step 3's encoding check")
        d.add("outcome", f"step 3: the first argument's {len(argument)} bytes are not the RLP encoding of a transaction: "
              "MalformedEncoding()", "SATIN-KEY-005")
        return "revert", MALFORMED_ENCODING
