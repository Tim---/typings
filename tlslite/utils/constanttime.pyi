from .compat import compatHMAC as compatHMAC
from _typeshed import Incomplete

def ct_lt_u32(val_a, val_b): ...
def ct_gt_u32(val_a, val_b): ...
def ct_le_u32(val_a, val_b): ...
def ct_lsb_prop_u8(val): ...
def ct_lsb_prop_u16(val): ...
def ct_isnonzero_u32(val): ...
def ct_neq_u32(val_a, val_b): ...
def ct_eq_u32(val_a, val_b): ...
def ct_check_cbc_mac_and_pad(
    data, mac, seqnumBytes, contentType, version, block_size: int = 16
): ...

ct_compare_digest: Incomplete
