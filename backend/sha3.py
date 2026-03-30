from backend.keccak import Keccak, MASK_64

def sha3_pad(msg: bytes, r: int) -> bytes:
    """
    Correct SHA-3 padding: pad10*1 with domain separation 0x06
    Implementation follows FIPS 202 exactly
    """
    rate_bytes = r // 8
    msg_len = len(msg)
    
    # The padding algorithm: append 0x06, then zeros, then 0x80
    # The total length must be a multiple of rate_bytes
    padded = bytearray(msg)
    padded.append(0x06)  # Domain separation for SHA-3
    
    # Add zeros until we have room for the final 0x80
    # We need at least 1 byte for 0x80, and the total must be multiple of rate_bytes
    while (len(padded) % rate_bytes) != (rate_bytes - 1):
        padded.append(0x00)
    
    # Append the final byte with the '1' bit at the end
    padded.append(0x80)
    
    return bytes(padded)

def absorb(k: Keccak, block: bytes, r: int):
    """
    XOR a block into the rate portion of the state
    Bytes are interpreted in little-endian order
    """
    rate_bytes = r // 8
    
    for i in range(rate_bytes):
        # Determine which lane this byte goes to
        lane_index = i // 8  # 8 bytes per lane
        byte_in_lane = i % 8
        
        # Map lane to (x, y) in row-major order (x changes fastest)
        x = lane_index % 5
        y = lane_index // 5
        
        # Insert byte in little-endian order
        byte_value = block[i]
        k.lanes[x][y] ^= (byte_value << (byte_in_lane * 8))
        k.lanes[x][y] &= MASK_64

def squeeze(k: Keccak, output_bits: int, r: int) -> bytes:
    """Extract output bytes from the state in little-endian order"""
    output_bytes = output_bits // 8
    rate_bytes = r // 8
    result = bytearray()
    
    while len(result) < output_bytes:
        # Extract from rate portion
        bytes_extracted = 0
        for y in range(5):
            for x in range(5):
                lane_idx = x + 5 * y
                if lane_idx * 8 >= rate_bytes:
                    continue
                
                lane = k.lanes[x][y]
                # Extract all 8 bytes from this lane (little-endian)
                for byte_pos in range(8):
                    if bytes_extracted < rate_bytes and len(result) < output_bytes:
                        result.append((lane >> (byte_pos * 8)) & 0xFF)
                        bytes_extracted += 1
                    else:
                        break
                
                if len(result) >= output_bytes:
                    break
            if len(result) >= output_bytes:
                break
        
        # If we need more bytes, permute the state
        if len(result) < output_bytes:
            k.f_keccak()
    
    return bytes(result)

def sha3(msg: bytes, r: int, c: int, output_bits: int) -> bytes:
    """
    Generic SHA-3 hash function
    r: bitrate (bits)
    c: capacity (bits)
    output_bits: desired output length
    """
    k = Keccak(bitrate=r, capacity=c, output_length=output_bits)
    
    # Pad the message
    padded_msg = sha3_pad(msg, r)
    block_size = r // 8
    
    # Absorb phase
    for i in range(0, len(padded_msg), block_size):
        block = padded_msg[i:i + block_size]
        absorb(k, block, r)
        k.f_keccak()  # Permute after each block
    
    # Squeeze phase
    return squeeze(k, output_bits, r)

# SHA-3 variants with correct parameters
def sha3_224(msg: bytes) -> bytes:
    """SHA3-224: r=1152, c=448, output=224"""
    return sha3(msg, r=1152, c=448, output_bits=224)

def sha3_256(msg: bytes) -> bytes:
    """SHA3-256: r=1088, c=512, output=256"""
    return sha3(msg, r=1088, c=512, output_bits=256)

def sha3_384(msg: bytes) -> bytes:
    """SHA3-384: r=832, c=768, output=384"""
    return sha3(msg, r=832, c=768, output_bits=384)

def sha3_512(msg: bytes) -> bytes:
    """SHA3-512: r=576, c=1024, output=512"""
    return sha3(msg, r=576, c=1024, output_bits=512)