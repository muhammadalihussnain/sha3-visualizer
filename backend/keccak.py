"""
Complete Keccak-f[1600] implementation
FIPS 202 compliant
"""

MASK_64 = 0xFFFFFFFFFFFFFFFF
MASK_BITS = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF  # 64 bits

# Rotation offsets for each lane (x,y)
ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# Rotation offsets (r[x][y])
ROTATIONS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

class Keccak:
    def __init__(self, bitrate: int, capacity: int, output_length: int):
        """
        Initialize Keccak state
        bitrate: r (rate in bits)
        capacity: c (capacity in bits)
        output_length: output size in bits
        """
        self.bitrate = bitrate
        self.capacity = capacity
        self.output_length = output_length
        # 5x5 matrix of 64-bit lanes
        self.lanes = [[0] * 5 for _ in range(5)]
    
    def theta(self):
        """Theta step: XOR columns with rotated sums"""
        C = [0] * 5
        D = [0] * 5
        
        # Compute parity of each column
        for x in range(5):
            C[x] = self.lanes[x][0] ^ self.lanes[x][1] ^ self.lanes[x][2] ^ self.lanes[x][3] ^ self.lanes[x][4]
        
        # Compute D[x] = C[x-1] ^ rot(C[x+1], 1)
        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ ((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63)) & MASK_64
        
        # XOR D into each lane
        for x in range(5):
            for y in range(5):
                self.lanes[x][y] ^= D[x]
                self.lanes[x][y] &= MASK_64
    
    def rho(self):
        """Rho step: rotate each lane by fixed offset"""
        new_lanes = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                rotation = ROTATIONS[x][y]
                lane = self.lanes[x][y]
                # Circular left rotation
                rotated = ((lane << rotation) | (lane >> (64 - rotation))) & MASK_64
                new_lanes[x][y] = rotated
        self.lanes = new_lanes
    
    def pi(self):
        """Pi step: permute lanes"""
        new_lanes = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                new_lanes[x][y] = self.lanes[(x + 3 * y) % 5][x]
        self.lanes = new_lanes
    
    def chi(self):
        """Chi step: nonlinear mixing"""
        new_lanes = [[0] * 5 for _ in range(5)]
        for y in range(5):
            # Process each row independently
            for x in range(5):
                new_lanes[x][y] = self.lanes[x][y] ^ ((~self.lanes[(x + 1) % 5][y]) & self.lanes[(x + 2) % 5][y])
                new_lanes[x][y] &= MASK_64
        self.lanes = new_lanes
    
    def iota(self, round_index: int):
        """Iota step: XOR round constant into lane (0,0)"""
        rc = ROUND_CONSTANTS[round_index]
        self.lanes[0][0] ^= rc
        self.lanes[0][0] &= MASK_64
    
    def f_keccak(self):
        """Keccak-f[1600] permutation: 24 rounds"""
        for round_idx in range(24):
            self.theta()
            self.rho()
            self.pi()
            self.chi()
            self.iota(round_idx)
    
    def reset(self):
        """Reset the state to all zeros"""
        self.lanes = [[0] * 5 for _ in range(5)]