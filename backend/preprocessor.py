"""
File Input & Preprocessing Module for SHA-3 Visualization
Handles file reading, padding calculation, and block preparation
"""

import os
from typing import Tuple, List, Dict, Any
from dataclasses import dataclass
from backend.sha3 import sha3_pad, sha3_224, sha3_256, sha3_384, sha3_512

@dataclass
class BlockInfo:
    """Information about a single block in the absorption phase"""
    block_index: int
    block_data: bytes
    is_padding_block: bool
    padding_bytes_added: int
    rate_bytes: int

@dataclass
class PreprocessingResult:
    """Complete preprocessing result for visualization"""
    original_input: bytes
    original_size_bytes: int
    padded_input: bytes
    padded_size_bytes: int
    selected_variant: str
    rate_bits: int
    rate_bytes: int
    capacity_bits: int
    total_blocks: int
    blocks: List[BlockInfo]
    padding_applied: str
    domain_separation: str

class SHA3Preprocessor:
    """Handles preprocessing of input for SHA-3 visualization"""
    
    # SHA-3 variants configuration
    VARIANTS = {
        "SHA3-224": {"r": 1152, "c": 448, "output": 224},
        "SHA3-256": {"r": 1088, "c": 512, "output": 256},
        "SHA3-384": {"r": 832, "c": 768, "output": 384},
        "SHA3-512": {"r": 576, "c": 1024, "output": 512},
    }
    
    def __init__(self):
        self.current_result = None
    
    def read_file(self, file_path: str) -> bytes:
        """
        Read file content as bytes
        
        Args:
            file_path: Path to the file
            
        Returns:
            File content as bytes
            
        Raises:
            FileNotFoundError: If file doesn't exist
            PermissionError: If can't read file
            IOError: For other I/O errors
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"Cannot read file: {file_path}")
        
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            raise IOError(f"Error reading file {file_path}: {str(e)}")
    
    def get_input_source(self, text_input: str = None, file_path: str = None) -> bytes:
        """
        Get input bytes from either text or file
        
        Args:
            text_input: Text string input
            file_path: Path to file
            
        Returns:
            Input as bytes
            
        Raises:
            ValueError: If both or neither input provided
        """
        if text_input is None and file_path is None:
            raise ValueError("Either text_input or file_path must be provided")
        
        if text_input is not None and file_path is not None:
            raise ValueError("Cannot provide both text_input and file_path")
        
        if text_input is not None:
            return text_input.encode('utf-8')
        
        if file_path is not None:
            return self.read_file(file_path)
        
        return b""  # Should never reach here
    
    def calculate_blocks_needed(self, padded_length: int, rate_bytes: int) -> int:
        """
        Calculate number of blocks needed for absorption
        
        Args:
            padded_length: Length of padded message in bytes
            rate_bytes: Rate in bytes
            
        Returns:
            Number of blocks
        """
        if rate_bytes <= 0:
            raise ValueError(f"Invalid rate_bytes: {rate_bytes}")
        
        if padded_length == 0:
            return 0
        
        # Ceiling division
        return (padded_length + rate_bytes - 1) // rate_bytes
    
    def split_into_blocks(self, padded_data: bytes, rate_bytes: int) -> List[bytes]:
        """
        Split padded data into rate-sized blocks
        
        Args:
            padded_data: Padded message bytes
            rate_bytes: Size of each block in bytes
            
        Returns:
            List of blocks
        """
        if rate_bytes <= 0:
            raise ValueError(f"Invalid rate_bytes: {rate_bytes}")
        
        blocks = []
        for i in range(0, len(padded_data), rate_bytes):
            block = padded_data[i:i + rate_bytes]
            blocks.append(block)
        
        return blocks
    
    def identify_padding_blocks(self, blocks: List[bytes], original_length: int, 
                                rate_bytes: int) -> List[BlockInfo]:
        """
        Identify which blocks contain padding
        
        Args:
            blocks: List of all blocks
            original_length: Original message length in bytes
            rate_bytes: Rate in bytes
            
        Returns:
            List of BlockInfo objects
        """
        block_infos = []
        bytes_processed = 0
        
        for idx, block in enumerate(blocks):
            is_padding_block = bytes_processed >= original_length
            padding_bytes = 0
            
            if is_padding_block:
                # Count padding bytes in this block
                padding_bytes = len(block)
            else:
                # Check if this block contains the padding start
                block_end = bytes_processed + len(block)
                if block_end > original_length:
                    # This block contains some padding
                    is_padding_block = True
                    padding_bytes = block_end - original_length
            
            block_infos.append(BlockInfo(
                block_index=idx,
                block_data=block,
                is_padding_block=is_padding_block,
                padding_bytes_added=padding_bytes,
                rate_bytes=rate_bytes
            ))
            
            bytes_processed += len(block)
        
        return block_infos
    
    def preprocess(self, input_data: bytes, variant: str) -> PreprocessingResult:
        """
        Main preprocessing function
        
        Args:
            input_data: Input bytes to hash
            variant: SHA-3 variant (e.g., "SHA3-256")
            
        Returns:
            PreprocessingResult with all information for visualization
        """
        if variant not in self.VARIANTS:
            raise ValueError(f"Unknown variant: {variant}. Choose from {list(self.VARIANTS.keys())}")
        
        # Get variant parameters
        params = self.VARIANTS[variant]
        rate_bits = params["r"]
        rate_bytes = rate_bits // 8
        capacity_bits = params["c"]
        
        # Apply padding
        padded_input = sha3_pad(input_data, rate_bits)
        
        # Calculate blocks
        total_blocks = self.calculate_blocks_needed(len(padded_input), rate_bytes)
        
        # Split into blocks
        blocks = self.split_into_blocks(padded_input, rate_bytes)
        
        # Identify padding blocks
        block_infos = self.identify_padding_blocks(blocks, len(input_data), rate_bytes)
        
        # Create padding description
        padding_applied = self._describe_padding(input_data, padded_input)
        
        # Create result
        result = PreprocessingResult(
            original_input=input_data,
            original_size_bytes=len(input_data),
            padded_input=padded_input,
            padded_size_bytes=len(padded_input),
            selected_variant=variant,
            rate_bits=rate_bits,
            rate_bytes=rate_bytes,
            capacity_bits=capacity_bits,
            total_blocks=total_blocks,
            blocks=block_infos,
            padding_applied=padding_applied,
            domain_separation="0x06 for SHA-3"
        )
        
        self.current_result = result
        return result
    
    def _describe_padding(self, original: bytes, padded: bytes) -> str:
        """
        Create human-readable description of padding
        
        Args:
            original: Original input bytes
            padded: Padded input bytes
            
        Returns:
            Description string
        """
        padding_bytes = len(padded) - len(original)
        
        if padding_bytes == 0:
            return "No padding needed (message already multiple of rate)"
        
        # Find the 0x06 and 0x80 markers
        description = f"Added {padding_bytes} bytes of padding: "
        
        # Show last few bytes for visualization
        last_bytes = padded[-4:] if len(padded) >= 4 else padded
        description += f"... {last_bytes.hex()} (last 4 bytes)"
        
        return description
    
    def get_rate_capacity_split(self, variant: str) -> Tuple[int, int, List[str]]:
        """
        Get rate and capacity information for visualization
        
        Args:
            variant: SHA-3 variant
            
        Returns:
            Tuple of (rate_bits, capacity_bits, lane_labels)
        """
        if variant not in self.VARIANTS:
            raise ValueError(f"Unknown variant: {variant}")
        
        params = self.VARIANTS[variant]
        rate_bits = params["r"]
        capacity_bits = params["c"]
        
        # Generate lane labels (25 lanes total)
        rate_lanes = rate_bits // 64
        lane_labels = []
        
        for i in range(25):
            if i < rate_lanes:
                lane_labels.append(f"Rate Lane {i}")
            else:
                lane_labels.append(f"Capacity Lane {i}")
        
        return rate_bits, capacity_bits, lane_labels