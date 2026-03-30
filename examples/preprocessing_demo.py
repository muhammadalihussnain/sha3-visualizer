"""
Demonstration of the preprocessing module
"""

from backend.preprocessor import SHA3Preprocessor

def demo_preprocessing():
    """Demonstrate preprocessing features"""
    preprocessor = SHA3Preprocessor()
    
    print("=" * 60)
    print("SHA-3 Preprocessing Module Demo")
    print("=" * 60)
    
    # Example 1: Text input with SHA3-256
    print("\n1. Processing text input with SHA3-256:")
    print("-" * 40)
    result = preprocessor.preprocess(b"Hello SHA-3 World!", "SHA3-256")
    print(f"Input: {result.original_input}")
    print(f"Input size: {result.original_size_bytes} bytes")
    print(f"Rate: {result.rate_bits} bits ({result.rate_bytes} bytes)")
    print(f"Capacity: {result.capacity_bits} bits")
    print(f"Padding applied: {result.padding_applied}")
    print(f"Total blocks needed: {result.total_blocks}")
    
    # Show block details
    for block in result.blocks:
        print(f"  Block {block.block_index}: {len(block.block_data)} bytes, "
              f"Padding block: {block.is_padding_block}")
    
    # Example 2: Rate/Capacity visualization
    print("\n2. Rate vs Capacity Split (SHA3-224):")
    print("-" * 40)
    rate, capacity, labels = preprocessor.get_rate_capacity_split("SHA3-224")
    print(f"Rate: {rate} bits ({rate//64} lanes)")
    print(f"Capacity: {capacity} bits ({capacity//64} lanes)")
    
    # Count rate vs capacity lanes
    rate_lanes = sum(1 for l in labels if "Rate" in l)
    cap_lanes = sum(1 for l in labels if "Capacity" in l)
    print(f"Rate lanes: {rate_lanes}, Capacity lanes: {cap_lanes}")
    
    # Example 3: Empty input
    print("\n3. Processing empty input:")
    print("-" * 40)
    result = preprocessor.preprocess(b"", "SHA3-512")
    print(f"Empty input requires {result.total_blocks} block(s) due to padding")
    
    # Example 4: Large input
    print("\n4. Processing large input (5000 bytes):")
    print("-" * 40)
    large_input = b"X" * 5000
    result = preprocessor.preprocess(large_input, "SHA3-256")
    print(f"Large input ({len(large_input)} bytes) splits into {result.total_blocks} blocks")
    print(f"Each block is {result.rate_bytes} bytes except possibly the last")

if __name__ == "__main__":
    demo_preprocessing()