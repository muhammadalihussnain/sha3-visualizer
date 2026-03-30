"""
Unit tests for SHA-3 Preprocessor module
Achieves 100% code coverage
"""

import pytest
import os
import tempfile
from backend.preprocessor import SHA3Preprocessor, PreprocessingResult, BlockInfo

class TestSHA3Preprocessor:
    """Test suite for SHA3Preprocessor class"""
    
    @pytest.fixture
    def preprocessor(self):
        """Create preprocessor instance"""
        return SHA3Preprocessor()
    
    @pytest.fixture
    def temp_file(self):
        """Create temporary file for testing"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test file content for SHA-3")
            temp_path = f.name
        
        yield temp_path
        
        # Cleanup
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    
    # Tests for read_file method
    def test_read_file_success(self, preprocessor, temp_file):
        """Test successful file reading"""
        content = preprocessor.read_file(temp_file)
        assert content == b"Test file content for SHA-3"
    
    def test_read_file_not_found(self, preprocessor):
        """Test reading non-existent file"""
        with pytest.raises(FileNotFoundError) as exc_info:
            preprocessor.read_file("/nonexistent/file.txt")
        assert "File not found" in str(exc_info.value)
    
    def test_read_file_permission_error(self, preprocessor, temp_file):
        """Test reading file without permission"""
        # Make file read-only
        os.chmod(temp_file, 0o000)
        
        with pytest.raises(PermissionError) as exc_info:
            preprocessor.read_file(temp_file)
        assert "Cannot read file" in str(exc_info.value)
        
        # Restore permission for cleanup
        os.chmod(temp_file, 0o644)
    
    def test_read_file_io_error(self, preprocessor):
        """Test reading file with I/O error"""
        # Pass directory instead of file
        with pytest.raises(IOError) as exc_info:
            preprocessor.read_file("/tmp")
        assert "Error reading file" in str(exc_info.value)
    
    # Tests for get_input_source method
    def test_get_input_from_text(self, preprocessor):
        """Test getting input from text string"""
        result = preprocessor.get_input_source(text_input="Hello World")
        assert result == b"Hello World"
    
    def test_get_input_from_file(self, preprocessor, temp_file):
        """Test getting input from file"""
        result = preprocessor.get_input_source(file_path=temp_file)
        assert result == b"Test file content for SHA-3"
    
    def test_get_input_no_arguments(self, preprocessor):
        """Test error when no arguments provided"""
        with pytest.raises(ValueError) as exc_info:
            preprocessor.get_input_source()
        assert "Either text_input or file_path must be provided" in str(exc_info.value)
    
    def test_get_input_both_arguments(self, preprocessor, temp_file):
        """Test error when both arguments provided"""
        with pytest.raises(ValueError) as exc_info:
            preprocessor.get_input_source(text_input="test", file_path=temp_file)
        assert "Cannot provide both" in str(exc_info.value)
    
    # Tests for calculate_blocks_needed method
    def test_calculate_blocks_single(self, preprocessor):
        """Test single block calculation"""
        blocks = preprocessor.calculate_blocks_needed(100, 136)
        assert blocks == 1
    
    def test_calculate_blocks_multiple(self, preprocessor):
        """Test multiple blocks calculation"""
        blocks = preprocessor.calculate_blocks_needed(200, 136)
        assert blocks == 2
    
    def test_calculate_blocks_exact(self, preprocessor):
        """Test exact multiple of rate"""
        blocks = preprocessor.calculate_blocks_needed(272, 136)
        assert blocks == 2
    
    def test_calculate_blocks_zero(self, preprocessor):
        """Test zero length input"""
        blocks = preprocessor.calculate_blocks_needed(0, 136)
        assert blocks == 0
    
    def test_calculate_blocks_invalid_rate(self, preprocessor):
        """Test invalid rate"""
        with pytest.raises(ValueError) as exc_info:
            preprocessor.calculate_blocks_needed(100, 0)
        assert "Invalid rate_bytes" in str(exc_info.value)
    
    # Tests for split_into_blocks method
    def test_split_blocks_exact(self, preprocessor):
        """Test splitting into exact blocks"""
        data = b"A" * 272
        blocks = preprocessor.split_into_blocks(data, 136)
        assert len(blocks) == 2
        assert len(blocks[0]) == 136
        assert len(blocks[1]) == 136
    
    def test_split_blocks_uneven(self, preprocessor):
        """Test splitting with remainder"""
        data = b"A" * 150
        blocks = preprocessor.split_into_blocks(data, 136)
        assert len(blocks) == 2
        assert len(blocks[0]) == 136
        assert len(blocks[1]) == 14
    
    def test_split_blocks_empty(self, preprocessor):
        """Test splitting empty data"""
        blocks = preprocessor.split_into_blocks(b"", 136)
        assert blocks == []
    
    def test_split_blocks_invalid_rate(self, preprocessor):
        """Test splitting with invalid rate"""
        with pytest.raises(ValueError) as exc_info:
            preprocessor.split_into_blocks(b"test", 0)
        assert "Invalid rate_bytes" in str(exc_info.value)
    
    # Tests for identify_padding_blocks
    def test_identify_padding_no_padding(self, preprocessor):
        """Test identification when no padding exists"""
        original = b"Hello World"
        blocks = [b"Hello Worl", b"d"]
        block_infos = preprocessor.identify_padding_blocks(blocks, len(original), 8)
        
        assert len(block_infos) == 2
        assert not block_infos[0].is_padding_block
        assert block_infos[0].padding_bytes_added == 0
        assert not block_infos[1].is_padding_block
    
    def test_identify_padding_with_padding(self, preprocessor):
        """Test identification when padding exists"""
        original = b"Hello"
        blocks = [b"Hello", b"World"]
        block_infos = preprocessor.identify_padding_blocks(blocks, len(original), 5)
        
        assert len(block_infos) == 2
        assert not block_infos[0].is_padding_block
        assert block_infos[0].padding_bytes_added == 0
        assert block_infos[1].is_padding_block
        assert block_infos[1].padding_bytes_added == 5
    
    def test_identify_padding_mixed_block(self, preprocessor):
        """Test block that contains both data and padding"""
        original = b"Hello"
        blocks = [b"HelloWorld"]
        block_infos = preprocessor.identify_padding_blocks(blocks, len(original), 10)
        
        assert len(block_infos) == 1
        assert block_infos[0].is_padding_block
        assert block_infos[0].padding_bytes_added == 5  # "World" is padding
    
    # Tests for preprocess method
    def test_preprocess_sha3_256_text(self, preprocessor):
        """Test preprocessing text for SHA3-256"""
        result = preprocessor.preprocess(b"Hello", "SHA3-256")
        
        assert isinstance(result, PreprocessingResult)
        assert result.original_input == b"Hello"
        assert result.selected_variant == "SHA3-256"
        assert result.rate_bits == 1088
        assert result.rate_bytes == 136
        assert result.capacity_bits == 512
        assert result.total_blocks > 0
        assert len(result.blocks) == result.total_blocks
    
    def test_preprocess_sha3_224(self, preprocessor):
        """Test preprocessing for SHA3-224"""
        result = preprocessor.preprocess(b"Test", "SHA3-224")
        
        assert result.selected_variant == "SHA3-224"
        assert result.rate_bits == 1152
        assert result.rate_bytes == 144
        assert result.capacity_bits == 448
    
    def test_preprocess_sha3_384(self, preprocessor):
        """Test preprocessing for SHA3-384"""
        result = preprocessor.preprocess(b"Test", "SHA3-384")
        
        assert result.selected_variant == "SHA3-384"
        assert result.rate_bits == 832
        assert result.rate_bytes == 104
        assert result.capacity_bits == 768
    
    def test_preprocess_sha3_512(self, preprocessor):
        """Test preprocessing for SHA3-512"""
        result = preprocessor.preprocess(b"Test", "SHA3-512")
        
        assert result.selected_variant == "SHA3-512"
        assert result.rate_bits == 576
        assert result.rate_bytes == 72
        assert result.capacity_bits == 1024
    
    def test_preprocess_invalid_variant(self, preprocessor):
        """Test preprocessing with invalid variant"""
        with pytest.raises(ValueError) as exc_info:
            preprocessor.preprocess(b"Test", "SHA3-999")
        assert "Unknown variant" in str(exc_info.value)
    
    def test_preprocess_empty_input(self, preprocessor):
        """Test preprocessing empty input"""
        result = preprocessor.preprocess(b"", "SHA3-256")
        
        assert result.original_size_bytes == 0
        assert result.padded_size_bytes > 0  # Padding always added
        assert result.total_blocks == 1  # Padding creates at least one block
    
    def test_preprocess_large_input(self, preprocessor):
        """Test preprocessing large input"""
        large_data = b"X" * 10000
        result = preprocessor.preprocess(large_data, "SHA3-256")
        
        assert result.original_size_bytes == 10000
        assert result.total_blocks > 0
        assert len(result.blocks) == result.total_blocks
    
    # Tests for _describe_padding method
    def test_describe_padding_with_padding(self, preprocessor):
        """Test padding description when padding added"""
        original = b"Hello"
        padded = b"Hello\x06\x00\x00\x00\x00\x00\x00\x00\x00\x80"
        description = preprocessor._describe_padding(original, padded)
        
        assert "Added" in description
        assert "bytes of padding" in description
    
    def test_describe_padding_no_padding(self, preprocessor):
        """Test padding description when no padding needed"""
        # Create data that's already multiple of rate (unlikely for SHA-3)
        original = b"A" * 136
        description = preprocessor._describe_padding(original, original)
        
        assert "No padding needed" in description
    
    # Tests for get_rate_capacity_split method
    def test_get_rate_capacity_split_256(self, preprocessor):
        """Test rate/capacity split for SHA3-256"""
        rate, capacity, labels = preprocessor.get_rate_capacity_split("SHA3-256")
        
        assert rate == 1088
        assert capacity == 512
        assert len(labels) == 25
        assert labels[0] == "Rate Lane 0"
        assert labels[16] == "Rate Lane 16"  # 1088/64 = 17 rate lanes
        assert labels[17] == "Capacity Lane 17"  # Rest are capacity
    
    def test_get_rate_capacity_split_224(self, preprocessor):
        """Test rate/capacity split for SHA3-224"""
        rate, capacity, labels = preprocessor.get_rate_capacity_split("SHA3-224")
        
        assert rate == 1152
        assert capacity == 448
        assert len(labels) == 25
        # 1152/64 = 18 rate lanes (0-17), 7 capacity lanes (18-24)
        assert labels[17] == "Rate Lane 17"
        assert labels[18] == "Capacity Lane 18"
    
    def test_get_rate_capacity_split_invalid(self, preprocessor):
        """Test invalid variant for split"""
        with pytest.raises(ValueError) as exc_info:
            preprocessor.get_rate_capacity_split("Invalid")
        assert "Unknown variant" in str(exc_info.value)
    
    # Tests for BlockInfo dataclass
    def test_block_info_creation(self):
        """Test BlockInfo dataclass creation"""
        block = BlockInfo(
            block_index=0,
            block_data=b"test",
            is_padding_block=False,
            padding_bytes_added=0,
            rate_bytes=136
        )
        
        assert block.block_index == 0
        assert block.block_data == b"test"
        assert not block.is_padding_block
        assert block.padding_bytes_added == 0
    
    # Integration tests
    def test_full_pipeline_text_input(self, preprocessor):
        """Test complete preprocessing pipeline with text input"""
        # Step 1: Get input
        input_data = preprocessor.get_input_source(text_input="SHA-3 Test")
        
        # Step 2: Preprocess
        result = preprocessor.preprocess(input_data, "SHA3-256")
        
        # Step 3: Verify results
        assert result.original_input == b"SHA-3 Test"
        assert result.padded_input != result.original_input
        assert len(result.blocks) == result.total_blocks
        
        # Step 4: Verify block information
        for block in result.blocks:
            assert len(block.block_data) == result.rate_bytes or \
                   block.block_index == result.total_blocks - 1
    
    def test_full_pipeline_file_input(self, preprocessor, temp_file):
        """Test complete preprocessing pipeline with file input"""
        # Step 1: Get input from file
        input_data = preprocessor.get_input_source(file_path=temp_file)
        
        # Step 2: Preprocess
        result = preprocessor.preprocess(input_data, "SHA3-512")
        
        # Step 3: Verify results
        assert result.original_input == b"Test file content for SHA-3"
        assert result.selected_variant == "SHA3-512"
        assert result.rate_bytes == 72
    
    def test_multiple_preprocess_calls(self, preprocessor):
        """Test multiple preprocessing calls with different variants"""
        result1 = preprocessor.preprocess(b"Test1", "SHA3-256")
        result2 = preprocessor.preprocess(b"Test2", "SHA3-512")
        
        assert result1.selected_variant == "SHA3-256"
        assert result2.selected_variant == "SHA3-512"
        assert result1.rate_bits != result2.rate_bits
    
    def test_current_result_storage(self, preprocessor):
        """Test that current result is stored"""
        result = preprocessor.preprocess(b"Test", "SHA3-256")
        assert preprocessor.current_result == result
        
        # New preprocessing should update current_result
        result2 = preprocessor.preprocess(b"Another", "SHA3-512")
        assert preprocessor.current_result == result2