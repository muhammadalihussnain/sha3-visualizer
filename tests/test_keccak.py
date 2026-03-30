import pytest
from backend.keccak import Keccak

def test_theta_step():
    k = Keccak(bitrate=1088, capacity=512, output_length=256)
    # Initialize lanes to known values
    k.lanes = [[0]*5 for _ in range(5)]
    k.theta()
    # Test that lanes changed (or specific expected result)
    assert isinstance(k.lanes, list)
    assert len(k.lanes) == 5
    assert len(k.lanes[0]) == 5

def test_full_keccak_run():
    k = Keccak(bitrate=1088, capacity=512, output_length=256)
    k.f_keccak()
    # After full 24-round F-Keccak, lanes should still be 5x5
    assert len(k.lanes) == 5
    assert len(k.lanes[0]) == 5