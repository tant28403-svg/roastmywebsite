import subprocess
import sys


def test_main_entry_point():
    result = subprocess.run(
        [sys.executable, "-m", "roastmywebsite", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert "Roast My Website" in result.stdout