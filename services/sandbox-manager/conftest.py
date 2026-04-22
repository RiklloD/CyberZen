import sys
import pathlib

# Add src/ to sys.path so tests can import sentinel_sandbox without an editable install
sys.path.insert(0, str(pathlib.Path(__file__).parent / "src"))
