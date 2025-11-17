# app/common/input_thread.py
import sys
import threading
import queue

def start_input_thread(input_queue: queue.Queue):
    """Run in background to capture console input."""
    def _reader():
        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break  # EOF
                input_queue.put(line.strip())
            except:
                break
    thread = threading.Thread(target=_reader, daemon=True)
    thread.start()
    return thread