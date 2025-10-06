import subprocess
import sys

def run_with_timeout(command, timeout_seconds):
    """
    Runs a command with a specified timeout.
    Kills the process if it exceeds the timeout.
    """
    process = None
    try:
        process = subprocess.Popen(command, stdout=sys.stdout, stderr=sys.stderr)
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        print(f"Command '{' '.join(command)}' timed out after {timeout_seconds} seconds. Terminating.")
        if process:
            process.kill()
            process.wait()
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python run_with_timeout.py <timeout_in_seconds> <command...>")
        sys.exit(1)

    try:
        timeout = int(sys.argv[1])
        cmd = sys.argv[2:]
        run_with_timeout(cmd, timeout)
    except ValueError:
        print("Error: Timeout must be an integer.")
        sys.exit(1)
