import subprocess
import sys
import argparse

def run_with_timeout(command, timeout_seconds):
    """
    Runs a command with a specified timeout in a given working directory.
    Kills the process if it exceeds the timeout.
    """
    process = None
    try:
        print(f"Running command: '{' '.join(command)}' with timeout {timeout_seconds} seconds")
        
        process = subprocess.Popen(command, stdout=sys.stdout, stderr=sys.stderr)
        process.wait(timeout=timeout_seconds)
    except FileNotFoundError:
        print(f"Error: Command not found. Make sure '{command[0]}' is in your PATH or provide an absolute path.")
    except subprocess.TimeoutExpired:
        print(f"Command timed out after {timeout_seconds} seconds. Terminating process.")
        if process:
            process.kill()
            process.wait()
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a command with a timeout.")
    parser.add_argument('timeout', type=int, help="Timeout in seconds.")
    parser.add_argument('command', nargs=argparse.REMAINDER, help="The command to run.")
    
    args = parser.parse_args()

    if not args.command:
        print("Error: No command provided.")
        parser.print_help()
        sys.exit(1)

    if not args.timeout > 0:
        print("Error: Timeout must be a positive integer.")
        parser.print_help()
        sys.exit(1)

    run_with_timeout(args.command, args.timeout)

