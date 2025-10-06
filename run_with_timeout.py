import subprocess
import sys
import argparse
import threading

def stream_output(pipe, output_stream):
    """Reads from a pipe and writes to a given stream."""
    if not pipe:
        return
    for line in iter(pipe.readline, ''):
        output_stream.write(line)
        output_stream.flush()
    pipe.close()

def run_with_timeout(command, timeout_seconds):
    """
    Runs a command with a specified timeout, streaming its stdout and stderr.
    Kills the process if it exceeds the timeout.
    """
    process = None
    try:
        print(f"Running command: '{' '.join(command)}' with timeout {timeout_seconds} seconds")
        
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        # Use threads to stream stdout and stderr simultaneously to the script's own streams
        stdout_thread = threading.Thread(target=stream_output, args=(process.stdout, sys.stdout))
        stderr_thread = threading.Thread(target=stream_output, args=(process.stderr, sys.stderr))

        stdout_thread.start()
        stderr_thread.start()

        process.wait(timeout=timeout_seconds)

        # Wait for streaming threads to finish
        stdout_thread.join()
        stderr_thread.join()

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

    cmd_to_run = args.command
    # If running a python script, automatically add the -u flag for unbuffered output
    if cmd_to_run and cmd_to_run[0].endswith('python') and '-u' not in cmd_to_run:
        cmd_to_run.insert(1, '-u')

    run_with_timeout(cmd_to_run, args.timeout)

