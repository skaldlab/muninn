import subprocess
import os

def run_command(user_input):
    # semgrep: dangerous subprocess usage
    subprocess.run(user_input, shell=True)

def get_user():
    # semgrep: exec usage
    exec(os.environ.get("USER_CODE", ""))
