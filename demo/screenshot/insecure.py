import subprocess
import os

def run_command(user_input):
    subprocess.run(user_input, shell=True)

def get_user():
    exec(os.environ.get("USER_CODE", ""))
