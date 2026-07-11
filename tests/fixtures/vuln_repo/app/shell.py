import subprocess


def list_directory(path: str) -> str:
    cmd = f"ls -la {path}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
