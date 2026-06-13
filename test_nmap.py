import subprocess

result = subprocess.run(
    ["nmap", "-F", "scanme.nmap.org"],
    capture_output=True,
    text=True
)

print(result.stdout)
