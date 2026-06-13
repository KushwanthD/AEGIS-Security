import subprocess

result = subprocess.run(
    ["nmap", "-F", "localhost"],
    capture_output=True,
    text=True
)

output = result.stdout

print(output)

for line in output.splitlines():

    if "/tcp" in line and "open" in line:

        parts = line.split()

        port = parts[0]
        service = parts[2]

        print(
            f"OPEN PORT FOUND: {port} ({service})"
        )
