import docker
client = docker.from_env()
cmd = 'apt-get update -qq 2>&1 | tail -2; apt-get install -y wordlists dirb 2>&1 | tail -5; echo "---WORDLISTS---"; find /usr/share/wordlists -name "*.txt" -type f 2>/dev/null | head -20; echo "---DIRB---"; find /usr/share/dirb -name "*.txt" -type f 2>/dev/null | head -20'
try:
    result = client.containers.run('neuroshell-kali', ['bash', '-c', cmd], remove=True, mem_limit='512m')
    print(result.decode())
except Exception as e:
    print(f"Error: {e}")
