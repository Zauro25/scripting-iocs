import hashlib
import subprocess
from datetime import datetime
from pathlib import Path


def collect_command(command):
	try:
		result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
		output = result.stdout or result.stderr
		return output.strip() or f"Command selesai dengan kode {result.returncode}."
	except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as error:
		return f"Pengumpulan gagal: {error}"


def collect_autoruns():
	locations = [
		("HKCU", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"),
		("HKCU RunOnce", r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"),
		("HKLM", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"),
		("HKLM RunOnce", r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"),
	]
	sections = []
	for name, key in locations:
		sections.append(f"[{name}]\n{collect_command(["reg", "query", key])}")
	return "\n\n".join(sections)


def sha256_file(path):
	digest = hashlib.sha256()
	with path.open("rb") as input_file:
		for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
			digest.update(chunk)
	return digest.hexdigest()


def main():
	timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
	output_dir = Path(f"triage_{timestamp}")
	output_dir.mkdir()
	commands = {
		"processes.txt": ["powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | Format-List"],
		"network.txt": ["powershell", "-NoProfile", "-Command", "Get-NetTCPConnection; Get-NetUDPEndpoint"],
		"logged_users.txt": ["query", "user"],
	}
	for filename, command in commands.items():
		(output_dir / filename).write_text(collect_command(command) + "\n", encoding="utf-8")
	(output_dir / "autoruns.txt").write_text(collect_autoruns() + "\n", encoding="utf-8")

	output_files = sorted(path for path in output_dir.iterdir() if path.is_file())
	hashes = "\n".join(f"{sha256_file(path)}  {path.name}" for path in output_files)
	(output_dir / "hashes.txt").write_text(hashes + "\n", encoding="utf-8")
	print(f"Triage selesai: {output_dir.resolve()}")


if __name__ == "__main__":
	main()
