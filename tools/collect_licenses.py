"""Bundle required notices from the exact resolved dependency sources."""
import json
import pathlib
import sys

metadata = json.load(sys.stdin)
output = []
missing = []
for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
    if package["name"] == "passwords-keeper":
        continue
    root = pathlib.Path(package["manifest_path"]).parent
    candidates = sorted(
        p for p in root.iterdir()
        if p.is_file() and p.name.lower().startswith(("license", "licence", "copying", "notice", "unlicense"))
    )
    if package.get("license_file"):
        extra = root / package["license_file"]
        if extra.is_file() and extra not in candidates:
            candidates.append(extra)
    if not candidates:
        family = "egui" if package["name"] in {"ecolor", "egui", "egui-winit", "emath", "epaint", "epaint_default_fonts"} else package["name"]
        fallback = pathlib.Path("assets/licenses") / family
        if fallback.is_dir():
            candidates.extend(sorted(p for p in fallback.iterdir() if p.is_file()))
        if package["name"] == "constify":
            sibling = root.parent / "egui_software_backend-0.0.2"
            candidates.extend(sorted(p for p in sibling.glob("LICENSE*")))
    if package["name"] == "epaint_default_fonts":
        candidates.extend(sorted((root / "fonts").glob("*.txt")))
    if not candidates:
        missing.append(package["name"] + " " + package["version"])
    output.append(f"{package['name']} {package['version']} ({package.get('license', 'see license below')})\n")
    for path in candidates:
        output.append(path.read_text(encoding="utf-8", errors="replace"))
    output.append("\n" + "=" * 76 + "\n")

if missing:
    print("Missing license files: " + ", ".join(missing), file=sys.stderr)
    sys.exit(1)
pathlib.Path("assets/third-party-licenses.txt").write_text("\n".join(output), encoding="utf-8")
print(f"Bundled notices for {len(output) // 3} dependency packages.")
