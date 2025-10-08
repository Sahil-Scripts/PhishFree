# install_pyg.py
# Run this inside your activated venv with: python install_pyg.py
# It will detect installed torch/cuda and attempt to install matching torch-geometric wheels.

import json, subprocess, sys, shutil, os

def run(cmd):
    print(">>>", " ".join(cmd))
    res = subprocess.run(cmd, shell=False)
    if res.returncode != 0:
        raise SystemExit(f"Command failed: {' '.join(cmd)} (exit {res.returncode})")

def python_json(code):
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()

def detect_torch():
    pycode = r'''
import json
try:
    import torch
    v = str(torch.__version__)
    c = str(torch.version.cuda) if torch.version.cuda is not None else "none"
except Exception as e:
    v = None
    c = None
print(json.dumps({"torch_version": v, "cuda_version": c}))
'''
    out = python_json(pycode)
    if not out:
        return None, None
    info = json.loads(out)
    return info.get("torch_version"), info.get("cuda_version")

def pip_install(pkgs):
    for p in pkgs:
        run([sys.executable, "-m", "pip", "install", "--upgrade", p])

def install_pyg_wheels(torch_ver, cuda_ver):
    base_ver = torch_ver.split("+")[0]
    if cuda_ver and cuda_ver != "none":
        cu_tag = "cu" + cuda_ver.replace(".", "")
        torch_tag = f"{base_ver}+{cu_tag}"
    else:
        torch_tag = base_ver
    wheel_index = f"https://data.pyg.org/whl/torch-{torch_tag}.html"
    print("Using PYG wheel index:", wheel_index)
    seq = ["torch-scatter", "torch-sparse", "torch-cluster", "torch-spline-conv", "torch-geometric"]
    for pkg in seq:
        print(f"Installing {pkg} ...")
        run([sys.executable, "-m", "pip", "install", pkg, "-f", wheel_index])

def verify():
    code = r'''
try:
    import torch, torch_geometric
    print("torch:", torch.__version__, "cuda:", torch.version.cuda)
    import torch_geometric
    print("torch_geometric OK")
except Exception as e:
    print("ERROR", e)
    raise
'''
    run([sys.executable, "-c", code])

def main():
    print("Detecting torch...")
    torch_ver, cuda_ver = detect_torch()
    print("Detected:", torch_ver, cuda_ver)
    if not torch_ver:
        print("Torch not found. Installing CPU-only torch+vision+audio (will be used if you don't need GPU).")
        pip_install(["--upgrade pip", "setuptools", "wheel"])
        run([sys.executable, "-m", "pip", "install", "--index-url", "https://download.pytorch.org/whl/cpu", "torch", "torchvision", "torchaudio"])
        torch_ver, cuda_ver = detect_torch()
        print("Now detected:", torch_ver, cuda_ver)
        if not torch_ver:
            raise SystemExit("Failed to install torch automatically; please install manually per https://pytorch.org")

    print("Installing PyG wheels for torch tag...")
    install_pyg_wheels(torch_ver, cuda_ver)
    print("Verifying installation...")
    verify()
    print("Done. Restart your Python process/IDE and run your app.")

if __name__ == "__main__":
    main()
