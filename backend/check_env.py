
import importlib, sys
packages = ["torch","torchvision","networkx","node2vec","sklearn","numpy","transformers","requests","web3","PIL"]
for p in packages:
    try:
        m = importlib.import_module(p)
        v = getattr(m, "__version__", "unknown")
        print(f"{p}: installed, version={v}")
    except Exception as e:
        print(f"{p}: NOT available ({type(e).__name__}) -> {e}")
print("python:", sys.version)
try:
    import torch
    print("torch.cuda.is_available:", torch.cuda.is_available())
except Exception as e:
    print("torch import/cuda check failed:", e)



