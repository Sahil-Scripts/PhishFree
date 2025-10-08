
import sys
import json
import struct
print("Python bitness:", struct.calcsize("P")*8, "bit")
try:
    import torch
    print("torch:", torch.__version__, "cuda:", torch.version.cuda)
except Exception as e:
    print("torch import FAILED:", e)
try:
    import torch_geometric
    print("torch_geometric imported OK:", getattr(torch_geometric, "__version__", "unknown"))
    from torch_geometric.data import Data
    print("torch_geometric.Data OK")
except Exception as e:
    print("torch_geometric import FAILED:", e)
    raise

