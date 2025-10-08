"""
backend/cnn_model.py

Adjusted CLIP-based visual phishing detector using Hugging Face CLIPModel + CLIPProcessor.
Replaces the OpenAI `clip` dependency with the HF `transformers` implementation for easier
installation on Windows/venv environments.

Features:
- HF CLIP embeddings (ViT-B/32) + a trainable MLP head for supervised phish/benign classification
- Optional contrastive anchor loss to improve embedding robustness
- Mixed-precision training using torch.cuda.amp
- Simple manual batching (compatible with HF CLIP processor)
- Brand template embedding computation and similarity scoring
- TorchScript export helper (best-effort; may fail for some HF models — guarded)

Dependencies:
    pip install torch torchvision torchaudio  # use the correct CUDA/CPU wheel
    pip install transformers sentence-transformers ftfy regex tqdm pillow scikit-learn numpy

Usage:
    Drop this file into backend/cnn_model.py and import CNNModel in your app.
    Ensure transformers and torch are installed in your venv.

Author: ChatGPT (adapted to HF CLIP)
"""
from __future__ import annotations

import os
import io
import math
import time
import json
from typing import List, Dict, Optional, Any, Tuple

import numpy as np
from PIL import Image
from tqdm import tqdm

import torch
from torch import nn

from sklearn.metrics import roc_auc_score

from transformers import CLIPProcessor, CLIPModel

# -------------------------
# Global HF CLIP load (one-time)
# -------------------------
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
HF_CLIP_MODEL_NAME = "openai/clip-vit-base-patch32"

print(f"[CNNModel] Loading HF CLIP model '{HF_CLIP_MODEL_NAME}' on {DEVICE} ...")
_hf_clip_model = CLIPModel.from_pretrained(HF_CLIP_MODEL_NAME).to(DEVICE)
_hf_clip_processor = CLIPProcessor.from_pretrained(HF_CLIP_MODEL_NAME)
_hf_clip_model.eval()

# Determine embed dim robustly
try:
    CLIP_EMBED_DIM = _hf_clip_model.config.projection_dim
except Exception:
    # fallback by running a dummy forward
    with torch.no_grad():
        dummy = _hf_clip_model.get_image_features(
            **_hf_clip_processor(images=Image.new("RGB", (224, 224)), return_tensors="pt").to(DEVICE)
        )
    CLIP_EMBED_DIM = dummy.shape[-1]

print(f"[CNNModel] CLIP embed dim: {CLIP_EMBED_DIM}")

# -------------------------
# Lightweight record structure (not strict dataclass to keep compatibility)
# Each record: {"image_path": str, "label": 0|1, "anchor_path": Optional[str]}
# -------------------------
# Note: For simplicity and Windows compatibility we avoid using DataLoader with complex tensor collate;
# we batch manually via list slicing and HF processor.
# -------------------------


# -------------------------
# MLP head
# -------------------------
class HeadMLP(nn.Module):
    def __init__(self, embed_dim: int = CLIP_EMBED_DIM, hidden: int = 256, dropout: float = 0.2):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(embed_dim, hidden),
            nn.LayerNorm(hidden),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden, hidden // 2),
            nn.ReLU(),
            nn.Dropout(dropout * 0.5),
            nn.Linear(hidden // 2, 1)  # logits
        )

    def forward(self, emb: torch.Tensor) -> torch.Tensor:
        return self.net(emb).squeeze(-1)


# -------------------------
# Main wrapper class (keeps API similar to earlier CNNModel)
# -------------------------
class CNNModel:
    def __init__(self,
                 device: Optional[str] = None,
                 clip_model_name: str = HF_CLIP_MODEL_NAME,
                 head_ckpt: Optional[str] = None,
                 brand_templates: Optional[Dict[str, np.ndarray]] = None):
        """
        device: 'cuda' or 'cpu' or None to auto-select
        clip_model_name: HF CLIP model id
        head_ckpt: optional path to MLP head checkpoint (torch)
        brand_templates: dict {brand_name: np.array(embedding)} normalized
        """
        self.device = device or DEVICE
        # use the pre-loaded global hf clip model + processor
        self.clip_model = _hf_clip_model
        self.clip_processor = _hf_clip_processor
        self.clip_model.eval()

        # head
        embed_dim = CLIP_EMBED_DIM
        self.head = HeadMLP(embed_dim=embed_dim).to(self.device)
        if head_ckpt and os.path.exists(head_ckpt):
            try:
                self.head.load_state_dict(torch.load(head_ckpt, map_location=self.device))
                print(f"[CNNModel] Loaded head checkpoint from {head_ckpt}")
            except Exception as ex:
                print("[CNNModel] Failed to load head checkpoint:", ex)

        self.criterion_bce = nn.BCEWithLogitsLoss()
        self.brand_templates = brand_templates or {}
        self.temp = 0.07  # contrastive temperature

    # -------------------------
    # Embedding helpers (numpy in / numpy out)
    # -------------------------
    def embed_pil(self, pil: Image.Image) -> np.ndarray:
        """
        Compute normalized CLIP embedding for a PIL image; returns numpy vector.
        """
        inputs = self.clip_processor(images=pil, return_tensors="pt")
        # move tensors to device
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        with torch.no_grad():
            img_emb = self.clip_model.get_image_features(**inputs)  # [1, D]
            img_emb = img_emb / img_emb.norm(p=2, dim=-1, keepdim=True)
        return img_emb.squeeze(0).cpu().numpy()

    def embed_from_path(self, path: str) -> np.ndarray:
        pil = Image.open(path).convert("RGB")
        return self.embed_pil(pil)

    def embed_from_bytes(self, image_bytes: bytes) -> np.ndarray:
        pil = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        return self.embed_pil(pil)

    # -------------------------
    # Predict / inference helpers
    # -------------------------
    def predict_from_pil(self, pil: Image.Image) -> Dict[str, Any]:
        """
        Returns {'score': float (0..1), 'best_brand': str, 'best_sim': float, 'sims': dict}
        """
        self.clip_model.eval()
        self.head.eval()
        # embed via HF
        emb_np = self.embed_pil(pil)
        # convert to tensor for head
        emb_t = torch.tensor(emb_np, dtype=torch.float32).unsqueeze(0).to(self.device)
        with torch.no_grad():
            logits = self.head(emb_t).squeeze(-1)
            prob = float(torch.sigmoid(logits).cpu().numpy())
        sims = {}
        for b, ve in (self.brand_templates or {}).items():
            sims[b] = float(np.dot(emb_np, ve))
        if sims:
            best_brand, best_sim = max(sims.items(), key=lambda kv: kv[1])
        else:
            best_brand, best_sim = "", 0.0
        return {"score": prob, "best_brand": best_brand, "best_sim": best_sim, "sims": sims}

    def predict_from_bytes(self, image_bytes: bytes) -> Dict[str, Any]:
        pil = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        return self.predict_from_pil(pil)

    # -------------------------
    # Compute brand template embeddings from directory
    # -------------------------
    def compute_brand_embeddings(self, templates_dir: str, normalize: bool = True) -> Dict[str, np.ndarray]:
        """
        Loads images in templates_dir and computes CLIP embeddings.
        Template filename (without extension) used as brand name.
        """
        templates = {}
        if not os.path.isdir(templates_dir):
            raise FileNotFoundError(f"Templates directory not found: {templates_dir}")
        files = [f for f in os.listdir(templates_dir) if os.path.isfile(os.path.join(templates_dir, f))]
        for fn in tqdm(files, desc="Computing brand templates"):
            p = os.path.join(templates_dir, fn)
            try:
                emb = self.embed_from_path(p)
                if normalize:
                    norm = np.linalg.norm(emb)
                    if norm > 0:
                        emb = emb / norm
                name = os.path.splitext(fn)[0]
                templates[name] = emb
            except Exception as ex:
                print("[CNNModel] Failed to compute template for", p, ex)
        self.brand_templates = templates
        return templates

    # -------------------------
    # Training loop (manual batching)
    # -------------------------
    def train_loop(self,
                   train_records: List[Dict[str, Any]],
                   val_records: Optional[List[Dict[str, Any]]] = None,
                   out_dir: str = "./cnn_ckpt",
                   epochs: int = 8,
                   batch_size: int = 32,
                   lr: float = 3e-4,
                   weight_decay: float = 1e-5,
                   use_contrastive: bool = True,
                   grad_accum: int = 1,
                   max_grad_norm: float = 1.0):
        """
        train_records: list of dicts {"image_path":..., "label":0/1, "anchor_path": optional}
        val_records: same structure (optional)
        Manual batching is used to leverage HF clip processor for image batches.
        """
        os.makedirs(out_dir, exist_ok=True)
        opt = torch.optim.AdamW(self.head.parameters(), lr=lr, weight_decay=weight_decay)
        total_steps = max(1, (len(train_records) * epochs) // batch_size)
        warmup_steps = max(1, int(0.03 * total_steps))
        def lr_lambda(step):
            if step < warmup_steps:
                return float(step) / float(max(1, warmup_steps))
            progress = float(step - warmup_steps) / float(max(1, total_steps - warmup_steps))
            return max(0.0, 0.5 * (1.0 + math.cos(math.pi * progress)))
        scheduler = torch.optim.lr_scheduler.LambdaLR(opt, lr_lambda)
        scaler = torch.cuda.amp.GradScaler(enabled=(self.device != "cpu"))
        best_auc = 0.0
        global_step = 0

        for epoch in range(1, epochs + 1):
            # shuffle
            indices = np.random.permutation(len(train_records))
            epoch_losses = []
            self.head.train()
            for start in range(0, len(indices), batch_size):
                batch_idx = indices[start:start + batch_size]
                batch_recs = [train_records[i] for i in batch_idx]
                # load images and anchors as lists of PIL images (anchors may be None)
                images = []
                labels = []
                anchors = []
                anchor_valid_flags = []
                for r in batch_recs:
                    try:
                        pil = Image.open(r["image_path"]).convert("RGB")
                    except Exception:
                        # if image fails, use a gray image placeholder
                        pil = Image.new("RGB", (224, 224), (128, 128, 128))
                    images.append(pil)
                    labels.append(float(r.get("label", 0)))
                    a_p = r.get("anchor_path")
                    if a_p:
                        try:
                            a_pil = Image.open(a_p).convert("RGB")
                            anchors.append(a_pil)
                            anchor_valid_flags.append(True)
                        except Exception:
                            anchors.append(None)
                            anchor_valid_flags.append(False)
                    else:
                        anchors.append(None)
                        anchor_valid_flags.append(False)

                # process batch with HF processor -> pixel_values tensor
                inputs = self.clip_processor(images=images, return_tensors="pt")
                pixel_values = inputs["pixel_values"].to(self.device)  # [B,3,H,W]
                labels_t = torch.tensor(labels, dtype=torch.float32, device=self.device)

                with torch.cuda.amp.autocast(enabled=(self.device != "cpu")):
                    # get image embeddings from HF CLIP
                    img_emb = self.clip_model.get_image_features(pixel_values)  # [B, D]
                    img_emb = img_emb / img_emb.norm(p=2, dim=-1, keepdim=True)
                    logits = self.head(img_emb)  # [B]
                    loss = self.criterion_bce(logits.squeeze(-1), labels_t)

                    # contrastive part if anchors available
                    if use_contrastive and any(anchor_valid_flags):
                        # build anchors list in same order for valid indices
                        valid_idxs = [i for i, v in enumerate(anchor_valid_flags) if v]
                        if len(valid_idxs) > 0:
                            anchor_images = [anchors[i] for i in valid_idxs]
                            anchor_inputs = self.clip_processor(images=anchor_images, return_tensors="pt")
                            anchor_pixel_values = anchor_inputs["pixel_values"].to(self.device)
                            anchor_emb = self.clip_model.get_image_features(anchor_pixel_values)
                            anchor_emb = anchor_emb / anchor_emb.norm(p=2, dim=-1, keepdim=True)
                            emb_valid = img_emb[valid_idxs]
                            sim = (emb_valid @ anchor_emb.T) / self.temp  # [V, V]
                            target = torch.arange(sim.size(0), device=self.device)
                            loss_contrast = nn.CrossEntropyLoss()(sim, target)
                            loss = loss + 0.5 * loss_contrast

                scaler.scale(loss / grad_accum).backward()
                if (global_step + 1) % grad_accum == 0:
                    scaler.unscale_(opt)
                    torch.nn.utils.clip_grad_norm_(self.head.parameters(), max_grad_norm)
                    scaler.step(opt)
                    scaler.update()
                    opt.zero_grad()
                    scheduler.step()
                epoch_losses.append(float(loss.item()))
                global_step += 1

            avg_loss = float(np.mean(epoch_losses)) if epoch_losses else 0.0

            # validation
            val_auc = None
            if val_records:
                val_auc = self._evaluate_records(val_records, batch_size=batch_size)
                print(f"[Epoch {epoch}] loss={avg_loss:.4f} val_auc={val_auc:.4f}")
                if val_auc > best_auc:
                    best_auc = val_auc
                    torch.save(self.head.state_dict(), os.path.join(out_dir, "best_head.pth"))
            else:
                print(f"[Epoch {epoch}] loss={avg_loss:.4f}")

        # final save
        torch.save(self.head.state_dict(), os.path.join(out_dir, "last_head.pth"))
        print("[CNNModel] Training complete. Best val AUC:", best_auc)
        return best_auc

    # -------------------------
    # Evaluate helper over record list
    # -------------------------
    def _evaluate_records(self, records: List[Dict[str, Any]], batch_size: int = 32) -> float:
        self.head.eval()
        ys = []
        ps = []
        with torch.no_grad():
            for start in range(0, len(records), batch_size):
                batch = records[start:start + batch_size]
                images = []
                labels = []
                for r in batch:
                    try:
                        pil = Image.open(r["image_path"]).convert("RGB")
                    except Exception:
                        pil = Image.new("RGB", (224, 224), (128, 128, 128))
                    images.append(pil)
                    labels.append(float(r.get("label", 0)))
                inputs = self.clip_processor(images=images, return_tensors="pt")
                pixel_values = inputs["pixel_values"].to(self.device)
                img_emb = self.clip_model.get_image_features(pixel_values)
                img_emb = img_emb / img_emb.norm(p=2, dim=-1, keepdim=True)
                logits = self.head(img_emb).cpu().numpy().squeeze(-1)
                probs = 1.0 / (1.0 + np.exp(-logits))
                ys.extend(labels)
                ps.extend(probs.tolist())
        try:
            auc = roc_auc_score(ys, ps)
        except Exception:
            auc = 0.5
        return auc

    # -------------------------
    # Export to TorchScript (best-effort)
    # -------------------------
    def export_torchscript(self, out_path: str = "./cnn_ts.pt"):
        """
        Attempt to export a wrapper combining the CLIP visual encoder and the head.
        Note: HF CLIP components may not be fully torch.jit-traceable on all platforms.
        """
        class Wrapper(nn.Module):
            def __init__(self, hf_clip_model, head):
                super().__init__()
                # use the visual submodule (backbone) and the projection head
                # HF CLIPModel's visual module is accessible as hf_clip_model.vision_model or visual_model depending on version
                # We'll try multiple attribute names for compatibility.
                if hasattr(hf_clip_model, "vision_model"):
                    self.visual = hf_clip_model.vision_model
                elif hasattr(hf_clip_model, "visual"):
                    self.visual = hf_clip_model.visual
                else:
                    raise RuntimeError("Cannot find visual submodule on HF CLIP model")
                # for HF, get_image_features includes projection; to keep consistent we apply visual then projection if needed
                self.projection = hf_clip_model.visual_projection if hasattr(hf_clip_model, "visual_projection") else None
                self.head = head

            def forward(self, x):
                # x: [B,3,H,W] float tensors normalized as HF processor expects
                # pass through visual; handle cases where visual returns last_hidden_state
                v = self.visual(x)
                # visual output shape may differ; if projection exists, use it
                if self.projection is not None:
                    emb = self.projection(v)
                else:
                    emb = v
                emb = emb / (emb.norm(dim=-1, keepdim=True) + 1e-12)
                logits = self.head(emb)
                probs = torch.sigmoid(logits).squeeze(-1)
                return probs

        print("[CNNModel] Attempting TorchScript export (may fail on some HF builds)...")
        wrapper = Wrapper(self.clip_model, self.head).to(self.device).eval()
        example = torch.randn(1, 3, 224, 224).to(self.device)
        try:
            traced = torch.jit.trace(wrapper, example, check_trace=False)
            traced.save(out_path)
            print("[CNNModel] Saved TorchScript to", out_path)
        except Exception as ex:
            print("[CNNModel] TorchScript export failed:", ex)

# -------------------------
# Simple CLI / example usage
# -------------------------
if __name__ == "__main__":
    print("CNNModel quick test (adapt paths in code).")
    cm = CNNModel()
    # compute templates if directory exists
    templates_dir = "./data/brand_templates"
    if os.path.isdir(templates_dir):
        print("Computing brand templates...")
        cm.compute_brand_embeddings(templates_dir)
        print("Templates:", list(cm.brand_templates.keys())[:10])
    sample_image = "./data/sample_screenshot.png"
    if os.path.exists(sample_image):
        print("Predicting sample image:", sample_image)
        with open(sample_image, "rb") as f:
            b = f.read()
        out = cm.predict_from_bytes(b)
        print("Prediction:", out)
    else:
        print("No sample image found at", sample_image, " — place one to test predict_from_bytes().")
