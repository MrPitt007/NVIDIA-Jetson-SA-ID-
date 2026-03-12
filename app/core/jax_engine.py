# SAFE JAX ENGINE FOR WINDOWS — NO JAX REQUIRED

import numpy as np
import asyncio

class DummyEngine:
    def run_liveness(self, frame):
        # Simulation mode: always return "live"
        return True, "live", 0.99

    def run_face_embed(self, img):
        # Return a simple deterministic embedding
        return np.zeros(128, dtype=np.float32)

    def run_cosine_match(self, emb_live, emb_doc):
        # Always match with high confidence
        return True, 0.90

async def warm_up_jax():
    # No-op warmup for development
    await asyncio.sleep(0)

engine = DummyEngine()