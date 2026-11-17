"""
CyberGuard Desktop - Multi-Monitor Screen Capture Module
Uses MSS to capture all connected displays in-memory without disk writes.
"""

from typing import List, Dict, Any, Optional
import mss
import numpy as np
import cv2
from utils.logger import logger


class ScreenCaptureManager:
    """
    Manages capturing all connected monitors using MSS.
    Reuses the MSS context to minimize overhead.
    """

    def __init__(self):
        self._sct: Optional[mss.mss] = None
        self._last_error_time: float = 0.0

    def _ensure_sct(self) -> mss.mss:
        if self._sct is None:
            self._sct = mss.mss()
        return self._sct

    def get_monitors(self) -> List[Dict[str, int]]:
        """
        Return the list of individual physical monitors (excluding the index-0 virtual desktop).
        """
        sct = self._ensure_sct()
        monitors = sct.monitors
        if len(monitors) > 1:
            return monitors[1:]
        return monitors[:1]

    def get_monitor_count(self) -> int:
        """
        Return count of physical monitors detected.
        """
        monitors = self.get_monitors()
        return len(monitors)

    def capture_all_monitors(self) -> List[Dict[str, Any]]:
        """
        Captures each connected monitor individually.
        Returns a list of dictionaries:
        [
            {
                "monitor_id": 1,
                "rect": {"left": 0, "top": 0, "width": 1920, "height": 1080},
                "image_bgr": np.ndarray (OpenCV format)
            },
            ...
        ]
        All captures remain strictly in-memory.
        """
        sct = self._ensure_sct()
        monitors = sct.monitors
        results = []

        # If multiple monitors exist, sct.monitors[0] is the virtual combination.
        # We capture monitors[1:] so each screen is analyzed with accurate resolution.
        target_monitors = monitors[1:] if len(monitors) > 1 else monitors

        for idx, mon in enumerate(target_monitors, start=1):
            try:
                sct_img = sct.grab(mon)
                # Convert MSS BGRA to standard BGR for OpenCV
                img_bgra = np.array(sct_img, dtype=np.uint8)
                img_bgr = cv2.cvtColor(img_bgra, cv2.COLOR_BGRA2BGR)

                results.append({
                    "monitor_id": idx,
                    "rect": mon,
                    "image_bgr": img_bgr
                })
            except Exception as e:
                import time
                now = time.time()
                if now - self._last_error_time > 10.0:
                    logger.error(f"Error capturing monitor {idx}: {e}")
                    self._last_error_time = now

        return results

    def close(self):
        if self._sct is not None:
            try:
                self._sct.close()
            except Exception:
                pass
            self._sct = None

