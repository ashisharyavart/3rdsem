"""
CyberGuard Desktop - Screen Change Detection Module
Detects visual changes between successive screen captures to avoid redundant OCR.
"""

from typing import Dict, Tuple
import cv2
import numpy as np
from utils.logger import logger


class ScreenChangeDetector:
    """
    Evaluates whether a captured monitor image has changed meaningfully compared
    to the prior capture. Uses downscaling, grayscale conversion, and pixel difference
    thresholds to filter out cursor blinks and micro-jitters.
    """

    def __init__(self, diff_threshold: float = 0.015, downscale_width: int = 640):
        self.diff_threshold = diff_threshold
        self.downscale_width = downscale_width
        self._prev_frames: Dict[int, np.ndarray] = {}

    def _preprocess(self, image_bgr: np.ndarray) -> np.ndarray:
        """Resize, convert to grayscale, and slightly blur to eliminate noise."""
        h, w = image_bgr.shape[:2]
        if w > self.downscale_width:
            new_h = max(1, int(h * (self.downscale_width / w)))
            resized = cv2.resize(image_bgr, (self.downscale_width, new_h), interpolation=cv2.INTER_AREA)
        else:
            resized = image_bgr

        gray = cv2.cvtColor(resized, cv2.COLOR_BGR2GRAY)
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        return blurred

    def has_changed(self, monitor_id: int, image_bgr: np.ndarray) -> Tuple[bool, float]:
        """
        Determines whether the screen has changed significantly.
        Returns:
            (has_changed: bool, diff_ratio: float)
        """
        if image_bgr is None or image_bgr.size == 0:
            return False, 0.0

        current_processed = self._preprocess(image_bgr)

        if monitor_id not in self._prev_frames:
            # First frame for this monitor is always considered changed
            self._prev_frames[monitor_id] = current_processed
            return True, 1.0

        prev_processed = self._prev_frames[monitor_id]

        # In case monitor dimensions changed
        if prev_processed.shape != current_processed.shape:
            self._prev_frames[monitor_id] = current_processed
            return True, 1.0

        # Compute absolute difference
        diff = cv2.absdiff(prev_processed, current_processed)

        # Threshold difference: ignore tiny intensity changes (< 25)
        _, thresh = cv2.threshold(diff, 25, 255, cv2.THRESH_BINARY)
        changed_pixels = np.count_nonzero(thresh)
        total_pixels = thresh.size
        diff_ratio = changed_pixels / float(total_pixels)

        if diff_ratio >= self.diff_threshold:
            self._prev_frames[monitor_id] = current_processed
            return True, diff_ratio

        return False, diff_ratio

    def force_update(self, monitor_id: int, image_bgr: np.ndarray):
        """Force update the baseline without reporting change."""
        self._prev_frames[monitor_id] = self._preprocess(image_bgr)

    def reset(self):
        """Reset previous frame history (e.g. when monitoring stops or restarts)."""
        self._prev_frames.clear()

