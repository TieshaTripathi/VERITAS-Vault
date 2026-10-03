import time
import math
import numpy as np
import pytest
from src.vision.auto_capture import (
    FaceStabilityTracker,
    draw_cyan_target_brackets,
    draw_hud_overlay,
    HUD_SCANNING,
    HUD_FIXATING,
    HUD_VERIFYING,
)


def test_face_stability_tracker_euclidean_distance():
    tracker = FaceStabilityTracker(jitter_threshold=15.0)

    # Centroid 1: (100 + 40, 100 + 40) = (140, 140)
    bbox1 = (100, 100, 80, 80)

    # Centroid 2: (106 + 40, 108 + 40) = (146, 148)
    # dx = 6, dy = 8, Euclidean dist = sqrt(36 + 64) = 10.0 <= 15
    bbox_stable = (106, 108, 80, 80)
    assert tracker.is_stable(bbox1, bbox_stable, threshold=15.0) is True
    assert FaceStabilityTracker.is_stable(bbox1, bbox_stable, threshold=15.0) is True

    # Centroid 3: (120 + 40, 120 + 40) = (160, 160)
    # dx = 20, dy = 20, dist = sqrt(800) ~= 28.28 > 15
    bbox_unstable = (120, 120, 80, 80)
    assert tracker.is_stable(bbox1, bbox_unstable, threshold=15.0) is False
    assert FaceStabilityTracker.is_stable(bbox1, bbox_unstable, threshold=15.0) is False

    # Edge cases
    assert tracker.is_stable(None, bbox1) is False
    assert tracker.is_stable(bbox1, None) is False


def test_face_stability_tracker_fixation_and_cooldown():
    tracker = FaceStabilityTracker(stability_threshold_ms=300.0, jitter_threshold=15.0, cooldown_seconds=2.0)

    bbox1 = (150, 150, 100, 100)
    bbox2 = (152, 151, 100, 100)

    # Initial frame
    assert tracker.check_fixation(bbox1, duration_ms=300.0) is False
    assert tracker.cooldown_active(cooldown_seconds=2.0) is False

    # Immediate second frame (< 300ms)
    assert tracker.check_fixation(bbox2, duration_ms=300.0) is False

    # Wait past 300ms threshold (e.g., 320ms)
    time.sleep(0.32)
    assert tracker.check_fixation(bbox2, duration_ms=300.0) is True

    # Trigger capture and verify cooldown
    tracker.record_capture()
    assert tracker.cooldown_active(cooldown_seconds=2.0) is True
    # Fixation timer was reset
    assert tracker.fixation_start_time is None

    # Status under cooldown
    status, _ = tracker.get_hud_status(bbox2)
    assert "COOLDOWN" in status


def test_face_stability_tracker_movement_resets_fixation():
    tracker = FaceStabilityTracker(stability_threshold_ms=300.0, jitter_threshold=15.0)

    bbox_center = (100, 100, 60, 60)
    tracker.check_fixation(bbox_center)
    time.sleep(0.15)

    # Big sudden jump (> 15px centroid delta)
    bbox_jump = (200, 200, 60, 60)
    assert tracker.check_fixation(bbox_jump, duration_ms=300.0) is False

    # Wait another 0.20s (total elapsed > 300ms from start, but since jump it is only 0.20s)
    time.sleep(0.20)
    assert tracker.check_fixation(bbox_jump, duration_ms=300.0) is False

    # Wait remaining time for the new position (> 300ms from jump)
    time.sleep(0.15)
    assert tracker.check_fixation(bbox_jump, duration_ms=300.0) is True


def test_hud_drawing_brackets_and_overlay():
    img = np.zeros((480, 640, 3), dtype=np.uint8)
    bbox = (100, 80, 120, 140)

    # Draw cyan brackets
    img_bracket = draw_cyan_target_brackets(img.copy(), bbox, color=(255, 255, 0), thickness=2)
    # Check that cyan pixels exist (B=255, G=255, R=0)
    assert np.any((img_bracket[:, :, 0] == 255) & (img_bracket[:, :, 1] == 255))

    # Draw HUD overlay
    img_hud = draw_hud_overlay(img.copy(), HUD_SCANNING, color=(255, 255, 0), progress=0.5)
    assert img_hud.shape == img.shape
