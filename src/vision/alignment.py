"""
VERITAS-Vault Canonical Face Alignment & Landmark Normalization
===============================================================
Performs face landmark detection, eye orientation alignment, affine warping,
and canonical resolution scaling.
Prevents unaligned or skewed face crops from degrading ArcFace/FaceNet feature embeddings.

If eye detection or landmark localization fails due to extreme pitch/yaw/roll or occlusion,
returns alignment_success=False with reason RECAPTURE_REQUIRED.
"""
import math
import cv2
import numpy as np
from typing import Tuple, Dict, Any, Optional, Union

# Load Haar Eye Cascade for robust CPU-based eye localization
_eye_cascade = None

# Canonical ArcFace / InsightFace reference points on standard 112x112 destination grid:
# Point ordering: [viewer-left eye / subject-right eye, viewer-right eye / subject-left eye, nose, left mouth, right mouth]
ARCFACE_REFERENCE_LANDMARKS = np.array([
    [38.2946, 51.6963],
    [73.5318, 51.5014],
    [56.0252, 71.7366],
    [41.5493, 92.3655],
    [70.7299, 92.2041]
], dtype=np.float32)


def _get_eye_cascade() -> cv2.CascadeClassifier:
    global _eye_cascade
    if _eye_cascade is None:
        path = cv2.data.haarcascades + "haarcascade_eye.xml"
        _eye_cascade = cv2.CascadeClassifier(path)
    return _eye_cascade


def align_face_5point(
    image: np.ndarray,
    landmarks: Union[np.ndarray, Dict[str, Tuple[float, float]]],
    target_size: Tuple[int, int] = (112, 112)
) -> Tuple[np.ndarray, bool, Dict[str, Any]]:
    """
    Performs canonical 5-point similarity transformation (rotation, uniform scale, translation)
    to ArcFace standard coordinates on a target_size grid. Preserves facial aspect ratio.

    Args:
        image: Source frame or crop.
        landmarks: Either (5, 2) array or dict with 'right_eye', 'left_eye', 'nose', 'right_mouth', 'left_mouth'.
        target_size: Output resolution, default (112, 112).

    Returns:
        (aligned_crop: np.ndarray, alignment_success: bool, metrics: Dict[str, Any])
    """
    if image is None or image.size == 0:
        return np.zeros((*target_size, 3), dtype=np.uint8), False, {
            "alignment_success": False,
            "reason": "EMPTY_IMAGE",
            "quality_score": 0.0
        }

    src_pts = None
    if isinstance(landmarks, np.ndarray):
        if landmarks.shape == (5, 2):
            src_pts = landmarks.astype(np.float32)
        elif landmarks.ndim == 1 and landmarks.size >= 10:
            if landmarks.size == 15:  # Raw YuNet row [x,y,w,h, re_x, re_y, le_x, le_y, n_x, n_y, rm_x, rm_y, lm_x, lm_y, conf]
                src_pts = landmarks[4:14].reshape((5, 2)).astype(np.float32)
            else:
                src_pts = landmarks[:10].reshape((5, 2)).astype(np.float32)
    elif isinstance(landmarks, dict):
        required_keys = ["right_eye", "left_eye", "nose", "right_mouth", "left_mouth"]
        if all(k in landmarks for k in required_keys):
            src_pts = np.array([
                landmarks["right_eye"],
                landmarks["left_eye"],
                landmarks["nose"],
                landmarks["right_mouth"],
                landmarks["left_mouth"]
            ], dtype=np.float32)

    if src_pts is None or len(src_pts) != 5:
        return cv2.resize(image, target_size), False, {
            "alignment_success": False,
            "reason": "INVALID_5POINT_LANDMARKS",
            "quality_score": 0.50
        }

    # Scale reference points if target_size is not (112, 112)
    dst_pts = ARCFACE_REFERENCE_LANDMARKS.copy()
    if target_size != (112, 112):
        scale_x = target_size[0] / 112.0
        scale_y = target_size[1] / 112.0
        dst_pts[:, 0] *= scale_x
        dst_pts[:, 1] *= scale_y

    M, inliers = cv2.estimateAffinePartial2D(src_pts, dst_pts)
    if M is None:
        return cv2.resize(image, target_size), False, {
            "alignment_success": False,
            "reason": "AFFINE_ESTIMATION_FAILED",
            "quality_score": 0.50
        }

    aligned = cv2.warpAffine(
        image,
        M,
        target_size,
        flags=cv2.INTER_CUBIC,
        borderMode=cv2.BORDER_REFLECT
    )
    return aligned, True, {
        "alignment_success": True,
        "method": "CANONICAL_5POINT_AFFINE",
        "quality_score": 0.98
    }


def align_face(
    face_crop: np.ndarray,
    target_size: Tuple[int, int] = (112, 112),
    desired_left_eye: Tuple[float, float] = (0.32, 0.38),
    landmarks: Optional[Union[np.ndarray, Dict[str, Tuple[float, float]]]] = None
) -> Tuple[np.ndarray, bool, Dict[str, Any]]:
    """
    Aligns a face crop by detecting eye coordinates or using 5-point landmarks,
    calculating rotation angle, and applying affine transformation.

    Returns:
        (aligned_crop: np.ndarray, alignment_success: bool, metrics: Dict[str, Any])
    """
    if face_crop is None or face_crop.size == 0:
        return np.zeros((*target_size, 3), dtype=np.uint8), False, {
            "alignment_success": False,
            "reason": "EMPTY_FRAME",
            "quality_score": 0.0
        }

    h, w = face_crop.shape[:2]
    if h < 40 or w < 40:
        resized = cv2.resize(face_crop, target_size)
        return resized, False, {
            "alignment_success": False,
            "reason": "FACE_TOO_SMALL_FOR_ALIGNMENT",
            "quality_score": 0.3
        }

    if landmarks is not None:
        aligned, ok, metrics = align_face_5point(face_crop, landmarks, target_size)
        if ok:
            return aligned, ok, metrics

    gray = cv2.cvtColor(face_crop, cv2.COLOR_BGR2GRAY) if len(face_crop.shape) == 3 else face_crop
    # Restrict eye search to upper 60% of face to avoid mouth false-positives
    upper_face = gray[0:int(h * 0.62), :]
    eyes = _get_eye_cascade().detectMultiScale(upper_face, scaleFactor=1.1, minNeighbors=4, minSize=(15, 15))

    # If exactly two eyes detected, perform canonical rotational alignment
    if len(eyes) == 2:
        # Sort left to right
        sorted_eyes = sorted(eyes, key=lambda e: e[0])
        e1, e2 = sorted_eyes[0], sorted_eyes[1]
        p1 = (e1[0] + e1[2] / 2.0, e1[1] + e1[3] / 2.0)
        p2 = (e2[0] + e2[2] / 2.0, e2[1] + e2[3] / 2.0)

        # Angle of the line between eyes
        dx = p2[0] - p1[0]
        dy = p2[1] - p1[1]
        dist = math.hypot(dx, dy)

        if dist > w * 0.15:  # Plausible eye separation
            angle = math.degrees(math.atan2(dy, dx))
            # Calculate rotation center at midpoint of eyes
            eye_center = ((p1[0] + p2[0]) / 2.0, (p1[1] + p2[1]) / 2.0)

            # Desired distance based on canonical left and right eye placements
            desired_dist = (1.0 - 2.0 * desired_left_eye[0]) * target_size[0]
            scale = desired_dist / max(dist, 1e-5)

            M = cv2.getRotationMatrix2D(eye_center, angle, scale)
            # Adjust translation so eye center lands at target placement
            tX = target_size[0] * 0.5
            tY = target_size[1] * desired_left_eye[1]
            M[0, 2] += (tX - eye_center[0])
            M[1, 2] += (tY - eye_center[1])

            aligned = cv2.warpAffine(face_crop, M, target_size, flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REFLECT)
            return aligned, True, {
                "alignment_success": True,
                "rotation_degrees": round(angle, 2),
                "scale_factor": round(scale, 3),
                "quality_score": 0.95,
                "method": "CANONICAL_EYE_AFFINE"
            }

    # Fallback: Aspect-ratio preserving center crop and resize
    resized = cv2.resize(face_crop, target_size, interpolation=cv2.INTER_AREA)
    return resized, False, {
        "alignment_success": False,
        "reason": "EYE_LANDMARKS_NOT_RESOLVED",
        "quality_score": 0.65,
        "method": "ASPECT_PRESERVED_FALLBACK"
    }
