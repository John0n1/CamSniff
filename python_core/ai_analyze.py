import sys
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
import cv2
import numpy as np
from datetime import datetime, timezone

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s %(asctime)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

def iso_now() -> str:
    """Return current timestamp in ISO format."""
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def analyze_image(img_path: str, ip: str) -> Optional[Dict[str, Any]]:
    """
    Analyze camera image for security indicators.
    
    Args:
        img_path: Path to image file
        ip: IP address of camera
        
    Returns:
        Analysis results dictionary or None if analysis fails
    """
    try:
        img = cv2.imread(img_path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            logger.error("Could not read image: %s", img_path)
            return None

        # Threshold for IR spot detection
        _, th = cv2.threshold(img, 200, 255, cv2.THRESH_BINARY)
        ir_count = int(cv2.countNonZero(th))

        # Motion area detection
        contours, _ = cv2.findContours(th, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        motion_areas = sum(1 for c in contours if cv2.contourArea(c) > 100)

        # Brightness analysis
        brightness = float(cv2.mean(img)[0])

        return {
            "ip": ip,
            "timestamp": iso_now(),
            "ir_spots": ir_count,
            "motion_areas": int(motion_areas),
            "brightness": round(brightness, 2),
            "image_path": img_path,
        }
    except Exception as e:
        logger.error("Error analyzing image %s: %s", img_path, e)
        return None

def generate_alerts(analysis: Dict[str, Any]) -> List[str]:
    """Generate security alerts based on analysis results."""
    alerts = []
    ir_count = analysis.get("ir_spots", 0)
    motion_areas = analysis.get("motion_areas", 0)
    brightness = analysis.get("brightness", 0)
    
    if ir_count > 50:
        alerts.append(f"IR spots detected ({ir_count}px) - Night vision likely")
    if motion_areas > 5:
        alerts.append(f"Multiple motion areas ({motion_areas}) - Active scene")
    if brightness < 50:
        alerts.append("Low light - IR camera may be active")
        
    return alerts

def main() -> int:
    """Main entry point for AI analysis."""
    if len(sys.argv) < 5:
        logger.error("Usage: ai_analyze.py <image> <ip> <alerts_log> <analysis_json>")
        return 2
    
    img_path, ip, alerts_log, analysis_json = sys.argv[1:5]
    
    # Validate input files exist
    if not Path(img_path).exists():
        logger.error("Image file does not exist: %s", img_path)
        return 1
    
    analysis = analyze_image(img_path, ip)
    if analysis is None:
        return 1

    # Save analysis results
    try:
        with open(analysis_json, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2)
        logger.info("Analysis saved to: %s", analysis_json)
    except Exception as e:
        logger.error("Failed to save analysis: %s", e)
        return 1

    # Generate and save alerts
    alerts = generate_alerts(analysis)
    if alerts:
        try:
            with open(alerts_log, 'a', encoding='utf-8') as af:
                for alert in alerts:
                    af.write(json.dumps({
                        "type": "ai_notice",
                        "timestamp": iso_now(),
                        "ip": ip,
                        "message": alert,
                    }) + "\n")
            
            for alert in alerts:
                logger.info("AI Alert: %s", alert)
        except Exception as e:
            logger.error("Failed to save alerts: %s", e)
            return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
