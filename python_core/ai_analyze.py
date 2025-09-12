import sys
import json
import cv2
from datetime import datetime, timezone

# Usage: ai_analyze.py <image_path> <ip> <alerts_log_path> <analysis_json_path>

def iso_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def main():
    if len(sys.argv) < 5:
        print("[AI] Usage: ai_analyze.py <image> <ip> <alerts_log> <analysis_json>")
        return 2
    img_path, ip, alerts_log, analysis_json = sys.argv[1:5]

    img = cv2.imread(img_path, 0)
    if img is None:
        print("[AI] Could not read image", file=sys.stderr)
        return 1

    _, th = cv2.threshold(img, 200, 255, cv2.THRESH_BINARY)
    ir_count = int(cv2.countNonZero(th))

    contours, _ = cv2.findContours(th, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    motion_areas = sum(1 for c in contours if cv2.contourArea(c) > 100)

    brightness = float(cv2.mean(img)[0])

    analysis = {
        "ip": ip,
        "timestamp": iso_now(),
        "ir_spots": ir_count,
        "motion_areas": int(motion_areas),
        "brightness": round(brightness, 2),
        "image_path": img_path,
    }

    alerts = []
    if ir_count > 50:
        alerts.append(f"IR spots detected ({ir_count}px) - Night vision likely")
    if motion_areas > 5:
        alerts.append(f"Multiple motion areas ({motion_areas}) - Active scene")
    if brightness < 50:
        alerts.append("Low light - IR camera may be active")

    with open(analysis_json, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2)

    if alerts:
        with open(alerts_log, 'a', encoding='utf-8') as af:
            for m in alerts:
                af.write(json.dumps({
                    "type": "ai_notice",
                    "timestamp": iso_now(),
                    "ip": ip,
                    "message": m,
                }) + "\n")
        for m in alerts:
            print(f"[AI] {m}")

if __name__ == "__main__":
    sys.exit(main())
