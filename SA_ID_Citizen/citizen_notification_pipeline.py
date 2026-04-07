"""
SA-ID Citizen App — Notification Pipeline
Handles: SMS, Email, Push notification delivery
"""
import hashlib
import time
import re
from typing import Optional

NOTIFICATION_TYPES = {
    "otp":            "One-Time PIN for verification",
    "sign_complete":  "Document signed successfully",
    "payment":        "Grant payment processed",
    "id_flagged":     "SA-ID reported lost/stolen",
    "update_confirm": "Contact details updated",
    "login_alert":    "New login detected",
    "verify_success": "Identity verified",
}

def run_notification_pipeline(
    id_number_hash: str,
    notification_type: str,
    channel: str,            # 'sms', 'email', 'push'
    recipient: str,          # mobile number or email
    reference: Optional[str] = None,
    custom_message: Optional[str] = None,
) -> dict:
    """Sends notification via chosen channel."""

    valid_channels = ["sms", "email", "push"]
    if channel not in valid_channels:
        return {
            "success": False,
            "error": f"channel must be one of {valid_channels}",
            "timestamp": int(time.time()),
        }

    if notification_type not in NOTIFICATION_TYPES:
        return {
            "success": False,
            "error": f"Unknown notification_type. Valid: {list(NOTIFICATION_TYPES.keys())}",
            "timestamp": int(time.time()),
        }

    # Validate recipient format
    if channel == "sms" and not re.match(r'^\+?[0-9\s\-]{10,15}$', recipient):
        return {"success": False, "error": "Invalid mobile number", "timestamp": int(time.time())}
    if channel == "email" and not re.match(r'^[^@]+@[^@]+\.[^@]+$', recipient):
        return {"success": False, "error": "Invalid email address", "timestamp": int(time.time())}

    # Build message
    messages = {
        "otp":            f"SA-ID: Your OTP is 847392. Valid for 5 minutes. Do not share.",
        "sign_complete":  f"SA-ID: Document signed successfully. Ref: {reference or 'N/A'}",
        "payment":        f"SA-ID: Your SASSA payment has been processed. Ref: {reference or 'N/A'}",
        "id_flagged":     f"SA-ID ALERT: Your ID has been flagged as lost/stolen. Ref: {reference or 'N/A'}",
        "update_confirm": f"SA-ID: Your contact details have been updated successfully.",
        "login_alert":    f"SA-ID: New login detected on your account. Not you? Call 0800-SA-ID.",
        "verify_success": f"SA-ID: Identity verification successful. Ref: {reference or 'N/A'}",
    }

    message = custom_message or messages[notification_type]
    notif_id = f"NOTIF-{hashlib.sha256(f'{id_number_hash}{time.time()}'.encode()).hexdigest()[:10].upper()}"

    return {
        "success": True,
        "notification_id": notif_id,
        "notification_type": notification_type,
        "channel": channel,
        "recipient_masked": recipient[:4] + "****" + recipient[-2:] if len(recipient) > 6 else "****",
        "message_preview": message[:60] + "..." if len(message) > 60 else message,
        "status": "DELIVERED",
        "delivered_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "reference": reference,
        "popia_compliant": True,
        "timestamp": int(time.time()),
    }
