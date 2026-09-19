"""
CAN-Sentinel - CAN Traffic Sniffer
Captures CAN frames from vcan0 and saves them as structured CSV logs.
"""

import csv
import os
from datetime import datetime

try:
    import can
except ImportError:
    can = None


# Project paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NORMAL_LOG = os.path.join(
    BASE_DIR,
    "data",
    "normal",
    "normal_capture.csv"
)

ABNORMAL_LOG = os.path.join(
    BASE_DIR,
    "data",
    "abnormal",
    "abnormal_capture.csv"
)


# CAN configuration
CAN_CHANNEL = "vcan0"
CAN_INTERFACE = "vcan0"


CSV_COLUMNS = [
    "timestamp",
    "can_id",
    "dlc",
    "payload",
    "label",
    "attack_type"
]


def get_timestamp(timestamp=None):
    """Return timestamp in the project's CSV format."""

    if timestamp is not None:
        try:
            return datetime.fromtimestamp(timestamp).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )[:-3]
        except (TypeError, ValueError, OSError):
            pass

    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )[:-3]


def format_can_id(can_id):
    """Convert CAN ID to hexadecimal format."""

    return f"0x{can_id:03X}"


def format_payload(data):
    """Convert CAN payload bytes to hexadecimal text."""

    return " ".join(f"{byte:02X}" for byte in data)


def create_log_file(file_path):
    """Create the CSV file and header if it does not exist."""

    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    if not os.path.exists(file_path):
        with open(
            file_path,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)
            writer.writerow(CSV_COLUMNS)


def save_frame(
    file_path,
    timestamp,
    can_id,
    dlc,
    payload,
    label,
    attack_type
):
    """Save one CAN frame to the CSV log."""

    create_log_file(file_path)

    with open(
        file_path,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            can_id,
            dlc,
            payload,
            label,
            attack_type
        ])


def connect_to_can():
    """Connect to the vcan0 interface."""

    if can is None:
        raise RuntimeError(
            "python-can is not installed. "
            "Install it using: python -m pip install python-can"
        )

    try:
        bus = can.Bus(
            interface="socketcan",
            channel=CAN_CHANNEL
        )

        print(f"[INFO] Connected to {CAN_INTERFACE}")
        return bus

    except Exception as error:
        raise RuntimeError(
            f"Could not connect to {CAN_INTERFACE}: {error}"
        )


def process_frame(
    message,
    output_file,
    label,
    attack_type
):
    """Process and save one received CAN frame."""

    timestamp = get_timestamp(message.timestamp)

    can_id = format_can_id(
        message.arbitration_id
    )

    dlc = len(message.data)

    payload = format_payload(
        message.data
    )

    save_frame(
        output_file,
        timestamp,
        can_id,
        dlc,
        payload,
        label,
        attack_type
    )

    print(
        f"[CAPTURE] {timestamp} | "
        f"ID={can_id} | "
        f"DLC={dlc} | "
        f"Payload={payload}"
    )


def capture_traffic(
    output_file,
    label="normal",
    attack_type="none",
    duration=30
):
    """Capture CAN traffic for the specified duration."""

    print("\n" + "=" * 65)
    print("CAN-Sentinel CAN Traffic Sniffer")
    print("=" * 65)

    print(f"Interface   : {CAN_INTERFACE}")
    print(f"Output file : {output_file}")
    print(f"Label       : {label}")
    print(f"Attack type : {attack_type}")
    print(f"Duration    : {duration} seconds")
    print("=" * 65)

    try:
        bus = connect_to_can()

    except RuntimeError as error:
        print(f"\n[ERROR] {error}")
        print(
            "[INFO] Live vcan0 capture requires "
            "Linux/Kali with SocketCAN configured."
        )
        return False

    captured_frames = 0

    print("\n[INFO] Listening for CAN traffic...")
    print("[INFO] Press Ctrl+C to stop.\n")

    try:
        while True:

            message = bus.recv(timeout=1.0)

            if message is not None:

                process_frame(
                    message,
                    output_file,
                    label,
                    attack_type
                )

                captured_frames += 1

            if duration > 0:
                # Use the bus timestamp when available, but stop
                # after the requested wall-clock duration.
                if not hasattr(capture_traffic, "_start_time"):
                    capture_traffic.start_time = __import_(
                        "time"
                    ).time()

                elapsed = _import_("time").time() - (
                    capture_traffic._start_time
                )

                if elapsed >= duration:
                    break

    except KeyboardInterrupt:
        print("\n[INFO] Capture stopped by user.")

    finally:
        capture_traffic._start_time = None

        try:
            bus.shutdown()
        except Exception:
            pass

    print("\n[INFO] Capture completed.")
    print(f"[INFO] Frames captured: {captured_frames}")
    print(f"[INFO] Saved to: {output_file}")

    return True


def capture_normal_traffic(duration=30):
    """Capture normal CAN traffic."""

    return capture_traffic(
        output_file=NORMAL_LOG,
        label="normal",
        attack_type="none",
        duration=duration
    )


def capture_abnormal_traffic(
    attack_type="unknown",
    duration=30
):
    """Capture abnormal/test CAN traffic."""

    return capture_traffic(
        output_file=ABNORMAL_LOG,
        label="abnormal",
        attack_type=attack_type,
        duration=duration
    )


def display_log_summary(file_path):
    """Display basic information about a saved CAN log."""

    if not os.path.exists(file_path):
        print(f"\n[ERROR] File not found: {file_path}")
        return

    frame_count = 0
    can_ids = set()

    with open(
        file_path,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            frame_count += 1

            if row.get("can_id"):
                can_ids.add(row["can_id"])

    print("\n" + "=" * 65)
    print("CAN Log Summary")
    print("=" * 65)
    print(f"File         : {file_path}")
    print(f"Total frames : {frame_count}")

    if can_ids:
        print(
            "CAN IDs      : "
            + ", ".join(sorted(can_ids))
        )
    else:
        print("CAN IDs      : None")

    print("=" * 65)


def run_sniffer():
    """Run the interactive sniffer menu."""

    print("\n" + "=" * 65)
    print("             CAN-Sentinel CAN Traffic Sniffer")
    print("=" * 65)

    while True:

        print("\n1. Capture normal traffic")
        print("2. Capture abnormal traffic")
        print("3. View normal log summary")
        print("4. View abnormal log summary")
        print("5. Exit")

        choice = input("\nEnter choice: ").strip()

        if choice == "1":

            duration_input = input(
                "Capture duration in seconds (default 30): "
            ).strip()

            try:
                duration = float(duration_input) if duration_input else 30
            except ValueError:
                duration = 30
                print("[WARNING] Invalid duration. Using 30 seconds.")

            capture_normal_traffic(duration)

        elif choice == "2":

            print("\nAttack types:")
            print("1. flooding")
            print("2. spoofing")
            print("3. other")

            attack_choice = input(
                "Select attack type: "
            ).strip()

            if attack_choice == "1":
                attack_type = "flooding"

            elif attack_choice == "2":
                attack_type = "spoofing"

            elif attack_choice == "3":
                attack_type = input(
                    "Enter attack type: "
                ).strip() or "unknown"

            else:
                attack_type = "unknown"

            duration_input = input(
                "Capture duration in seconds (default 30): "
            ).strip()

            try:
                duration = float(duration_input) if duration_input else 30
            except ValueError:
                duration = 30
                print("[WARNING] Invalid duration. Using 30 seconds.")

            capture_abnormal_traffic(
                attack_type=attack_type,
                duration=duration
            )

        elif choice == "3":

            display_log_summary(NORMAL_LOG)

        elif choice == "4":

            display_log_summary(ABNORMAL_LOG)

        elif choice == "5":

            print("[INFO] Exiting CAN sniffer.")
            break

        else:

            print("[ERROR] Invalid choice. Please select 1-5.")


if __name__ == "__main__":
    run_sniffer()