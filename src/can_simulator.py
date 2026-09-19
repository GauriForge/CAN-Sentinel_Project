"""
CAN-Sentinel - CAN Traffic Simulator

This module simulates CAN bus traffic for the CAN-Sentinel project.

It generates:
1. Normal CAN traffic
2. Flooding attack traffic
3. Spoofing attack traffic

The simulator is designed for a virtual CAN interface such as vcan0.
It can also be used in dataset-generation mode, where simulated frames
are written to CSV files.

CAN-ID Mapping:
    0x100 -> Engine RPM
    0x101 -> Vehicle Speed
    0x102 -> Engine Temperature
    0x103 -> Brake Status
    0x104 -> Steering Angle

The module does not interact with a real vehicle or physical ECU.
It is intended only for controlled cybersecurity testing.
"""

import csv
import os
import random
import time
from datetime import datetime

try:
    import can
except ImportError:
    can = None


# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NORMAL_DATASET = os.path.join(
    BASE_DIR,
    "data",
    "normal",
    "normal_dataset.csv"
)

ABNORMAL_DATASET = os.path.join(
    BASE_DIR,
    "data",
    "abnormal",
    "abnormal_dataset.csv"
)


# ---------------------------------------------------------------------------
# CAN message configuration
# ---------------------------------------------------------------------------

CAN_INTERFACE = "vcan0"
CAN_CHANNEL = "vcan0"
CAN_BITRATE = 500000


# CAN IDs used by the simulated vehicle network.
ENGINE_RPM_ID = 0x100
VEHICLE_SPEED_ID = 0x101
ENGINE_TEMP_ID = 0x102
BRAKE_STATUS_ID = 0x103
STEERING_ANGLE_ID = 0x104


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def get_timestamp():
    """
    Return the current timestamp in the same format used by the datasets.
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def rpm_to_payload(rpm):
    """
    Convert RPM into an 8-byte CAN payload.

    The RPM value is stored as a 16-bit unsigned integer in the
    first two bytes.
    """
    rpm = max(0, min(int(rpm), 65535))

    return bytes([
        (rpm >> 8) & 0xFF,
        rpm & 0xFF,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00
    ])


def speed_to_payload(speed):
    """
    Convert vehicle speed into an 8-byte CAN payload.

    Speed is represented using the first byte.
    """
    speed = max(0, min(int(speed), 255))

    return bytes([
        speed,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00
    ])


def temperature_to_payload(temperature):
    """
    Convert engine temperature into an 8-byte CAN payload.

    Temperature is represented using the first byte.
    """
    temperature = max(0, min(int(temperature), 255))

    return bytes([
        temperature,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00
    ])


def brake_to_payload(brake_status):
    """
    Convert brake status into an 8-byte CAN payload.

    0 = brake released
    1 = brake applied
    """
    brake_status = 1 if brake_status else 0

    return bytes([
        brake_status,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00
    ])


def steering_to_payload(angle):
    """
    Convert steering angle into an 8-byte CAN payload.

    The angle is stored as a signed 16-bit value.
    """
    angle = max(-32768, min(int(angle), 32767))

    if angle < 0:
        angle = (1 << 16) + angle

    return bytes([
        (angle >> 8) & 0xFF,
        angle & 0xFF,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00
    ])


def payload_to_string(payload):
    """
    Convert a byte payload into the dataset format.

    Example:
        b'\\x06\\xf0\\x00...' -> '06 F0 00 00 ...'
    """
    return " ".join(f"{byte:02X}" for byte in payload)


# ---------------------------------------------------------------------------
# CAN frame creation
# ---------------------------------------------------------------------------

def create_can_frame(can_id, payload):
    """
    Create a python-can message.

    Returns:
        can.Message or None if python-can is not installed.
    """
    if can is None:
        return None

    return can.Message(
        arbitration_id=can_id,
        data=payload,
        is_extended_id=False
    )


# ---------------------------------------------------------------------------
# Dataset handling
# ---------------------------------------------------------------------------

def save_dataset_row(file_path, timestamp, can_id, payload, label, attack_type):
    """
    Append one simulated CAN frame to a CSV dataset.
    """

    directory = os.path.dirname(file_path)
    os.makedirs(directory, exist_ok=True)

    file_exists = os.path.exists(file_path)

    with open(file_path, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "timestamp",
                "can_id",
                "dlc",
                "payload",
                "label",
                "attack_type"
            ])

        writer.writerow([
            timestamp,
            f"0x{can_id:03X}",
            len(payload),
            payload_to_string(payload),
            label,
            attack_type
        ])


# ---------------------------------------------------------------------------
# CAN bus initialization
# ---------------------------------------------------------------------------

def create_can_bus():
    """
    Connect to the configured virtual CAN interface.

    Returns:
        python-can Bus object.

    Raises:
        RuntimeError if python-can is unavailable or the interface
        cannot be opened.
    """

    if can is None:
        raise RuntimeError(
            "python-can is not installed. "
            "Install it using: pip install python-can"
        )

    try:
        bus = can.Bus(
            interface="socketcan",
            channel=CAN_CHANNEL,
            bitrate=CAN_BITRATE
        )

        print(f"[INFO] Connected to CAN interface: {CAN_INTERFACE}")
        return bus

    except Exception as error:
        raise RuntimeError(
            f"Unable to connect to {CAN_INTERFACE}: {error}"
        )


# ---------------------------------------------------------------------------
# Frame transmission
# ---------------------------------------------------------------------------

def send_frame(bus, can_id, payload, label="normal", attack_type="none",
               save_to_dataset=False, dataset_path=None):
    """
    Send a CAN frame and optionally save it to a dataset.

    This function is shared by normal and abnormal traffic generation.
    """

    timestamp = get_timestamp()

    if bus is not None:
        message = create_can_frame(can_id, payload)

        if message is not None:
            try:
                bus.send(message)
            except Exception as error:
                print(
                    f"[ERROR] Failed to send CAN frame "
                    f"0x{can_id:03X}: {error}"
                )
                return False

    if save_to_dataset and dataset_path:
        save_dataset_row(
            dataset_path,
            timestamp,
            can_id,
            payload,
            label,
            attack_type
        )

    print(
        f"[CAN] {timestamp} | "
        f"ID=0x{can_id:03X} | "
        f"DLC={len(payload)} | "
        f"Payload={payload_to_string(payload)} | "
        f"Label={label} | "
        f"Attack={attack_type}"
    )

    return True


# ---------------------------------------------------------------------------
# Normal traffic simulation
# ---------------------------------------------------------------------------

def generate_normal_traffic(bus=None, duration=10, save_dataset=True):
    """
    Generate realistic periodic normal CAN traffic.

    Simulated signals:
        Engine RPM
        Vehicle Speed
        Engine Temperature
        Brake Status
        Steering Angle

    The generated traffic follows the same CAN-ID structure used
    by the project's normal dataset.
    """

    print("\n[INFO] Starting normal CAN traffic simulation...")
    print(f"[INFO] Duration: {duration} seconds")

    start_time = time.time()

    rpm = 1800
    speed = 40
    temperature = 82
    steering_angle = 5

    while time.time() - start_time < duration:

        # Small variations make the traffic less artificial while
        # keeping values inside a realistic range.
        rpm += random.randint(-80, 80)
        rpm = max(1000, min(rpm, 3000))

        speed += random.randint(-2, 2)
        speed = max(0, min(speed, 100))

        temperature += random.randint(-1, 1)
        temperature = max(75, min(temperature, 100))

        steering_angle += random.randint(-3, 3)
        steering_angle = max(-90, min(steering_angle, 90))

        brake_status = random.choice([0, 0, 0, 1])

        frames = [
            (
                ENGINE_RPM_ID,
                rpm_to_payload(rpm)
            ),
            (
                VEHICLE_SPEED_ID,
                speed_to_payload(speed)
            ),
            (
                ENGINE_TEMP_ID,
                temperature_to_payload(temperature)
            ),
            (
                BRAKE_STATUS_ID,
                brake_to_payload(brake_status)
            ),
            (
                STEERING_ANGLE_ID,
                steering_to_payload(steering_angle)
            )
        ]

        for can_id, payload in frames:

            send_frame(
                bus,
                can_id,
                payload,
                label="normal",
                attack_type="none",
                save_to_dataset=save_dataset,
                dataset_path=NORMAL_DATASET
            )

            time.sleep(0.05)

    print("[INFO] Normal traffic simulation completed.")


# ---------------------------------------------------------------------------
# Flooding attack simulation
# ---------------------------------------------------------------------------

def generate_flooding_attack(
    bus=None,
    duration=5,
    save_dataset=True
):
    """
    Generate a CAN flooding attack.

    The attacker repeatedly transmits a large number of frames
    using the high-priority Engine RPM CAN ID (0x100).

    This creates unusually high message frequency, which can be
    detected by frequency and timing based detection logic.
    """

    print("\n[WARNING] Starting CAN flooding attack simulation...")
    print(f"[INFO] Duration: {duration} seconds")

    start_time = time.time()

    flooding_payload = bytes([
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF
    ])

    while time.time() - start_time < duration:

        send_frame(
            bus,
            ENGINE_RPM_ID,
            flooding_payload,
            label="abnormal",
            attack_type="flooding",
            save_to_dataset=save_dataset,
            dataset_path=ABNORMAL_DATASET
        )

        # Very small delay represents a high-frequency attack.
        time.sleep(0.01)

    print("[WARNING] Flooding attack simulation completed.")


# ---------------------------------------------------------------------------
# Spoofing attack simulation
# ---------------------------------------------------------------------------

def generate_spoofing_attack(
    bus=None,
    duration=5,
    save_dataset=True
):
    """
    Generate a CAN spoofing attack.

    The attacker sends forged Engine RPM messages using CAN ID 0x100.
    The payload contains unusually high RPM values.

    This allows the detection system to examine both:
        - CAN-ID behavior
        - payload/value anomalies
    """

    print("\n[WARNING] Starting CAN spoofing attack simulation...")
    print(f"[INFO] Duration: {duration} seconds")

    start_time = time.time()

    spoofed_rpm_values = [
        8500,
        9000,
        9500,
        10000,
        11000
    ]

    index = 0

    while time.time() - start_time < duration:

        rpm = spoofed_rpm_values[index % len(spoofed_rpm_values)]

        payload = rpm_to_payload(rpm)

        send_frame(
            bus,
            ENGINE_RPM_ID,
            payload,
            label="abnormal",
            attack_type="spoofing",
            save_to_dataset=save_dataset,
            dataset_path=ABNORMAL_DATASET
        )

        index += 1

        # Spoofing is slower than flooding but still abnormal.
        time.sleep(0.12)

    print("[WARNING] Spoofing attack simulation completed.")


# ---------------------------------------------------------------------------
# Combined abnormal traffic simulation
# ---------------------------------------------------------------------------

def generate_abnormal_traffic(
    bus=None,
    flooding_duration=5,
    spoofing_duration=5,
    save_dataset=True
):
    """
    Generate the abnormal traffic scenarios supported by CAN-Sentinel.

    Sequence:
        1. Flooding
        2. Spoofing
    """

    print("\n" + "=" * 70)
    print("CAN-Sentinel Abnormal Traffic Simulation")
    print("=" * 70)

    generate_flooding_attack(
        bus=bus,
        duration=flooding_duration,
        save_dataset=save_dataset
    )

    time.sleep(1)

    generate_spoofing_attack(
        bus=bus,
        duration=spoofing_duration,
        save_dataset=save_dataset
    )

    print("[INFO] Abnormal traffic simulation completed.")


# ---------------------------------------------------------------------------
# Simulation menu
# ---------------------------------------------------------------------------

def run_simulator():
    """
    Main simulator interface.

    The user can choose:
        1. Normal traffic
        2. Flooding attack
        3. Spoofing attack
        4. All scenarios
        5. Exit
    """

    print("\n" + "=" * 70)
    print("              CAN-Sentinel CAN Traffic Simulator")
    print("=" * 70)
    print(f"CAN Interface : {CAN_INTERFACE}")
    print(f"Normal Dataset: {NORMAL_DATASET}")
    print(f"Abnormal Data : {ABNORMAL_DATASET}")
    print("=" * 70)

    try:
        bus = create_can_bus()
    except RuntimeError as error:
        print(f"\n[ERROR] {error}")
        print(
            "\n[INFO] The simulator requires a configured vcan0 "
            "interface for live CAN transmission."
        )
        return

    try:
        while True:

            print("\nSelect simulation mode:")
            print("1. Normal traffic")
            print("2. Flooding attack")
            print("3. Spoofing attack")
            print("4. Run all scenarios")
            print("5. Exit")

            choice = input("\nEnter choice: ").strip()

            if choice == "1":

                generate_normal_traffic(
                    bus=bus,
                    duration=10,
                    save_dataset=True
                )

            elif choice == "2":

                generate_flooding_attack(
                    bus=bus,
                    duration=5,
                    save_dataset=True
                )

            elif choice == "3":

                generate_spoofing_attack(
                    bus=bus,
                    duration=5,
                    save_dataset=True
                )

            elif choice == "4":

                generate_normal_traffic(
                    bus=bus,
                    duration=10,
                    save_dataset=True
                )

                time.sleep(1)

                generate_abnormal_traffic(
                    bus=bus,
                    flooding_duration=5,
                    spoofing_duration=5,
                    save_dataset=True
                )

            elif choice == "5":

                print("[INFO] Exiting CAN simulator.")
                break

            else:

                print("[ERROR] Invalid choice. Please select 1-5.")

    except KeyboardInterrupt:

        print("\n[INFO] Simulator stopped by user.")

    finally:

        try:
            bus.shutdown()
            print("[INFO] CAN interface closed.")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Program entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_simulator()