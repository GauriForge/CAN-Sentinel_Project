"""
CAN-Sentinel - CAN ID Mapping Module

Maps CAN IDs to their corresponding vehicle message
and ECU information.
"""


# CAN ID mapping
CAN_MESSAGES = {
    0x100: {
        "name": "Engine RPM",
        "ecu": "Engine ECU",
        "description": "Engine rotational speed"
    },

    0x101: {
        "name": "Vehicle Speed",
        "ecu": "Transmission ECU",
        "description": "Vehicle speed"
    },

    0x102: {
        "name": "Engine Temperature",
        "ecu": "Engine ECU",
        "description": "Engine coolant temperature"
    },

    0x103: {
        "name": "Brake Status",
        "ecu": "Brake ECU",
        "description": "Brake system status"
    },

    0x104: {
        "name": "Steering Angle",
        "ecu": "Steering ECU",
        "description": "Steering wheel angle"
    }
}


# ------------------------------------------------------------
# Mapping functions
# ------------------------------------------------------------

def get_message_info(can_id):
    """Return complete information for a CAN ID."""

    try:
        if isinstance(can_id, str):
            can_id = can_id.strip()

            if can_id.lower().startswith("0x"):
                can_id = int(can_id, 16)
            else:
                can_id = int(can_id)

        return CAN_MESSAGES.get(
            can_id,
            {
                "name": "Unknown",
                "ecu": "Unknown ECU",
                "description": "Unknown CAN message"
            }
        )

    except (ValueError, TypeError):
        return {
            "name": "Unknown",
            "ecu": "Unknown ECU",
            "description": "Invalid CAN ID"
        }


def get_ecu_name(can_id):
    """Return the ECU associated with a CAN ID."""

    return get_message_info(can_id)["ecu"]


def get_message_name(can_id):
    """Return the message name associated with a CAN ID."""

    return get_message_info(can_id)["name"]


def get_message_description(can_id):
    """Return the description associated with a CAN ID."""

    return get_message_info(can_id)["description"]


# ------------------------------------------------------------
# Program entry point
# ------------------------------------------------------------

if __name__ == "__main__":

    print("=" * 60)
    print("CAN-Sentinel CAN ID Mapping")
    print("=" * 60)

    for can_id, information in CAN_MESSAGES.items():

        print(
            f"0x{can_id:03X} | "
            f"{information['name']} | "
            f"{information['ecu']}"
        )