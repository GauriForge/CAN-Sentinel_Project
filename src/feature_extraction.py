"""
CAN-Sentinel - Feature Extraction Module

Reads CAN traffic datasets and converts raw CAN frames
into numerical features for anomaly detection.
"""

import os
import pandas as pd


# Project paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NORMAL_FILE = os.path.join(
    BASE_DIR,
    "data",
    "normal",
    "normal_dataset.csv"
)

ABNORMAL_FILE = os.path.join(
    BASE_DIR,
    "data",
    "abnormal",
    "abnormal_dataset.csv"
)

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "models"
)

OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "extracted_features.csv"
)


# ------------------------------------------------------------
# Dataset loading
# ------------------------------------------------------------

def read_dataset(file_path, dataset_name):
    """Read a CAN dataset from CSV."""

    print()
    print(f"Reading {dataset_name} dataset...")
    print(f"File: {file_path}")

    if not os.path.exists(file_path):
        print("Dataset file was not found.")
        return pd.DataFrame()

    try:
        data = pd.read_csv(file_path)

        print(f"Records: {len(data)}")

        return data

    except Exception as error:
        print(f"Error while reading dataset: {error}")
        return pd.DataFrame()


# ------------------------------------------------------------
# CAN ID conversion
# ------------------------------------------------------------

def convert_can_id(value):
    """Convert hexadecimal or decimal CAN ID into an integer."""

    try:
        value = str(value).strip()

        if value.lower().startswith("0x"):
            return int(value, 16)

        return int(float(value))

    except (ValueError, TypeError):
        return 0


# ------------------------------------------------------------
# Payload conversion
# ------------------------------------------------------------

def extract_payload_bytes(payload):
    """
    Convert a payload such as:

        06 F0 00 00 00 00 00 00

    into a list of integer byte values.
    """

    if pd.isna(payload):
        return [0] * 8

    try:
        values = str(payload).strip().split()

        byte_values = []

        for value in values[:8]:
            byte_values.append(int(value, 16))

        while len(byte_values) < 8:
            byte_values.append(0)

        return byte_values

    except (ValueError, TypeError):
        return [0] * 8


# ------------------------------------------------------------
# Feature extraction
# ------------------------------------------------------------

def extract_features(dataframe, label):
    """
    Extract numerical features from CAN traffic.

    Features include:
        - CAN ID
        - DLC
        - payload bytes
        - payload statistics
        - message frequency
        - time interval
        - label
    """

    if dataframe.empty:
        return pd.DataFrame()

    data = dataframe.copy()

    # Ensure required columns exist.
    required_columns = [
        "timestamp",
        "can_id",
        "dlc",
        "payload"
    ]

    for column in required_columns:
        if column not in data.columns:
            print(f"Missing required column: {column}")
            return pd.DataFrame()

    result = pd.DataFrame(index=data.index)

    # --------------------------------------------------------
    # CAN ID
    # --------------------------------------------------------

    result["can_id"] = data["can_id"].apply(
        convert_can_id
    )

    # --------------------------------------------------------
    # DLC
    # --------------------------------------------------------

    result["dlc"] = pd.to_numeric(
        data["dlc"],
        errors="coerce"
    ).fillna(0)

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    timestamps = pd.to_datetime(
        data["timestamp"],
        errors="coerce"
    )

    result["timestamp"] = (
        timestamps.astype("int64") / 1_000_000_000
    ).fillna(0)

    # --------------------------------------------------------
    # Payload bytes
    # --------------------------------------------------------

    payload_bytes = data["payload"].apply(
        extract_payload_bytes
    )

    for index in range(8):
        result[f"byte_{index}"] = payload_bytes.apply(
            lambda values: values[index]
        )

    # --------------------------------------------------------
    # Payload statistics
    # --------------------------------------------------------

    byte_columns = [
        f"byte_{index}"
        for index in range(8)
    ]

    result["payload_sum"] = result[
        byte_columns
    ].sum(axis=1)

    result["payload_mean"] = result[
        byte_columns
    ].mean(axis=1)

    result["payload_max"] = result[
        byte_columns
    ].max(axis=1)

    result["payload_min"] = result[
        byte_columns
    ].min(axis=1)

    # Number of non-zero payload bytes
    result["non_zero_bytes"] = (
        result[byte_columns] != 0
    ).sum(axis=1)

    # --------------------------------------------------------
    # Message frequency
    # --------------------------------------------------------

    result["message_frequency"] = result[
        "can_id"
    ].map(
        result["can_id"].value_counts()
    )

    # --------------------------------------------------------
    # Timing interval
    # --------------------------------------------------------

    result["time_interval"] = (
        result.groupby("can_id")["timestamp"]
        .diff()
        .fillna(0)
    )

    # --------------------------------------------------------
    # Repeated message feature
    # --------------------------------------------------------

    result["repeated_message"] = (
        result["can_id"].eq(
            result["can_id"].shift()
        )
        &
        result["payload_sum"].eq(
            result["payload_sum"].shift()
        )
    ).astype(int)

    # --------------------------------------------------------
    # Label
    # --------------------------------------------------------

    result["label"] = label

    return result


# ------------------------------------------------------------
# Main process
# ------------------------------------------------------------

def main():
    """Run the complete feature extraction process."""

    print()
    print("=" * 60)
    print("CAN-Sentinel Feature Extraction")
    print("=" * 60)

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    # Load datasets
    normal_data = read_dataset(
        NORMAL_FILE,
        "normal"
    )

    abnormal_data = read_dataset(
        ABNORMAL_FILE,
        "abnormal"
    )

    if normal_data.empty:
        print("\nERROR: Normal dataset could not be loaded.")
        return

    if abnormal_data.empty:
        print("\nERROR: Abnormal dataset could not be loaded.")
        return

    # Extract normal features
    print("\nExtracting normal traffic features...")

    normal_features = extract_features(
        normal_data,
        label=0
    )

    print(
        f"Normal feature records: "
        f"{len(normal_features)}"
    )

    # Extract abnormal features
    print("\nExtracting abnormal traffic features...")

    abnormal_features = extract_features(
        abnormal_data,
        label=1
    )

    print(
        f"Abnormal feature records: "
        f"{len(abnormal_features)}"
    )

    if normal_features.empty or abnormal_features.empty:
        print("\nERROR: Feature extraction failed.")
        return

    # Combine datasets
    combined_features = pd.concat(
        [
            normal_features,
            abnormal_features
        ],
        ignore_index=True
    )

    # Replace invalid values
    combined_features = combined_features.replace(
        [float("inf"), float("-inf")],
        0
    )

    combined_features = combined_features.fillna(0)

    # Save features
    try:

        combined_features.to_csv(
            OUTPUT_FILE,
            index=False
        )

    except Exception as error:

        print(
            f"\nERROR: Could not save feature dataset: "
            f"{error}"
        )
        return

    print()
    print("=" * 60)
    print("Feature extraction completed successfully.")
    print("=" * 60)

    print(
        f"Total records: "
        f"{len(combined_features)}"
    )

    print(
        f"Total features: "
        f"{len(combined_features.columns)}"
    )

    print(
        f"Output file: "
        f"{OUTPUT_FILE}"
    )

    print("\nFeature columns:")

    for column in combined_features.columns:
        print(f"- {column}")


# ------------------------------------------------------------
# Program entry point
# ------------------------------------------------------------

if __name__ == "__main__":
    main()