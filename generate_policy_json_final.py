#!/usr/bin/env python3

import copy
import csv
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import quote

import requests
import urllib3


BASE_DIR = Path(__file__).resolve().parent

INPUT_CSV = BASE_DIR / "policy_input_all_policy_types.csv"
BASE_TEMPLATE_JSON = BASE_DIR / "base_schedule_template.json"
SOURCE_JSON_DIR = BASE_DIR / "source_json"
OUTPUT_DIR = BASE_DIR / "generated_json"

API_PORT = 1556
API_VERSION = "3.0"
REQUEST_TIMEOUT = 120
VERIFY_SSL = False
API_KEY_ENV = "NBU_API_KEY"


def clean(value):
    return "" if value is None else str(value).strip()


def safe_filename(value):
    return re.sub(r'[\\/:*?"<>|]+', "_", value.strip())


def load_json(path):
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    with path.open("r", encoding="utf-8-sig") as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        raise ValueError(f"Top-level JSON must be an object: {path}")

    return data


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=4, ensure_ascii=False)
        handle.write("\n")


def get_policy_object(data):
    try:
        policy = data["data"]["attributes"]["policy"]
    except (KeyError, TypeError):
        raise KeyError(
            "Expected policy path: data -> attributes -> policy"
        )

    if not isinstance(policy, dict):
        raise ValueError("Policy section is not a JSON object")

    return policy


def time_to_seconds(value):
    value = clean(value)

    if not value:
        raise ValueError("Backup time is empty")

    parts = value.split(":")

    if len(parts) not in (2, 3):
        raise ValueError(
            f"Invalid time '{value}'. Use HH:MM or HH:MM:SS"
        )

    try:
        hour = int(parts[0])
        minute = int(parts[1])
        second = int(parts[2]) if len(parts) == 3 else 0
    except ValueError as error:
        raise ValueError(
            f"Invalid time '{value}'. Use numeric HH:MM"
        ) from error

    if not 0 <= hour <= 23:
        raise ValueError("Hour must be between 00 and 23")

    if not 0 <= minute <= 59:
        raise ValueError("Minute must be between 00 and 59")

    if not 0 <= second <= 59:
        raise ValueError("Second must be between 00 and 59")

    return hour * 3600 + minute * 60 + second


def update_schedule_start_times(
    schedules,
    full_start_seconds,
    incremental_start_seconds
):
    full_updated = 0
    incremental_updated = 0

    for schedule in schedules:
        if not isinstance(schedule, dict):
            continue

        schedule_name = clean(
            schedule.get("scheduleName")
        ).lower()

        backup_type = clean(
            schedule.get("backupType")
        ).lower()

        is_full = (
            schedule_name == "full"
            or backup_type == "full backup"
        )

        is_incremental = (
            schedule_name in {"incr", "inc", "incremental"}
            or "incremental" in backup_type
        )

        start_windows = schedule.get("startWindow", [])

        if not isinstance(start_windows, list):
            continue

        for window in start_windows:
            if not isinstance(window, dict):
                continue

            try:
                day_of_week = int(window.get("dayOfWeek"))
            except (TypeError, ValueError):
                continue

            if is_full and day_of_week == 6:
                window["startSeconds"] = full_start_seconds
                full_updated += 1

            elif is_incremental and day_of_week != 6:
                window["startSeconds"] = incremental_start_seconds
                incremental_updated += 1

    if full_updated == 0:
        raise ValueError(
            "No Full Backup window with dayOfWeek 6 found"
        )

    if incremental_updated == 0:
        raise ValueError(
            "No Incremental windows outside dayOfWeek 6 found"
        )


def update_wrapper_fields(data, new_policy_name):
    wrapper = data.get("data", {})

    if "id" in wrapper:
        wrapper["id"] = new_policy_name

    links = wrapper.get("links", {})
    self_link = links.get("self", {})

    if "href" in self_link:
        self_link["href"] = (
            f"/config/policies/{new_policy_name}"
        )

    meta = wrapper.get("meta", {})

    if "accessControlId" in meta:
        policy = get_policy_object(data)
        policy_type = clean(
            policy.get("policyType", "")
        ).upper()

        meta["accessControlId"] = (
            f"|PROTECTION|POLICIES|{policy_type}|"
            f"{new_policy_name}|"
        )


def api_error(response):
    try:
        payload = response.json()

        if isinstance(payload, dict):
            return str(
                payload.get("errorMessage")
                or payload.get("message")
                or payload.get("detail")
                or payload
            )

        return str(payload)

    except ValueError:
        return response.text.strip() or response.reason


def download_source_policy(
    master_server_name,
    policy_name,
    api_key
):
    SOURCE_JSON_DIR.mkdir(parents=True, exist_ok=True)

    output_file = (
        SOURCE_JSON_DIR
        / f"{safe_filename(policy_name)}.json"
    )

    encoded_policy = quote(policy_name, safe="")

    url = (
        f"https://{master_server_name}:{API_PORT}"
        f"/netbackup/config/policies/{encoded_policy}"
    )

    media_type = (
        f"application/vnd.netbackup+json;"
        f"version={API_VERSION}"
    )

    headers = {
        "Authorization": api_key,
        "Accept": media_type,
        "Content-Type": media_type,
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
        verify=VERIFY_SSL,
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Download failed for '{policy_name}'. "
            f"HTTP {response.status_code}: {api_error(response)}"
        )

    try:
        data = response.json()
    except ValueError as error:
        raise RuntimeError(
            f"Invalid JSON returned for policy '{policy_name}'"
        ) from error

    get_policy_object(data)
    save_json(output_file, data)

    return output_file



def update_vmware_storage_suffix(policy, target_environment):
    """
    VMware only:
      PROD -> storage suffix _6W
      VAL/NON-PROD -> storage suffix _3W

    All other policy types are not changed.
    """
    if clean(policy.get("policyType")).lower() != "vmware":
        return

    policy_attributes = policy.get("policyAttributes", {})

    if not isinstance(policy_attributes, dict):
        return

    storage = clean(policy_attributes.get("storage"))

    if not storage:
        return

    if target_environment == "PROD":
        new_storage = re.sub(r"_(3W|6W)$", "_6W", storage, flags=re.IGNORECASE)
    else:
        new_storage = re.sub(r"_(3W|6W)$", "_3W", storage, flags=re.IGNORECASE)

    policy_attributes["storage"] = new_storage


def create_new_policy(
    source_data,
    new_policy_name,
    target_environment,
    template_schedules,
    full_start_seconds,
    incremental_start_seconds
):
    new_data = copy.deepcopy(source_data)
    policy = get_policy_object(new_data)

    # Change the policy name for every policy type.
    policy["policyName"] = new_policy_name

    # VMware only: PROD uses _6W and VAL/NON-PROD uses _3W.
    # Non-VMware storage values remain exactly as in the source policy.
    update_vmware_storage_suffix(
        policy,
        target_environment
    )

    # For every policy type, replace the complete schedules block
    # using the common base schedule template.
    policy["schedules"] = copy.deepcopy(
        template_schedules
    )

    # For every policy type:
    # Full Backup      -> update only dayOfWeek 6.
    # Incremental      -> update every day except dayOfWeek 6.
    # durationSeconds  -> never changed.
    update_schedule_start_times(
        policy["schedules"],
        full_start_seconds,
        incremental_start_seconds,
    )

    update_wrapper_fields(
        new_data,
        new_policy_name
    )

    return new_data


def main():
    if not VERIFY_SSL:
        urllib3.disable_warnings(
            urllib3.exceptions.InsecureRequestWarning
        )

    api_key = clean(os.environ.get(API_KEY_ENV))

    if not api_key:
        print(
            f"Program failed: environment variable "
            f"{API_KEY_ENV} is not set"
        )
        return 1

    if not INPUT_CSV.exists():
        print(f"Program failed: CSV not found: {INPUT_CSV}")
        return 1

    template_schedules = None

    if BASE_TEMPLATE_JSON.exists():
        template_data = load_json(BASE_TEMPLATE_JSON)
        template_policy = get_policy_object(template_data)
        template_schedules = template_policy.get("schedules")

        if not isinstance(template_schedules, list):
            raise ValueError(
                "Template schedules block is invalid"
            )

    SOURCE_JSON_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with INPUT_CSV.open(
        "r",
        newline="",
        encoding="utf-8-sig"
    ) as handle:

        reader = csv.DictReader(handle)

        required_headers = {
            "Policyname",
            "Prod_policy_name",
            "val_policy_name",
            "Policy_type",
            "Master_Server_Name",
            "fullbackup_time",
            "inc_time",
        }

        missing = required_headers - set(reader.fieldnames or [])

        if missing:
            print(
                "Program failed: missing CSV columns: "
                + ", ".join(sorted(missing))
            )
            return 1

        success_count = 0
        failure_count = 0

        for row_number, row in enumerate(reader, start=2):
            try:
                source_policy_name = clean(row["Policyname"])
                prod_policy_name = clean(row["Prod_policy_name"])
                val_policy_name = clean(row["val_policy_name"])
                csv_policy_type = clean(row["Policy_type"])
                master_server_name = clean(row["Master_Server_Name"])
                fullbackup_time = clean(row["fullbackup_time"])
                inc_time = clean(row["inc_time"])

                if not source_policy_name:
                    raise ValueError("Policyname is empty")

                if not master_server_name:
                    raise ValueError(
                        "Master_Server_Name is empty"
                    )

                if not prod_policy_name and not val_policy_name:
                    raise ValueError(
                        "Provide either Prod_policy_name "
                        "or val_policy_name"
                    )

                if (
                    prod_policy_name
                    and val_policy_name
                    and prod_policy_name.lower()
                    == val_policy_name.lower()
                ):
                    raise ValueError(
                        "Prod and VAL policy names cannot be identical"
                    )

                source_file = download_source_policy(
                    master_server_name,
                    source_policy_name,
                    api_key,
                )

                source_data = load_json(source_file)
                source_policy = get_policy_object(source_data)

                actual_policy_type = clean(
                    source_policy.get("policyType")
                )

                if (
                    csv_policy_type
                    and actual_policy_type
                    and csv_policy_type.lower()
                    != actual_policy_type.lower()
                ):
                    raise ValueError(
                        f"Policy type mismatch. "
                        f"CSV={csv_policy_type}, "
                        f"JSON={actual_policy_type}"
                    )

                # The common schedule template and both backup times
                # are required for every policy type.
                if template_schedules is None:
                    raise ValueError(
                        "base_schedule_template.json is required"
                    )

                full_seconds = time_to_seconds(
                    fullbackup_time
                )

                inc_seconds = time_to_seconds(
                    inc_time
                )

                generated_files = []

                policy_targets = [
                    (prod_policy_name, "PROD"),
                    (val_policy_name, "VAL"),
                ]

                for new_policy_name, target_environment in policy_targets:
                    if not new_policy_name:
                        continue

                    new_data = create_new_policy(
                        source_data,
                        new_policy_name,
                        target_environment,
                        template_schedules,
                        full_seconds,
                        inc_seconds,
                    )

                    output_file = (
                        OUTPUT_DIR
                        / f"{safe_filename(new_policy_name)}.json"
                    )

                    save_json(output_file, new_data)
                    generated_files.append(output_file.name)

                print(
                    f"[SUCCESS] {source_policy_name} -> "
                    + ", ".join(generated_files)
                )

                success_count += 1

            except Exception as error:
                print(
                    f"[FAILED] CSV row {row_number}: {error}"
                )
                failure_count += 1

    print()
    print("=" * 68)
    print(f"Successful rows : {success_count}")
    print(f"Failed rows     : {failure_count}")
    print(f"Source JSON     : {SOURCE_JSON_DIR}")
    print(f"Generated JSON  : {OUTPUT_DIR}")
    print("=" * 68)

    return 0 if failure_count == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
