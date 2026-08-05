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
INPUT_CSV = BASE_DIR / "policy_input_with_download.csv"
SOURCE_JSON_DIR = BASE_DIR / "source_json"
BASE_TEMPLATE_JSON = BASE_DIR / "base_schedule_template.json"
OUTPUT_DIR = BASE_DIR / "generated_json"

API_PORT = 1556
API_VERSION = "3.0"
REQUEST_TIMEOUT = 120
VERIFY_SSL = False
API_KEY_ENVIRONMENT_VARIABLE = "NBU_API_KEY"


def clean(value):
    return "" if value is None else str(value).strip()


def safe_filename(value):
    return re.sub(r'[\\/:*?"<>|]+', "_", value.strip())


def load_json(path):
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    with path.open("r", encoding="utf-8-sig") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        raise ValueError(f"Top-level JSON must be an object: {path}")
    return data


def save_json(output_file, json_data):
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as file:
        json.dump(json_data, file, indent=4, ensure_ascii=False)
        file.write("\n")


def get_policy_object(json_data):
    try:
        policy = json_data["data"]["attributes"]["policy"]
    except (KeyError, TypeError):
        raise KeyError("Policy path not found. Expected: data -> attributes -> policy")
    if not isinstance(policy, dict):
        raise ValueError("data.attributes.policy is not a JSON object")
    return policy


def get_api_key():
    api_key = clean(os.environ.get(API_KEY_ENVIRONMENT_VARIABLE))
    if not api_key:
        raise RuntimeError(
            f"Environment variable {API_KEY_ENVIRONMENT_VARIABLE} is not set"
        )
    return api_key


def extract_api_error(response):
    try:
        data = response.json()
        if isinstance(data, dict):
            message = data.get("errorMessage") or data.get("message") or data.get("detail")
            code = data.get("errorCode")
            if code and message:
                return f"{code}: {message}"
            if message:
                return str(message)
        return json.dumps(data)
    except ValueError:
        return response.text.strip() or response.reason


def download_source_policy(master_server_name, policy_name, api_key):
    """Download one existing NetBackup policy and save it under source_json."""
    SOURCE_JSON_DIR.mkdir(parents=True, exist_ok=True)
    output_file = SOURCE_JSON_DIR / f"{safe_filename(policy_name)}.json"

    if output_file.exists():
        print(f"[INFO] Reusing source JSON: {output_file.name}")
        return output_file

    encoded_policy_name = quote(policy_name, safe="")
    url = (
        f"https://{master_server_name}:{API_PORT}"
        f"/netbackup/config/policies/{encoded_policy_name}"
    )
    media_type = f"application/vnd.netbackup+json;version={API_VERSION}"
    headers = {
        "Authorization": api_key,
        "Accept": media_type,
        "Content-Type": media_type,
    }

    print(f"[INFO] Downloading '{policy_name}' from '{master_server_name}'")

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            verify=VERIFY_SSL,
        )
    except requests.exceptions.SSLError as error:
        raise RuntimeError(f"SSL error: {error}") from error
    except requests.exceptions.Timeout as error:
        raise RuntimeError(f"Connection timed out: {master_server_name}") from error
    except requests.exceptions.ConnectionError as error:
        raise RuntimeError(f"Connection failed: {master_server_name}: {error}") from error

    if response.status_code != 200:
        raise RuntimeError(
            f"Policy download failed. HTTP {response.status_code}: "
            f"{extract_api_error(response)}"
        )

    try:
        policy_json = response.json()
    except ValueError as error:
        raise RuntimeError("NetBackup returned invalid JSON") from error

    get_policy_object(policy_json)
    save_json(output_file, policy_json)
    print(f"[SUCCESS] Downloaded source policy: {output_file}")
    return output_file


def update_wrapper_fields(json_data, new_policy_name):
    data = json_data.get("data", {})
    if "id" in data:
        data["id"] = new_policy_name

    links = data.get("links", {})
    self_link = links.get("self", {})
    if "href" in self_link:
        self_link["href"] = f"/config/policies/{new_policy_name}"

    meta = data.get("meta", {})
    if "accessControlId" in meta:
        policy = get_policy_object(json_data)
        policy_type = clean(policy.get("policyType", "VMware")).upper()
        meta["accessControlId"] = (
            f"|PROTECTION|POLICIES|{policy_type}|{new_policy_name}|"
        )


def create_new_policy(source_json, template_schedules, new_policy_name):
    new_json = copy.deepcopy(source_json)
    policy = get_policy_object(new_json)
    policy["policyName"] = new_policy_name
    policy["schedules"] = copy.deepcopy(template_schedules)
    update_wrapper_fields(new_json, new_policy_name)
    return new_json


def main():
    if not VERIFY_SSL:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    SOURCE_JSON_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    try:
        api_key = get_api_key()
        template_json = load_json(BASE_TEMPLATE_JSON)
        template_schedules = get_policy_object(template_json).get("schedules")

        if not isinstance(template_schedules, list) or not template_schedules:
            raise ValueError(
                "Schedules block missing or empty in base_schedule_template.json"
            )

        if not INPUT_CSV.exists():
            raise FileNotFoundError(f"CSV file not found: {INPUT_CSV}")

        with INPUT_CSV.open("r", newline="", encoding="utf-8-sig") as csv_file:
            reader = csv.DictReader(csv_file)
            required_columns = {
                "Policyname",
                "Prod_policy_name",
                "val_policy_name",
                "Policy_type",
                "Master_Server_Name",
            }
            missing = required_columns - set(reader.fieldnames or [])
            if missing:
                raise ValueError("Missing CSV columns: " + ", ".join(sorted(missing)))

            success_count = 0
            failure_count = 0

            for row_number, row in enumerate(reader, start=2):
                source_policy_name = clean(row["Policyname"])
                prod_policy_name = clean(row["Prod_policy_name"])
                val_policy_name = clean(row["val_policy_name"])
                csv_policy_type = clean(row["Policy_type"])
                master_server_name = clean(row["Master_Server_Name"])

                try:
                    if not source_policy_name:
                        raise ValueError("Policyname is empty")
                    if not prod_policy_name:
                        raise ValueError("Prod_policy_name is empty")
                    if not val_policy_name:
                        raise ValueError("val_policy_name is empty")
                    if not master_server_name:
                        raise ValueError("Master_Server_Name is empty")
                    if prod_policy_name.lower() == val_policy_name.lower():
                        raise ValueError("Prod and VAL policy names cannot be the same")

                    source_file = download_source_policy(
                        master_server_name,
                        source_policy_name,
                        api_key,
                    )
                    source_json = load_json(source_file)
                    source_policy = get_policy_object(source_json)
                    source_policy_type = clean(source_policy.get("policyType"))

                    if (
                        csv_policy_type
                        and source_policy_type
                        and csv_policy_type.lower() != source_policy_type.lower()
                    ):
                        raise ValueError(
                            f"Policy type mismatch. CSV={csv_policy_type}, "
                            f"JSON={source_policy_type}"
                        )

                    prod_json = create_new_policy(
                        source_json, template_schedules, prod_policy_name
                    )
                    val_json = create_new_policy(
                        source_json, template_schedules, val_policy_name
                    )

                    prod_output = OUTPUT_DIR / f"{safe_filename(prod_policy_name)}.json"
                    val_output = OUTPUT_DIR / f"{safe_filename(val_policy_name)}.json"
                    save_json(prod_output, prod_json)
                    save_json(val_output, val_json)

                    print(
                        f"[SUCCESS] {source_policy_name} -> "
                        f"{prod_output.name}, {val_output.name}"
                    )
                    success_count += 1

                except Exception as error:
                    print(f"[FAILED] CSV row {row_number}: {error}")
                    failure_count += 1

        print()
        print("=" * 68)
        print(f"Successful rows : {success_count}")
        print(f"Failed rows     : {failure_count}")
        print(f"Source JSON     : {SOURCE_JSON_DIR}")
        print(f"Generated JSON  : {OUTPUT_DIR}")
        print("=" * 68)
        return 0 if failure_count == 0 else 2

    except Exception as error:
        print(f"Program failed: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
