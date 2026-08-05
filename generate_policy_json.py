#!/usr/bin/env python3

import copy
import csv
import json
import re
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

INPUT_CSV = BASE_DIR / "policy_input.csv"
SOURCE_JSON_DIR = BASE_DIR / "source_json"
BASE_TEMPLATE_JSON = BASE_DIR / "base_schedule_template.json"
OUTPUT_DIR = BASE_DIR / "generated_json"


def clean(value):
    return "" if value is None else str(value).strip()


def safe_filename(value):
    return re.sub(r'[\\/:*?"<>|]+', "_", value.strip())


def load_json(path):
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    with path.open("r", encoding="utf-8-sig") as file:
        return json.load(file)


def get_policy_object(json_data):
    try:
        return json_data["data"]["attributes"]["policy"]
    except (KeyError, TypeError):
        raise KeyError(
            "Policy path not found. Expected: "
            "data -> attributes -> policy"
        )


def find_source_json(policy_name):
    expected_file = SOURCE_JSON_DIR / f"{policy_name}.json"

    if expected_file.exists():
        return expected_file

    expected_name = expected_file.name.lower()

    for json_file in SOURCE_JSON_DIR.glob("*.json"):
        if json_file.name.lower() == expected_name:
            return json_file

    raise FileNotFoundError(
        f"Source JSON not found for policy '{policy_name}' "
        f"under {SOURCE_JSON_DIR}"
    )


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
            f"|PROTECTION|POLICIES|{policy_type}|"
            f"{new_policy_name}|"
        )


def create_new_policy(source_json, template_schedules, new_policy_name):
    new_json = copy.deepcopy(source_json)
    policy = get_policy_object(new_json)

    # Replace policy name
    policy["policyName"] = new_policy_name

    # Replace the entire schedules block from the base template
    policy["schedules"] = copy.deepcopy(template_schedules)

    # Update wrapper fields when present
    update_wrapper_fields(new_json, new_policy_name)

    return new_json


def save_json(output_file, json_data):
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(
            json_data,
            file,
            indent=4,
            ensure_ascii=False
        )
        file.write("\n")


def main():
    SOURCE_JSON_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    try:
        template_json = load_json(BASE_TEMPLATE_JSON)
        template_policy = get_policy_object(template_json)
        template_schedules = template_policy.get("schedules")

        if not isinstance(template_schedules, list):
            raise ValueError(
                "Schedules block not found in base_schedule_template.json"
            )

        if not INPUT_CSV.exists():
            raise FileNotFoundError(
                f"CSV file not found: {INPUT_CSV}"
            )

        with INPUT_CSV.open(
            "r",
            newline="",
            encoding="utf-8-sig"
        ) as csv_file:

            reader = csv.DictReader(csv_file)

            required_columns = {
                "Policyname",
                "Prod_policy_name",
                "val_policy_name",
                "Policy_type",
                "Master_Server_Name",
            }

            missing_columns = required_columns - set(reader.fieldnames or [])

            if missing_columns:
                raise ValueError(
                    "Missing CSV columns: "
                    + ", ".join(sorted(missing_columns))
                )

            success_count = 0
            failure_count = 0

            for row_number, row in enumerate(reader, start=2):

                source_policy_name = clean(row["Policyname"])
                prod_policy_name = clean(row["Prod_policy_name"])
                val_policy_name = clean(row["val_policy_name"])
                csv_policy_type = clean(row["Policy_type"])

                try:
                    if not source_policy_name:
                        raise ValueError("Policyname is empty")

                    if not prod_policy_name:
                        raise ValueError("Prod_policy_name is empty")

                    if not val_policy_name:
                        raise ValueError("val_policy_name is empty")

                    if prod_policy_name.lower() == val_policy_name.lower():
                        raise ValueError(
                            "Prod and VAL policy names cannot be the same"
                        )

                    source_file = find_source_json(
                        source_policy_name
                    )

                    source_json = load_json(source_file)
                    source_policy = get_policy_object(source_json)

                    source_policy_type = clean(
                        source_policy.get("policyType")
                    )

                    if (
                        csv_policy_type
                        and source_policy_type
                        and csv_policy_type.lower()
                        != source_policy_type.lower()
                    ):
                        raise ValueError(
                            f"Policy type mismatch. CSV={csv_policy_type}, "
                            f"JSON={source_policy_type}"
                        )

                    prod_json = create_new_policy(
                        source_json,
                        template_schedules,
                        prod_policy_name
                    )

                    val_json = create_new_policy(
                        source_json,
                        template_schedules,
                        val_policy_name
                    )

                    prod_output = (
                        OUTPUT_DIR
                        / f"{safe_filename(prod_policy_name)}.json"
                    )

                    val_output = (
                        OUTPUT_DIR
                        / f"{safe_filename(val_policy_name)}.json"
                    )

                    save_json(prod_output, prod_json)
                    save_json(val_output, val_json)

                    print(
                        f"[SUCCESS] {source_policy_name} -> "
                        f"{prod_output.name}, {val_output.name}"
                    )

                    success_count += 1

                except Exception as error:
                    print(
                        f"[FAILED] CSV row {row_number}: {error}"
                    )
                    failure_count += 1

        print()
        print("=" * 65)
        print(f"Successful rows : {success_count}")
        print(f"Failed rows     : {failure_count}")
        print(f"Output folder   : {OUTPUT_DIR}")
        print("=" * 65)

        return 0 if failure_count == 0 else 2

    except Exception as error:
        print(f"Program failed: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
