import json
import re

# 1. Define an ordered list of placeholders and their regex patterns.
#    (Order matters: more specific patterns come first.)
ordered_placeholders = [
    # More specific patterns first (subnets before plain IP addresses)
    ("TARGET_SUBNET", r"(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}"),
    ("TARGET_IP",    r"(?:\d{1,3}\.){3}\d{1,3}"),
    ("DOMAIN",       r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"),
    ("INTERFACE",    r"(?:eth\d+|wlan\d+)"),
    ("LDAP_BASE_DN", r"dc=example,dc=com"),
    ("USER_DN",      r"uid=[a-zA-Z0-9]+"),
    ("KRB_TICKET",   r"ticket\.kirbi"),
    ("USERNAME",     r"(?:admin|user|username)"),
    ("PASSWORD",     r"(?:password123|password|pass)"),
    # The most generic (numbers) is last.
    ("PORT",         r"\d{1,5}")
]

# 2. Build a combined regex pattern using named groups.
pattern_parts = []
for key, pat in ordered_placeholders:
    # For fixed strings (like LDAP_BASE_DN or KRB_TICKET), you might not want word boundaries.
    if key in {"LDAP_BASE_DN", "KRB_TICKET"}:
        pattern_parts.append(f"(?P<{key}>{pat})")
    else:
        pattern_parts.append(f"(?P<{key}>\\b{pat}\\b)")
combined_pattern = "|".join(pattern_parts)
combined_regex = re.compile(combined_pattern)

def replace_static_with_placeholders(text):
    """Replace any static value (IP, domain, etc.) with its corresponding placeholder."""
    
    def replacement(match):
        # For each placeholder in order, check if its named group was matched.
        for key, _ in ordered_placeholders:
            if match.group(key) is not None:
                return "{" + key + "}"
        return match.group(0)

    new_text = combined_regex.sub(replacement, text)
    if text != new_text:
        print(f"Replaced: '{text}' with '{new_text}'")
    return new_text

def process_json(obj):
    """Recursively process the JSON object, replacing strings."""
    if isinstance(obj, dict):
        return {k: process_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [process_json(item) for item in obj]
    elif isinstance(obj, str):
        return replace_static_with_placeholders(obj)
    else:
        return obj

def main():
    input_file = 'A_T_C.json'          # Your original JSON file
    output_file = 'dynamic_tools_commands.json'  # The output JSON with placeholders

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: The file '{input_file}' was not found.")
        return
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return

    # Process the JSON data to replace static elements with placeholders.
    dynamic_data = process_json(data)

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(dynamic_data, f, indent=4)
        print(f"Dynamic JSON has been saved to '{output_file}'.")
    except IOError as e:
        print(f"Error writing to file '{output_file}': {e}")

if __name__ == "__main__":
    main()
