import os

# Words to replace
replacements = {
    "otplink": "linkotp",
    "OtpLink": "LinkOtp",
    "OTPLINK": "LINKOTP",
    "@yasirdora/otplink": "linkotp" # Just in case it's missed
}

# Directories and files to exclude
exclude_dirs = {".git", ".github", "node_modules", "dist"}
exclude_files = {"package-lock.json", "rename.py"}

def rename_in_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        return # Skip binary files

    new_content = content
    for old, new in replacements.items():
        new_content = new_content.replace(old, new)
        
    if new_content != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Updated {filepath}")

for root, dirs, files in os.walk('.'):
    dirs[:] = [d for d in dirs if d not in exclude_dirs]
    for file in files:
        if file in exclude_files:
            continue
        filepath = os.path.join(root, file)
        rename_in_file(filepath)
