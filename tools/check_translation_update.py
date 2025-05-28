#!/usr/bin/env python
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
# Contributed by QGrain <zhiyuzhang999@gmail.com>

# Usage: python tools/check_translation_update.py

import os
import re
import sys
import argparse
import subprocess

def get_git_repo_root(path):
    """Get root path of the repository"""
    try:
        # Use git rev-parse --show-toplevel to find the root path
        result = subprocess.run(
            ['git', 'rev-parse', '--show-toplevel'],
            cwd=path,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        print(f"Error: current work directory {path} is not in a Git repo.")
        return None
    except FileNotFoundError:
        print("Error: 'git' command not found.")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def get_commit_time(repo_root, commit_hash):
    """Get the commit time for a given commit hash."""
    try:
        result = subprocess.run(
            ['git', 'show', '-s', '--format=%ci', commit_hash],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True
        )
        commit_time = result.stdout.strip()
        return commit_time.split(' ')[0] + ' ' + commit_time.split(' ')[1]
    except Exception as e:
        print(f"Error in getting commit time of {commit_hash}: {e}")
        return None

def get_latest_commit_info(repo_root, file_path):
    """Get the latest commit hash and message for a given file.
    Args:
        repo_root: Git repository root path
        file_path: Path to the file
    Returns:
        tuple: (commit_hash, commit_time, commit_message) or (None, None, None) if not found
    """
    try:
        result = subprocess.run(
            ['git', 'log', '-1', '--format=%H%n%ci%n%B', '--', file_path],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True
        )

        lines = result.stdout.splitlines()
        if len(lines) >= 3:
            commit_hash = lines[0]
            commit_date = lines[1].split(' ')[0] + ' ' + lines[1].split(' ')[1]
            commit_message = '\n'.join(lines[2:])
            return commit_hash, commit_date, commit_message

        return None, None, None
    except Exception as e:
        print(f"Fail to get latest commit info of {file_path}: {e}")
        return None, None, None

def extract_source_commit_info(repo_root, file_path):
    """Extract the source commit hash and time that this translation is based on.
    Args:
        repo_root: Git repository root path
        file_path: Path to the translation file
    Returns:
        tuple: (source_commit_hash, source_commit_time) or (None, None) if not found
    """
    try:
        _, _, translation_commit_message = get_latest_commit_info(repo_root, file_path)

        update_marker = 'Update to commit'
        update_info = ''
        source_commit_hash, source_commit_time = None, None

        for line in translation_commit_message.splitlines():
            if update_marker in line:
                update_info = line.strip()
                break

        match = re.search(r"Update to commit ([0-9a-fA-F]{7,12}) \(\"(.+?)\"\)", update_info)
        if match:
            source_commit_hash = match.group(1)
            source_commit_time = get_commit_time(repo_root, source_commit_hash)

        return source_commit_hash, source_commit_time
    except Exception as e:
        print(f"Fail to extract source commit info of {file_path}: {e}")
        return None, None

def extract_translation_language(file_path):
    """Extract the language code from the translation file path."""
    match = re.search(r'docs/translations/([^/]+)/', file_path)
    if match:
        return match.group(1)
    return None

def check_translation_update(repo_root, translation_file_path):
    """Check if the translation file is up to date with the original file.
    Args:
        repo_root: Git repository root path
        translation_file_path: Path to the translation file
    Returns:
        tuple: (is_translation, support_update_check, is_update)
        True if the translation supports update check and is up to date, False otherwise
    """
    # 1. Checks if it is a valid translation file and needs to be checked
    language = extract_translation_language(translation_file_path)
    if not os.path.exists(translation_file_path) or language is None or f"docs/translations/{language}/README.md" in translation_file_path:
        return False, False, False

    # 2. Extract commit info of the translated source file
    translated_source_commit_hash, translated_source_commit_time = extract_source_commit_info(repo_root, translation_file_path)
    if not translated_source_commit_hash:
        print(f"File {translation_file_path} does not have a formatted update commit message, skip it.")
        return True, False, False

    # 3. Get the latest commit info of the source file
    # given the translation file syzkaller/docs/translations/LANGUAGE/PATH/ORIG.md
    # then the source file should be syzkaller/docs/PATH/ORIG.md
    relative_path = os.path.relpath(translation_file_path, repo_root)
    if "docs/translations/" not in relative_path:
        print(f"File '{translation_file_path}' is not a translation, skip it.")
        return False, False, False

    source_file_path = relative_path.replace(f"docs/translations/{language}/", "docs/")
    source_file_abs_path = os.path.join(repo_root, source_file_path)
    if not os.path.exists(source_file_abs_path):
        print(f"Source file '{source_file_abs_path}' does not exist, skip it.")
        return True, True, False
    source_commit_hash, source_commit_time, _ = get_latest_commit_info(repo_root, source_file_abs_path)

    # 4. Compare the commit hashes between the translated source and latest source
    if translated_source_commit_hash[:7] != source_commit_hash[:7]:
        print(f"{translation_file_path} is based on {translated_source_commit_hash[:7]} ({translated_source_commit_time}), " \
              f"while the latest source is {source_commit_hash[:7]} ({source_commit_time}).")
        return True, True, False

    return True, True, True

def main():
    parser = argparse.ArgumentParser(description="Check the update of translation files in syzkaller/docs/translations/.")
    parser.add_argument("-f", "--files", nargs="+", help="one or multiple paths of translation files (test only)")
    parser.add_argument("-r", "--repo-root", default=".", help="root directory of syzkaller (default: current directory)")
    args = parser.parse_args()

    repo_root = get_git_repo_root(args.repo_root)
    if not repo_root:
        return

    total_cnt, support_update_check_cnt, is_update_cnt = 0, 0, 0

    if args.files:
        for file_path in args.files:
            abs_file_path = os.path.abspath(file_path)
            if not abs_file_path.startswith(repo_root):
                print(f"File '{file_path}' is not in {repo_root}', skip it.")
                continue

            is_translation, support_update_check, is_update = check_translation_update(repo_root, abs_file_path)
            total_cnt += int(is_translation)
            support_update_check_cnt += int(support_update_check)
            is_update_cnt += int(is_update)
        print(f"Summary: {support_update_check_cnt}/{total_cnt} translation files have formatted commit message that support update check, " \
          f"{is_update_cnt}/{support_update_check_cnt} are update to date.")
        sys.exit(0)

    translation_dir = os.path.join(repo_root, 'docs', 'translations')
    for root, _, files in os.walk(translation_dir):
        for file in files:
            translation_path = os.path.join(root, file)
            # print(f"[DEBUG] {translation_path}")
            is_translation, support_update_check, is_update = check_translation_update(repo_root, translation_path)
            total_cnt += int(is_translation)
            support_update_check_cnt += int(support_update_check)
            is_update_cnt += int(is_update)
    print(f"Summary: {support_update_check_cnt}/{total_cnt} translation files have formatted commit message that support update check, " \
          f"{is_update_cnt}/{support_update_check_cnt} are update to date.")
    sys.exit(0)
    # We will add other exit code once all the previous translation commit messages are unified with the new format.

if __name__ == "__main__":
    main()