import csv
import json
import os
from pathlib import Path
import sys

def extract_info(repo_dir: Path) -> None | dict:
    """Finding the correct files to read from and creating dicts for the information
        If no valid file is found, returning None

    Args:
        repo_dir (Path): Path to the source code repositories

    Returns:
        None | dict: If
    """
    if os.path.exists(os.path.join(repo_dir, 'requirements.txt')):
        with open(os.path.join(repo_dir, 'requirements.txt'), 'r') as txtfile:
            content = txtfile.read()
            return {
                "name": str(repo_dir),
                "version": "",
                "type": "pip",
                "path": os.path.abspath(os.path.join(repo_dir, 'requirements.txt'))
            }
    elif os.path.exists(os.path.join(repo_dir, 'package.json')):
        with open(os.path.join(repo_dir, 'package.json'), 'r') as jsonfile:
            content = json.load(jsonfile)
            return {
                "name": content["name"],
                "version": content["version"],
                "type": "npm",
                "path": os.path.abspath(os.path.join(repo_dir, 'package.json'))
            }
    else:
        return None


def save_as_CSV(sbom_data: list, parent_dir: Path) -> None:
    """Creating and writeing the information from sbom_data to a CSV-file and saves it to the parent_dir

    Args:
        sbom_data (list): list of dicts to read from
        parent_dir (Path): Path to directory for saveing the CSV-file
    
    Returns:
        None
    """
    csv_file = os.path.join(parent_dir, 'sbom.csv')
    with open(csv_file, 'w', newline='') as csvfile:
        fieldnames = ['name', 'version', 'type', 'path']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in sbom_data:
            writer.writerow(item)
    print(f"Saved SBOM in CSV format to '{parent_dir}'")


def save_as_JSON(sbom_data: dict, parent_dir: Path) -> None:
    """Creating and writeing the information from sbom_data to a JSON-file and saves it to the parent_dir

    Args:
        sbom_data (list): list of dicts to read from
        parent_dir (Path): Path to directory for saveing the JSON-file
    
    Returns:
        None
    """
    json_file = os.path.join(parent_dir, 'sbom.json')
    with open(json_file, 'w') as jsonfile:
        json.dump(sbom_data, jsonfile, indent=4)
    print(f"Saved SBOM in JSON format to '{parent_dir}'")


def create_sbom(arguments: list) -> None:
    """_summary_

    Args:
        arguments (list): arguments from the command line, sys.argv

    Returns:
        None
    """
    #Checking for correct amount of arguments, only want 
    if len(arguments) != 2:
        raise ValueError("Wrong amounts of arguments!", arguments)
    
    repos = Path(arguments[1])
    if not repos.is_dir():
        raise NotADirectoryError("The argument you are passing is not a directory")
    
    full_repos_path = repos.resolve()
    
    repo_count = 0
    for subrepo in repos.iterdir():
        if subrepo.is_dir():
            repo_count += 1
    print(f"Found {repo_count} repositories in '{full_repos_path}'")
    
    target_filenames = ["requirements.txt", "package.json"]
    sbom_data = []
    for subrepo in repos.iterdir():
        if subrepo.is_dir():
            info = extract_info(subrepo)
            if info:
                sbom_data.append(info)
            else: 
                raise FileNotFoundError(f"Your repo: '{full_repos_path / subrepo.name}' does not have any of the targeted files: Targeted files '{target_filenames}'.")

    save_as_CSV(sbom_data, full_repos_path)
    save_as_JSON(sbom_data, full_repos_path)

create_sbom(sys.argv)