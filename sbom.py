import csv
import json
import os
from pathlib import Path
import sys


def extract_info(repo_dir):
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


def create_sbom(arguments: list):
    #TODO description of function
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
            found_target_file = False
            for item in subrepo.iterdir():
                if item.name in target_filenames:
                    found_target_file = True
                    info = extract_info(subrepo)
                    if info:
                        sbom_data.append(info)
                    break
            if not found_target_file:
                raise FileNotFoundError(f"Your repo: '{full_repos_path / subrepo.name}' does not have any of the targeted files: Targeted files '{target_filenames}'.")

    save_as_CSV(sbom_data, full_repos_path)
    save_as_JSON(sbom_data, full_repos_path)


def save_as_CSV(sbom_data: list, parent_dir: Path):
    csv_file = os.path.join(parent_dir, 'sbom.csv')
    with open(csv_file, 'w', newline='') as csvfile:
        fieldnames = ['name', 'version', 'type', 'path']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in sbom_data:
            writer.writerow(item)
    
    print(f"Saved SBOM in CSV format to '{parent_dir}'")
        

def save_as_JSON(sbom_data: dict, parent_dir: Path):
    json_file = os.path.join(parent_dir, 'sbom.json')
    sbom_data = [
        {
            "name": item["name"],
            "version": item["version"],
            "type": item["type"],
            "path": item["path"]
        }
        for item in sbom_data
    ]
    with open(json_file, 'w') as jsonfile:
        json.dump(sbom_data, jsonfile, indent=4)
    
    print(f"Saved SBOM in JSON format to '{parent_dir}'")


if __name__ == "__main__":
    create_sbom(sys.argv)