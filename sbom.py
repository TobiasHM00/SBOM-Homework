import csv
import json
import os
from pathlib import Path
import sys

def extract_info(filename: str | Path, repo_dir: str | Path) -> None | dict:
    """ Finding the correct files to read from and creating dicts for the information.
        If no valid file is found return None.

    Args:
        filename (str | Path): path to the filename of interest
        repo_dir (str | Path): path to the source code repositories

    Returns:
        None | dict: If
    """
    repo_dir = Path(repo_dir)
    file_path = os.path.join(repo_dir, filename)
    #Check for requirements.txt for Python projects and extracts the info wanted
    if filename == "requirements.txt":
        with open(file_path, "r") as txtfile:
            content = txtfile.read().split("\n")
            return {
                "name": str(repo_dir),
                "version": "",
                "description": "",
                "type": "pip",
                "path": os.path.abspath(file_path),
                "dependencies": list(content)
            }
    #Check for package.json for JavaScript projects and extracts the info wanted
    elif filename == "package.json":
        with open(file_path, "r") as jsonfile:
            content = dict(json.load(jsonfile))
            return {
                "name": content.get("name", ""),
                "version": content.get("version", ""),
                "type": "npm",
                "path": os.path.abspath(file_path),
                "author": content.get("author", ""),
                "license": content.get("license", ""),
                "description": content.get("description", ""),
                "engines": content.get("engines", {}),
                "dependencies": content.get("dependencies", {})
            }
    #Check for package-lock.json for JavaScript projects and extracts the info wanted
    elif filename == "package-lock.json":
        with open(file_path, "r") as lockfile:
            content = dict(json.load(lockfile))
            return {
                "name": content.get("name", ""),
                "version": content.get("version", ""),
                "type": "npm",
                "path": os.path.abspath(file_path),
                "lockfileVersion": content.get("lockfileVersion", "")
            }
    #Returns None if none of the valid files were found
    else:
        return None


def save_as_CSV(sbom_data: list, parent_dir: str | Path) -> None:
    """ Creating and writeing the information from sbom_data to a CSV-file and saves it to the parent_dir.

    Args:
        sbom_data (list): list of dicts to read from
        parent_dir (str | Path): path to directory for saveing the CSV-file
    
    Returns:
        None
    """
    parent_dir = Path(parent_dir)
    csv_file = os.path.join(parent_dir, "sbom.csv")
    with open(csv_file, "w", newline="") as csvfile:
        fieldnames = ["name", "version", "lockfileVersion", "description", "type", "engines", "path", "author", "license", "dependencies"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in sbom_data:
            writer.writerow(item)
    print(f"Saved SBOM in CSV format to '{parent_dir}'")


def save_as_JSON(sbom_data: dict, parent_dir: str | Path) -> None:
    """ Creating and writeing the information from sbom_data to a JSON-file and saves it to the parent_dir.

    Args:
        sbom_data (list): list of dicts to read from
        parent_dir (str | Path): path to directory for saveing the JSON-file
    
    Returns:
        None
    """
    parent_dir = Path(parent_dir)
    json_file = os.path.join(parent_dir, "sbom.json")
    with open(json_file, "w") as jsonfile:
        json.dump(sbom_data, jsonfile, indent=4)
    print(f"Saved SBOM in JSON format to '{parent_dir}'")


def create_sbom(directory: str | Path) -> None:
    """ Calls the extract_info function to get the data wanted form each of the valid files.
        Saves the data in the list of sbom_data and then calls the different functions to save the extracted data to file.

    Args:
        directory (str | Path): path to the passing directory

    Returns:
        None
    """   
    full_repos_path = Path(directory).resolve()
    
    #counts numbers of subdirectories
    repo_count = 0
    for subrepo in directory.iterdir():
        if subrepo.is_dir():
            repo_count += 1
    print(f"Found {repo_count} repositories in '{full_repos_path}'")
    
    #iterates through the subdirectories calls on extract_info to get the data from each valid file
    sbom_data = []
    
    for subrepo in directory.iterdir():
        if subrepo.is_dir():
            for item in subrepo.iterdir():
                if item.suffix != "":
                    filename = item.stem + item.suffix
                    info = extract_info(filename, subrepo)
                    if info:
                        sbom_data.append(info)
                    else: 
                        print(f"Your repo: '{full_repos_path / subrepo.name}' does not have any of the targeted files. Targeted files is eiter 'requirements.txt' or 'package.json'.")
                        sys.exit(1)

    #saves the sbom_data to CSV and JSON file
    save_as_CSV(sbom_data, full_repos_path)
    save_as_JSON(sbom_data, full_repos_path)


if __name__ == "__main__":
    #Check if the correct amount of arguments is provided
    if len(sys.argv) != 2:
        print("Usage: python3 sbom.py <directory>")
        sys.exit(1)

    #Check if the passing argument is a directory
    input_directory = Path(sys.argv[1])
    if not input_directory.is_dir():
        print("Invalid directory specified.")
        sys.exit(1)

    create_sbom(input_directory)