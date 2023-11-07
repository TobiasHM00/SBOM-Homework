from pathlib import Path
import sys


def sbom(arguments) -> None:
    if len(sys.argv) != 1:
        raise ValueError("Wrong amounts of arguments!")
    
    repo = Path(arguments[1])
    if not repo.is_dir():
        raise TypeError("Not a directory")
    
    print(str(repo))
    


if __name__ == "__main__":
    # TODO try-execept
    sbom(sys.argv)