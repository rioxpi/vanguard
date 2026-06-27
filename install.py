import os
import stat
import zipfile
import urllib.request
import subprocess

PROGRAMS_DIR = "programs"
URLS = {
    "nmap": "https://github.com/ernw/static-toolbox/releases/download/nmap-v7.94SVN/nmap-7.94SVN-x86_64-portable.zip",
    "ffuf": "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz",
    "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt",
    "subfinder": "https://github.com/projectdiscovery/subfinder/releases/download/v2.14.0/subfinder_2.14.0_linux_amd64.zip",
    "searchsploit": "https://gitlab.com/exploit-database/exploitdb/-/archive/main/exploitdb-main.zip?ref_type=heads",
}


def download_nmap() -> None:
    """
    Downloads and extracts the nmap portable version.
    """
    target_dir = os.path.join(PROGRAMS_DIR, "nmap")
    zip_path = "nmap_portable.zip"

    os.makedirs(target_dir, exist_ok=True)
    print("Downloading nmap 7.94SVN Portable...")
    req = urllib.request.Request(URLS["nmap"])

    try:
        with urllib.request.urlopen(req) as response, open(zip_path, "wb") as out_file:
            out_file.write(response.read())

        print("Download complete")
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(target_dir)

        nmap_binary = os.path.join(target_dir, "nmap")
        if os.path.exists(nmap_binary):
            st = os.stat(nmap_binary)
            os.chmod(nmap_binary, st.st_mode | stat.S_IEXEC)

        nmap_runner = os.path.join(target_dir, "run-nmap.sh")
        if os.path.exists(nmap_runner):
            st = os.stat(nmap_runner)
            os.chmod(nmap_runner, st.st_mode | stat.S_IEXEC)
    except Exception as e:
        print(f"An error occurred during download or extraction: {e}")
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)


def download_ffuf() -> None:
    """
    Downloads and extracts the ffuf binary.
    """
    target_dir = os.path.join(PROGRAMS_DIR, "ffuf")
    tar_path = "ffuf.tar.gz"

    os.makedirs(target_dir, exist_ok=True)
    print("Downloading ffuf 2.1.0...")
    req = urllib.request.Request(URLS["ffuf"])

    try:
        with urllib.request.urlopen(req) as response, open(tar_path, "wb") as out_file:
            out_file.write(response.read())

        print("Download complete")
        subprocess.run(["tar", "-xzf", tar_path, "-C", target_dir], check=True)

        ffuf_binary = os.path.join(target_dir, "ffuf")
        if os.path.exists(ffuf_binary):
            st = os.stat(ffuf_binary)
            os.chmod(ffuf_binary, st.st_mode | stat.S_IEXEC)
    except Exception as e:
        print(f"An error occurred during download or extraction: {e}")
    finally:
        if os.path.exists(tar_path):
            os.remove(tar_path)

    wordlist_path = os.path.join(PROGRAMS_DIR, "wordlist.txt")
    print("Downloading wordlist...")
    try:
        with (
            urllib.request.urlopen(URLS["wordlist"]) as response,
            open(wordlist_path, "wb") as out_file,
        ):
            out_file.write(response.read())
        print("wordlist download complete")
    except Exception as e:
        print(f"An error occurred while downloading the wordlist: {e}")


def download_subfinder() -> None:
    """
    Downloads and extracts the subfinder binary.
    """
    target_dir = os.path.join(PROGRAMS_DIR, "subfinder")
    zip_path = "subfinder.zip"

    os.makedirs(target_dir, exist_ok=True)
    print("Downloading subfinder 2.14.0...")
    req = urllib.request.Request(URLS["subfinder"])

    try:
        with urllib.request.urlopen(req) as response, open(zip_path, "wb") as out_file:
            out_file.write(response.read())

        print("Download complete")
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(target_dir)

        subfinder_binary = os.path.join(target_dir, "subfinder")
        if os.path.exists(subfinder_binary):
            st = os.stat(subfinder_binary)
            os.chmod(subfinder_binary, st.st_mode | stat.S_IEXEC)
    except Exception as e:
        print(f"An error occurred during download or extraction: {e}")
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)


def download_searchsploit() -> None:
    """
    Downloads searchsploit repository
    """
    target_dir = PROGRAMS_DIR
    zip_path = "exploitdb.zip"
    extract_dir = "exploitdb-main"
    target_folder = "exploitdb"

    os.makedirs(target_dir, exist_ok=True)
    print("Downloading searchsploit...")
    req = urllib.request.Request(URLS["searchsploit"])

    try:
        with urllib.request.urlopen(req) as response, open(zip_path, "wb") as out_file:
            out_file.write(response.read())

        print("Download complete")

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(target_dir)

        os.rename(
            os.path.join(PROGRAMS_DIR, extract_dir),
            os.path.join(PROGRAMS_DIR, target_folder),
        )
        os.remove(zip_path)

        searchsploit_binary = os.path.join(target_dir, "exploitdb", "searchsploit")
        if os.path.exists(searchsploit_binary):
            st = os.stat(searchsploit_binary)
            os.chmod(searchsploit_binary, st.st_mode | stat.S_IEXEC)
    except Exception as e:
        print(f"An error occurred during download or extraction: {e}")
    finally:
        if os.path.exists(os.path.join(target_dir, zip_path)):
            print("DELETING")
            os.remove(os.path.join(target_dir, zip_path))


def install() -> None:
    download_nmap()
    download_ffuf()
    download_subfinder()
    download_searchsploit()


if __name__ == "__main__":
    install()
