import requests
from bs4 import BeautifulSoup
import re
import urllib.request
import ssl
import hashlib
import base64

def get_highest_version(url):
    try:
        # Make a GET request to the URL
        response = requests.get(url)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Parse the HTML content of the page
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all version numbers in the page
            version_numbers = re.findall(r'\d+\.\d+\.\d+', response.text)

            # Get the highest version number
            highest_version = max(version_numbers, key=lambda x: tuple(map(int, x.split('.'))))

            return highest_version
        else:
            print(f"Error: Unable to fetch content from {url}. Status code: {response.status_code}")
    except Exception as e:
        print(f"An error occurred: {e}")

def download_msi(version):
    try:
        # Construct the URL for the MSI file
        msi_url = f"https://dist.scaleft.com/repos/windows/stable/amd64/windows-client/v{version}/ScaleFT-{version}.msi"

        # Specify the local file path where the MSI file will be saved
        local_file_path = f"ScaleFT-{version}.msi"

        # CA file
        ca_file_path = "cafile.pem"

        # Create an SSL context with the specified CA file
        ssl_context = ssl.create_default_context(cafile=ca_file_path)

        # Download the file
        # Open the URL using urlopen with the SSL context
        with urllib.request.urlopen(msi_url, context=ssl_context) as response:
            # Save the content to a local file
            with open(local_file_path, 'wb') as output_file:
                output_file.write(response.read())

        print(f"Downloaded MSI file for version {version} to {local_file_path}")
        return local_file_path
    except Exception as e:
        print(f"An error occurred during download: {e}")
        return None

def get_sha3_512_from_json(version):
    try:
        # Construct the URL for the JSON file
        json_url = f"https://dist.scaleft.com/repos/windows/stable/amd64/windows-client/dull.json"

        # Make a GET request to the JSON URL
        response = requests.get(json_url)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Parse the JSON content
            json_data = response.json()

            # Get the sha3_512 value for the specified version
            sha3_512_value = json_data.get('releases', [{}])[0].get('links', [{}])[0].get('hashes', {}).get('sha3_512')


            if sha3_512_value:
                print(sha3_512_value)
                return sha3_512_value
            else:
                print(f"Sha3_512 value not found for version {version} in the JSON data.")
                return None
        else:
            print(f"Error: Unable to fetch JSON content from {json_url}. Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def calculate_sha3_512(file_path):
    try:
        sha3_512_hash = hashlib.sha3_512()
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                sha3_512_hash.update(chunk)

        # Return the base64-encoded digest
        #print("DEBUG: ", base64.b64encode(sha3_512_hash.digest()).decode('utf-8').rstrip('='))
        encoded_digest = base64.urlsafe_b64encode(sha3_512_hash.digest()).decode('utf-8').rstrip('=')
        return encoded_digest
    except Exception as e:
        print(f"An error occurred during hash calculation: {e}")
        return None

if __name__ == "__main__":
    url = "https://dist.scaleft.com/repos/windows/stable/amd64/windows-client/"
    highest_version = get_highest_version(url)

    if highest_version:
        print(f"The highest version number is: {highest_version}")
        # downloaded_file = download_msi(highest_version)
        # quit hammering site
        downloaded_file = "ScaleFT-1.76.2.msi"

        if downloaded_file:
            sha3_512_from_json = get_sha3_512_from_json(highest_version)
            if sha3_512_from_json:
                sha3_512_calculated = calculate_sha3_512(downloaded_file)

                if sha3_512_calculated:
                    if sha3_512_from_json == sha3_512_calculated:
                        print("File integrity check passed. SHA3-512 values match.")
                    else:
                        print("File integrity check failed. SHA3-512 values do not match.")
                else:
                    print("File integrity check skipped due to hash calculation error.")
            else:
                print("File integrity check skipped. SHA3-512 value from JSON not available.")
        else:
            print("File integrity check skipped. Downloaded file not available.")
    else:
        print("Failed to retrieve version number.")
