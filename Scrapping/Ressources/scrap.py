import requests
from bs4 import BeautifulSoup
import os

def scrape_readme(base_url, current_path="", output_file="readme_contents.txt"):
    url = os.path.join(base_url, current_path)
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        links = soup.find_all("a", href=True)

        for link in links:
            href = link["href"]
            if href in ["../", "/"]:
                continue
            if href.lower() == "readme":
                readme_url = os.path.join(url, href)
                try:
                    readme_response = requests.get(readme_url)
                    readme_response.raise_for_status()
                    with open(output_file, "a") as f:
                        f.write(f"README found at {readme_url}:\n")
                        f.write(readme_response.text)
                        f.write("\n" + "="*50 + "\n") 

                    print(f"Saved README content from {readme_url}")

                except requests.RequestException as e:
                    print(f"Error reading README at {readme_url}: {e}")
            elif href.endswith("/"):
                scrape_readme(base_url, os.path.join(current_path, href), output_file)

    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")
base_url = "http://10.12.181.103/.hidden/"
output_file = "readme_contents.txt"
open(output_file, "w").close()
scrape_readme(base_url, output_file=output_file)
print(f"All README contents have been saved to {output_file}.")
