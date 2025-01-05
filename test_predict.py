import requests

url = "http://localhost:8081/predict/"
headers = {"x-api-key": "mysecureapikey"}
file_path = "data/processed/processed_cve_data.csv"

with open(file_path, "rb") as file:
    response = requests.post(url, headers=headers, files={"file": file})

print("Status Code:", response.status_code)
print("Response:", response.json())
