import requests
import pandas as pd

# Define the NVD API 2.0 base URL
base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Define parameters for the API request
params = {
    'pubStartDate': '2023-01-01T00:00:00.000',  # Start date
    'pubEndDate': '2023-12-31T23:59:59.999',    # End date
    'startIndex': 0,                            # Pagination index
    'resultsPerPage': 200                       # Number of results per page
}

# Initialize an empty list to store CVE data
cve_list = []

# Fetch data in pages
while True:
    print(f"Fetching data starting from index {params['startIndex']}...")
    response = requests.get(base_url)

    if response.status_code == 200:
        data = response.json()  # Parse JSON response
        cve_items = data.get('vulnerabilities', [])
        
        # Extract relevant fields from each CVE
        for item in cve_items:
            cve_id = item['cve']['id']
            description = item['cve']['descriptions'][0]['value']
            impact = item.get('cve', {}).get('metrics', {}).get('cvssMetricV2', [{}])[0].get('baseSeverity', 'N/A')
            cve_list.append({
                'CVE_ID': cve_id,
                'Description': description,
                'Impact': impact
            })
        
        # Check if more pages are available
        total_results = data.get('totalResults', 0)
        params['startIndex'] += params['resultsPerPage']  # Move to the next page

        if params['startIndex'] >= total_results:
            print("All data fetched.")
            break
    else:
        print(f"Failed to fetch data. Status code: {response.status_code}")
        break

# Convert the CVE list to a DataFrame
df_cve = pd.DataFrame(cve_list)

# Save the data to a CSV file
output_file = "cve_data_api2.csv"
df_cve.to_csv(output_file, index=False)
print(f"CVE data saved to {output_file}")
