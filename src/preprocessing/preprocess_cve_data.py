import sys
import os
import pandas as pd

# Add the project root directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# Import the CVE list from fetch_cve_data
from src.data_fetch.fetch_cve_data import cve_list

def preprocess_cve_data(cve_list, output_path="data/processed/processed_cve_data.csv"):
    """
    Preprocesses the raw CVE data and saves it to a CSV file.
    
    Args:
        cve_list (list): List of CVE records fetched from the API.
        output_path (str): Path to save the processed CSV file.
    """
    # Convert the CVE list into a Pandas DataFrame
    df_cve = pd.DataFrame(cve_list)
    
    # Display a sample of the data
    print("Sample of CVE Data:")
    print(df_cve.head())
    
    # Save the cleaned data into a CSV file
    df_cve.to_csv(output_path, index=False)
    print(f"Processed CVE data saved to {output_path}")

# Example usage
if __name__ == "__main__":
    # Preprocess and save the data
    preprocess_cve_data(cve_list)
