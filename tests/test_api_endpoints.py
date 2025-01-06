from fastapi.testclient import TestClient
from api.main import app
import os

client = TestClient(app)

# Set up mock data
MOCK_CSV = "tests/mock_cve_data.csv"
MOCK_EMPTY_CSV = "tests/mock_empty_data.csv"
MOCK_INVALID_FILE = "tests/mock_invalid.txt"
os.makedirs("tests", exist_ok=True)

# Create mock data files
with open(MOCK_CSV, "w") as f:
    f.write("Description\nSample vulnerability description 1\nSample vulnerability description 2")

with open(MOCK_EMPTY_CSV, "w") as f:
    f.write("Description\n")

with open(MOCK_INVALID_FILE, "w") as f:
    f.write("This is not a CSV file.")

def test_root_endpoint():
    """Test the root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "API is running"}

def test_predict_with_valid_csv():
    """Test /predict/ with a valid CSV file."""
    with open(MOCK_CSV, "rb") as file:
        response = client.post(
            "/predict/",
            headers={"x-api-key": "mysecureapikey"},
            files={"file": file},
        )
    assert response.status_code == 200
    assert "Predictions generated successfully." in response.json()["message"]

def test_predict_with_empty_csv():
    """Test /predict/ with an empty CSV file."""
    with open(MOCK_EMPTY_CSV, "rb") as file:
        response = client.post(
            "/predict/",
            headers={"x-api-key": "mysecureapikey"},
            files={"file": file},
        )
    assert response.status_code == 400
    assert "Uploaded CSV file is empty." in response.json()["detail"]

def test_predict_with_invalid_file_type():
    """Test /predict/ with an invalid file type."""
    with open(MOCK_INVALID_FILE, "rb") as file:
        response = client.post(
            "/predict/",
            headers={"x-api-key": "mysecureapikey"},
            files={"file": file},
        )
    assert response.status_code == 400
    assert "Only CSV files are supported." in response.json()["detail"]

def test_predict_without_api_key():
    """Test /predict/ without an API key."""
    with open(MOCK_CSV, "rb") as file:
        response = client.post(
            "/predict/",
            files={"file": file},
        )
    assert response.status_code == 403
    assert "Invalid or missing API key" in response.json()["detail"]


def test_visualize_with_existing_data():
    """Test /visualize/ with existing processed data."""
    # Simulate existing processed data
    os.makedirs("output", exist_ok=True)
    processed_csv = "output/predicted_cve_data.csv"
    with open(processed_csv, "w") as f:
        f.write("TTP,Recommendation\nT1,Mitigation 1\nT2,Mitigation 2\nT1,Mitigation 1")

    response = client.get(
        "/visualize/",
        headers={"x-api-key": "mysecureapikey"},
    )
    assert response.status_code == 200
    assert "Visualization generated successfully." in response.json()["message"]
    assert "output/ttp_distribution.png" in response.json()["visualization"]

def test_visualize_without_existing_data():
    """Test /visualize/ without existing processed data."""
    if os.path.exists("output/predicted_cve_data.csv"):
        os.remove("output/predicted_cve_data.csv")

    response = client.get(
        "/visualize/",
        headers={"x-api-key": "mysecureapikey"},
    )
    assert response.status_code == 404
    assert "No processed data found." in response.json()["detail"]



    # PYTHONPATH=. pytest tests/     //for test the endpoints
    # uvicorn api.main:app --host=0.0.0.0 --port=8000    // for start the server
    

