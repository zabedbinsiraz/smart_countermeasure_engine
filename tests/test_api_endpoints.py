from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

API_KEY = "mysecureapikey"

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "API is running"}

def test_predict():
    file_path = "data/processed/processed_cve_data.csv"
    with open(file_path, "rb") as f:
        response = client.post(
            "/predict/",
            headers={"x-api-key": API_KEY},
            files={"file": f},
        )
    assert response.status_code == 200
    assert "output_file" in response.json()

def test_visualize():
    response = client.get(
        "/visualize/",
        headers={"x-api-key": API_KEY}
    )
    assert response.status_code == 200
    assert "visualization" in response.json()
