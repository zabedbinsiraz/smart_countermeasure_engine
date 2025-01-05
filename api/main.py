from fastapi import FastAPI, UploadFile, HTTPException, Header, Depends
import pandas as pd
from src.models.countermeasure_engine import (
    load_model,
    predict_ttps,
    recommend_countermeasures,
    load_mitre_data,
    visualize_ttp_distribution,
)
import os
import tempfile
import logging

# Initialize FastAPI app
app = FastAPI()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Authentication setup
API_KEY = "mysecureapikey"

def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        logger.warning("Unauthorized access attempt with invalid API key.")
        raise HTTPException(status_code=403, detail="Invalid API key")

# Load model and MITRE data at startup
model_name = "prajjwal1/bert-tiny"
logger.info("Loading model and data...")
tokenizer, model, device = load_model(model_name)
mitre_file = "data/mitre/enterprise-attack.json"
ttp_to_mitigation = load_mitre_data(mitre_file)
logger.info("Model and data loaded successfully.")

@app.get("/")
def root():
    """
    Root endpoint to check API status.
    """
    return {"message": "API is running"}

@app.post("/predict/", dependencies=[Depends(verify_api_key)])
async def predict_ttp(file: UploadFile):
    """
    Predict TTPs from uploaded CVE data and recommend countermeasures.
    """
    logger.info("Received file for prediction.")
    if not file.filename.endswith(".csv"):
        logger.error("Invalid file type uploaded.")
        raise HTTPException(status_code=400, detail="Only CSV files are supported.")

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(file.file.read())
        tmp_path = tmp.name

    try:
        df = pd.read_csv(tmp_path)
    except Exception as e:
        logger.error(f"Error reading CSV file: {e}")
        raise HTTPException(status_code=400, detail=f"Error reading CSV file: {e}")

    if "Description" not in df.columns:
        logger.error("Missing 'Description' column in uploaded file.")
        raise HTTPException(status_code=400, detail="Missing 'Description' column in the CSV file.")

    descriptions = df["Description"].tolist()
    ttps = predict_ttps(descriptions, tokenizer, model, device)
    recommendations = recommend_countermeasures(ttps, ttp_to_mitigation)

    df["TTP"] = ttps
    df["Recommendation"] = recommendations

    output_path = "output/predicted_cve_data.csv"
    df.to_csv(output_path, index=False)
    logger.info(f"Predictions saved to {output_path}")

    return {"message": "Predictions generated successfully.", "output_file": output_path}

@app.get("/visualize/", dependencies=[Depends(verify_api_key)])
def visualize_ttp_distribution_endpoint():
    """
    Visualize TTP distribution for the last processed dataset.
    """
    output_file = "output/predicted_cve_data.csv"
    if not os.path.exists(output_file):
        logger.error("No processed data found for visualization.")
        raise HTTPException(status_code=404, detail="No processed data found. Please upload a file first.")

    df = pd.read_csv(output_file)
    visualize_ttp_distribution(df)
    logger.info("TTP distribution visualization generated.")

    return {"message": "Visualization generated successfully.", "visualization": "output/ttp_distribution.png"}
