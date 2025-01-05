import sys
import os
import pandas as pd
from src.models.countermeasure_engine import (
    load_model,
    predict_ttps,
    recommend_countermeasures,
    visualize_ttp_distribution,
    load_mitre_data,
)

# Add the src directory to sys.path
project_root = os.path.abspath(os.path.dirname(__file__))
src_path = os.path.join(project_root, "src")
sys.path.append(src_path)

if __name__ == "__main__":
    # Step 1: Load processed CVE data
    input_file = "data/processed/processed_cve_data.csv"
    try:
        df = pd.read_csv(input_file)
        print("Loaded DataFrame:")
        print(df.head())
        print(f"Number of rows: {len(df)}")
    except FileNotFoundError:
        print(f"Error: Processed CVE data not found at {input_file}")
        exit(1)

    # Step 2: Load MITRE ATT&CK data
    mitre_file = "data/mitre/enterprise-attack.json"
    print(f"Loading MITRE ATT&CK data from {mitre_file}...")
    try:
        ttp_to_mitigation = load_mitre_data(mitre_file)
        print(f"Loaded {len(ttp_to_mitigation)} TTP mappings.")
    except Exception as e:
        print(f"Error loading MITRE ATT&CK data: {e}")
        exit(1)

    # Step 3: Load model
    model_name = "prajjwal1/bert-tiny"
    print(f"Loading model: {model_name}...")
    try:
        tokenizer, model, device = load_model(model_name)
        print("Model loaded successfully.")
    except Exception as e:
        print(f"Error loading model: {e}")
        exit(1)

    # Step 4: Predict TTPs
    print("Predicting TTPs for CVE descriptions...")
    descriptions = df["Description"].tolist()
    print(f"Sample descriptions: {descriptions[:5]}")
    try:
        ttps = predict_ttps(descriptions, tokenizer, model, device)
        print(f"Sample TTP predictions: {ttps[:5]}")
    except Exception as e:
        print(f"Error during TTP prediction: {e}")
        exit(1)

    # Step 5: Recommend countermeasures
    print("Generating countermeasure recommendations...")
    try:
        recommendations = recommend_countermeasures(ttps, ttp_to_mitigation)
        print(f"Sample recommendations: {recommendations[:5]}")
    except Exception as e:
        print(f"Error generating recommendations: {e}")
        exit(1)

    # Step 6: Save updated data
    print("Saving updated data...")
    output_file = "data/processed/cve_with_recommendations.csv"
    try:
        df["TTP"] = ttps
        df["Recommendation"] = recommendations
        df.to_csv(output_file, index=False)
        print(f"Updated CVE data with recommendations saved to {output_file}")
    except Exception as e:
        print(f"Error saving updated data: {e}")
        exit(1)

    # Step 7: Visualize TTP distribution
    print("Visualizing TTP distribution...")
    try:
        visualize_ttp_distribution(df)
    except Exception as e:
        print(f"Error visualizing TTP distribution: {e}")
