from transformers import AutoTokenizer, AutoModelForSequenceClassification
import pandas as pd
import numpy as np
import torch
from tqdm import tqdm
from torch.cuda.amp import autocast
import matplotlib.pyplot as plt
import json


def load_model(model_name="prajjwal1/bert-tiny"):
    """
    Loads a pre-trained model for CVE analysis.

    Args:
        model_name (str): Hugging Face model name.

    Returns:
        tokenizer, model, device: Tokenizer, model, and the device (CPU or GPU).
    """
    print(f"Loading model: {model_name}...")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)  # Move model to GPU if available
    print(f"Model loaded on device: {device}")
    return tokenizer, model, device


def predict_ttps(cve_descriptions, tokenizer, model, device, batch_size=128, max_length=128):
    """
    Predicts TTPs for a list of CVE descriptions using a pre-trained model with batching.

    Args:
        cve_descriptions (list): List of CVE descriptions.
        tokenizer: Tokenizer for the pre-trained model.
        model: Pre-trained model.
        device: Device to run the model on (CPU or GPU).
        batch_size (int): Number of descriptions to process in a single batch.
        max_length (int): Maximum tokenized length for each description.

    Returns:
        list: Predicted TTPs for each CVE.
    """
    print("Predicting TTPs...")
    predictions = []

    for i in tqdm(range(0, len(cve_descriptions), batch_size), desc="Processing Batches"):
        batch = cve_descriptions[i:i + batch_size]
        inputs = tokenizer(batch, return_tensors="pt", truncation=True, padding=True, max_length=max_length).to(device)
        with torch.no_grad():
            with autocast():
                outputs = model(**inputs)
        probs = outputs.logits.softmax(dim=-1).cpu().numpy()
        batch_predictions = np.argmax(probs, axis=1)
        predictions.extend(batch_predictions)

    return predictions


def load_mitre_data(file_path="data/mitre/enterprise-attack.json"):
    """
    Loads MITRE ATT&CK data from a JSON file.

    Args:
        file_path (str): Path to the MITRE ATT&CK JSON file.

    Returns:
        dict: Mapping of TTP IDs to mitigations.
    """
    print(f"Loading MITRE ATT&CK data from {file_path}...")
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    ttp_to_mitigation = {}
    type_counts = {}  # To count occurrences of each type

    for obj in data.get("objects", []):
        obj_type = obj.get("type")
        # Count the occurrences of each type
        type_counts[obj_type] = type_counts.get(obj_type, 0) + 1

        if obj_type == "course-of-action":
            external_references = obj.get("external_references", [])
            for ref in external_references:
                ttp_id = ref.get("external_id")
                mitigation_desc = ref.get("description", obj.get("name", ""))
                if ttp_id and mitigation_desc:
                    if ttp_id not in ttp_to_mitigation:
                        ttp_to_mitigation[ttp_id] = []
                    ttp_to_mitigation[ttp_id].append(mitigation_desc)

    # Print a summary of object types
    print("Summary of object types in the JSON:")
    for obj_type, count in type_counts.items():
        print(f"  {obj_type}: {count}")

    print(f"Loaded {len(ttp_to_mitigation)} TTP mappings.")
    return ttp_to_mitigation


def recommend_countermeasures(ttps, ttp_to_mitigation):
    """
    Recommends countermeasures based on predicted TTPs using MITRE ATT&CK data.

    Args:
        ttps (list): List of predicted TTPs.
        ttp_to_mitigation (dict): Mapping of TTPs to mitigation descriptions.

    Returns:
        list: Recommended countermeasures for each TTP.
    """
    recommendations = []
    for ttp in ttps:
        mitigation = ttp_to_mitigation.get(ttp, ["No recommendation available"])
        recommendations.append(", ".join(mitigation))
    return recommendations


import os
import logging

logger = logging.getLogger(__name__)

def visualize_ttp_distribution(df):
    try:
        ttp_counts = df["TTP"].value_counts()
        ttp_counts.plot(kind="bar", figsize=(10, 6), color="skyblue")
        plt.title("TTP Distribution", fontsize=16)
        plt.xlabel("TTPs", fontsize=12)
        plt.ylabel("Count", fontsize=12)
        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "ttp_distribution.png")
        plt.savefig(output_path)
        plt.close()
        logger.info(f"Visualization saved to {output_path}")
        return output_path
    except Exception as e:
        logger.error(f"Error generating visualization: {e}")
        raise RuntimeError(f"Error generating visualization: {e}")


