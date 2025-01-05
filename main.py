import os

directories = [
    "data/raw",
    "data/processed",
    "src/data_fetch",
    "src/preprocessing",
    "src/models",
    "src/utils",
    "notebooks",
    "tests",
    "output"
]

for directory in directories:
    os.makedirs(directory, exist_ok=True)
print("Project structure created!")
