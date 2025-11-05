#!/bin/bash

# Path to your Conda installation (e.g., Miniconda3)
CONDA_PATH="~/miniconda" 

# Name of your Conda environment
CONDA_ENV="FTPVoicemailEmail"

# Activate the Conda environment
source "$CONDA_PATH/bin/activate" "$CONDA_ENV"

# Execute your application
gunicorn --bind 0.0.0.0:5000 wsgi:app