#!/bin/bash
mkdir -p models
echo "Models directory initialized" > models/.gitkeep
python -c "from terrasafe.infrastructure.ml_model import MLPredictor; MLPredictor()"
