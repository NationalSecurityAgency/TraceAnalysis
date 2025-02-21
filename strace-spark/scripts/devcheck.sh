#! /bin/bash

echo "isort:"
isort $(fd --glob '*.py' ./src/ )

echo "black:"
black $(fd --glob '*.py' ./src/ )
echo "Pylint:"
pylint ./src/

echo "Flake8:"
flake8 src/

echo "MyPy:"
mypy src/
