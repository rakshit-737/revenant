# The authors' evaluate.py (ATLAS, USENIX Security 2021) needs only numpy,
# scikit-learn and matplotlib; versions contemporary with Python 3.7.
FROM python:3.7-slim
RUN pip install --no-cache-dir numpy==1.18.5 scikit-learn==0.23.2 matplotlib==3.3.4
ENV MPLBACKEND=Agg
