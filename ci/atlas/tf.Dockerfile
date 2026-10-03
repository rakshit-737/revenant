# Environment for re-running ATLAS's released model.h5 (atlas.py, testing mode).
# Pins follow the ATLAS README (Python 3.7.7, TensorFlow 2.3.0, keras 2.4.3,
# fuzzywuzzy 0.18.0, numpy 1.16.6, networkx 2.2); python:3.7-slim is 3.7.17.
# h5py/scipy/protobuf are pinned to what TensorFlow 2.3.0 itself requires.
FROM python:3.7-slim
RUN pip install --no-cache-dir tensorflow==2.3.0 keras==2.4.3 fuzzywuzzy==0.18.0 numpy==1.16.6 \
        networkx==2.2 h5py==2.10.0 scipy==1.4.1 protobuf==3.20.3 scikit-learn==0.23.2 matplotlib==3.3.4
ENV MPLBACKEND=Agg TF_CPP_MIN_LOG_LEVEL=2 PYTHONUNBUFFERED=1
