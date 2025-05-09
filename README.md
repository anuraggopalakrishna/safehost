# Network Traffic Monitoring System

This project is a live network traffic monitoring and threat detection system. It utilizes machine learning to classify traffic and provides real-time visualization via Streamlit and Flask.

## 📦 Dataset

Download the dataset from [CIC Research Page](http://cicresearch.ca//CICDataset/CICDDoS2019/) and place it in the root directory of the project.

## 🛠 Setup

1. **(Optional)** Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   ```
2. Install Dependencies
   ```bash
    pip install -r requirements.txt
   ```
3. Generate the model:
   ```bash
    python model.py
   ```
   This will create a ```.pkl``` file used for classification.
   
## 🚀 Running the System
  
  Start the following components in separate terminals concurrently:

  1. Flask skeleton to listen for requests
     ```bash
     flask run
     ```
  2. Main traffic capture and processing:
     ```bash
     python main.py
     ```
  3. Streamlit dashboard:
     ```bash
     streamlit run streamlit.py
     ```

Wait a couple minutes for the dB to populate and then go to ```http://localhost:8501``` to check out the dashboard!

#### Project built by [Anurag G](https://https://github.com/anuraggopalakrishna)
