# Wireshark Packet Data Analyzer

This is a Streamlit-based application that allows users to analyze packet data using Google's Gemini AI model. The app provides different packet data samples and generates a security analysis for the selected sample.

## Prerequisites

- Python 3.x installed
- Streamlit library installed
- Google Generative AI (`google-generativeai`) package installed

## Installation

1. Clone the repository or download the script.
2. Install the required dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Usage

1. Replace `YOUR_API_KEY` in the script with your actual Google Gemini API key.
2. Run the application with the following command:
   ```sh
   streamlit run app.py
   ```
3. Select a packet data sample from the dropdown menu.
4. Click the **Analyze Packet Data** button to get an AI-generated security analysis.

## Features

- Provides sample packet data (HTTP, DNS, TCP Handshake, etc.)
- Uses Google Gemini AI to analyze security risks
- Displays formatted packet data for easy review

## Notes

- Ensure you have a valid Google Gemini API key before running the app.
- The application requires an active internet connection to interact with the Gemini AI model.


