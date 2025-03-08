import streamlit as st
import google.generativeai as genai

gemini_api_key = "AIzaSyBeVqw-w3rI_gcEWGTwphYI5DP-ldJJVZk"


# Function to analyze packet data using gemini
def analyze_packet_data(packet_data, api_key):

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(
            f"Analyze the following packet data for security issues and provide an explanation. Start with a classification whether it is 'SAFE', 'THREAT' or 'VULNERABILITY':\n{packet_data}"
        )
        analysis = response.text
        return analysis
    except Exception as e:
        st.error(f"Error analyzing packet data: {e}")
        return None


# Streamlit application layout
st.set_page_config(page_title="Packet Data Analyzer", layout="wide")
st.title("Wireshark Packet Data Analyzer")

# Dropdown to select packet data samples
packet_samples = {
    "HTTP Traffic": """Frame 1: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)
Ethernet II, Src: 00:0c:29:3e:8c:6b, Dst: 00:0c:29:f2:e4:5d
Internet Protocol Version 4, Src: 192.168.1.2, Dst: 93.184.216.34
Transmission Control Protocol, Src Port: 54321, Dst Port: 80
Hypertext Transfer Protocol""",
    "DNS Query": """Frame 2: 85 bytes on wire (680 bits), 85 bytes captured (680 bits)
Ethernet II, Src: 00:0c:29:f2:e4:5d, Dst: ff:ff:ff:ff:ff:ff
Internet Protocol Version 4, Src: 192.168.1.2, Dst: 224.0.0.251
User Datagram Protocol, Src Port: 5353, Dst Port: 5353
Domain Name System (query)""",
    "TCP Handshake": """Frame 3: 66 bytes on wire (528 bits), 66 bytes captured (528 bits)
Ethernet II, Src: 00:0c:29:f2:e4:5d, Dst: 00:0c:29:a5:b7:c7
Internet Protocol Version 4, Src: 192.168.1.2, Dst: 192.168.1.3
Transmission Control Protocol, Src Port: 12345, Dst Port: 80""",
    "ARP Request": """Frame 4: 42 bytes on wire (336 bits), 42 bytes captured (336 bits)
Ethernet II, Src: 00:0c:29:f2:e4:5d, Dst: ff:ff:ff:ff:ff:ff
Address Resolution Protocol (request)""",
    "ICMP Echo Request/Reply": """Frame 5-6:
Frame 5:
Internet Control Message Protocol
Type: Echo (ping) Request
Code: 0
Identifier (PID): 0x0001
Sequence number: 0x0001

Frame 6:
Internet Control Message Protocol
Type: Echo (ping) Reply
Code: 0
Identifier (PID): 0x0001
Sequence number: 0x0001""",
    "FTP Command and Response": """Frame 7-8:
Frame 7:
File Transfer Protocol
Command/Response Code : USER

Frame 8:
File Transfer Protocol
Command/Response Code : 230 User logged in""",
    "TLS Handshake": """Frame 9-10:
Frame 9:
Transport Layer Security Protocol
Client Hello

Frame 10:
Transport Layer Security Protocol
Server Hello""",
    "SMTP Email Transmission": """Frame 11-12:
Frame 11:
Simple Mail Transfer Protocol
Command/Response Code : HELO

Frame 12:
Simple Mail Transfer Protocol
Command/Response Code :250 OK""",
    "DHCP Discover": """Frame 13:
Dynamic Host Configuration Protocol (Discover)
Message type : Discover (1)
Client IP address : 0.0.0.0
Your (client) IP address : 0.0.0.0
Server IP address : 0.0.0.0
Client MAC address :00:c0:a8:b7:c8:d9""",
    "HTTP POST Request": """Frame 14:
Hypertext Transfer Protocol
POST /submit HTTP/1.1
Host : example.com
Content-Type : application/x-www-form-urlencoded

Body data : name=John&age=30""",
}

selected_packet = st.selectbox(
    "Select a packet data sample to analyze:", list(packet_samples.keys())
)

# Display selected packet data sample
st.subheader("Selected Packet Data:")
st.code(packet_samples[selected_packet], language="plaintext")

# Button to analyze the selected packet data sample
if st.button("Analyze Packet Data"):
    if gemini_api_key:
        analysis_result = analyze_packet_data(
            packet_samples[selected_packet], gemini_api_key
        )
        if analysis_result:
            st.subheader("Analysis Result:")
            st.write(analysis_result)
    else:
        st.error("API Key is invalid.")
