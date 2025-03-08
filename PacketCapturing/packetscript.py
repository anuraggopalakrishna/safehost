import pyshark
import psutil


def capture_packets(interface):
    # Capture packets in promiscuous mode with a filter for port 5000
    capture = pyshark.LiveCapture(
        interface=interface, bpf_filter="tcp port 5000"
    )

    print("Starting packet capture on interface:", interface)
    for packet in capture.sniff_continuously():
        try:
            print("Packet captured:")
            print(packet)
        except Exception as e:
            print("Error processing packet:", e)


if __name__ == "__main__":
    interface = "\\Device\\NPF_Loopback"
    if interface:
        capture_packets(interface)
    else:
        print("Loopback interface not found")
