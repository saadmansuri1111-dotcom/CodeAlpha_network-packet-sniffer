from scapy.all import sniff, conf
try:
    sniff(count=1, timeout=2)
except RuntimeError as e:
    if "winpcap is not installed" in str(e):
        print("Falling back to L3socket")
        sniff(count=1, timeout=2, opened_socket=conf.L3socket())
