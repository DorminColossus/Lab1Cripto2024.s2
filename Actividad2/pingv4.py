from scapy.all import *
import sys
import time
import struct

def send_custom_icmp_message(message):
    # Parámetros fijos del paquete ICMP (extraídos del frame original)
    src_ip = "192.168.1.142"
    dst_ip = "8.8.8.8"
    base_icmp_id = 2
    base_icmp_seq = 1
    base_timestamp = 0x4ad30900  # Timestamp extraído del frame original (en hex)
    payload_prefix = bytes.fromhex("4a d3 09 00 00 00 00 00")  # Primeros 8 bytes del payload original
    payload_suffix = bytes.fromhex("10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37")

    icmp_seq = base_icmp_seq
    icmp_id = base_icmp_id

    # Configuración del timestamp
    timestamp = struct.pack('!I', base_timestamp)

    for char in message:
        # Construir el payload ICMP
        char_payload = bytes([char.encode('ascii')[0]])
        payload = payload_prefix + timestamp + payload_suffix[:48 - len(payload_prefix) - len(timestamp) - 1] + char_payload

        # Crear el paquete ICMP
        ip_packet = IP(src=src_ip, dst=dst_ip, id=0xe80d, flags="DF")  # Ajustar id y flags
        icmp_packet = ICMP(id=icmp_id, seq=icmp_seq)
        raw_data = Raw(load=payload)

        # El paquete IP y ICMP con el payload
        packet = ip_packet/icmp_packet/raw_data

        # Calcular el checksum ICMP
        packet[ICMP].chksum = None  # Scapy lo recalculará automáticamente
        packet[IP].chksum = None  # Scapy lo recalculará automáticamente

        # Enviar el paquete
        send(packet, verbose=0)

        print(f"Sent packet with ID={icmp_id}, Seq={icmp_seq}")

        # Incrementar el número de secuencia
        icmp_seq = (icmp_seq % 256) + 1
        icmp_id += 1  # Incrementa el ID ICMP para cada paquete

        # Esperar un poco entre paquetes para no saturar la red
        time.sleep(0.1)

    print("Finished sending packets")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sudo python3 pingv4.py <message>")
        sys.exit(1)
    
    message = sys.argv[1]
    send_custom_icmp_message(message)
