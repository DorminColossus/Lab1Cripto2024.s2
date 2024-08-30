import sys

def cifrado_cesar(mensaje, corrimiento):
    resultado = []
    for caracter in mensaje:
        if caracter.isalpha():
            ascii_offset = 65 if caracter.isupper() else 97
            # Desplazamiento del caracter basado en el corrimiento
            nuevo_caracter = chr((ord(caracter) - ascii_offset + corrimiento) % 26 + ascii_offset)
            resultado.append(nuevo_caracter)
        else:
            resultado.append(caracter)  # Mantener espacios y otros caracteres intactos
    return ''.join(resultado)

if __name__ == "__main__":
    # Verifica que se hayan pasado los argumentos correctos
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py \"mensaje\" corrimiento")
        sys.exit(1)

    mensaje = sys.argv[1]
    corrimiento = int(sys.argv[2])

    mensaje_cifrado = cifrado_cesar(mensaje, corrimiento)
    print(mensaje_cifrado)
