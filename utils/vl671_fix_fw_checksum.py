import sys
import struct

def crc8(data: bytes) -> int:
    """
    Calculate CRC8 using the given algorithm.

    Args:
        data (bytes): Input data as a bytes object.

    Returns:
        int: Calculated CRC8 value.
    """
    v5 = 0  # Initialize the CRC accumulator
    for byte in data:
        v5 ^= byte << 8  # XOR the current byte shifted to the upper byte of v5
        for _ in range(8):
            if v5 & 0x8000:  # Check if the highest bit is set
                v5 ^= 0x8380  # XOR with the polynomial
            v5 *= 2  # Shift left
        v5 &= 0xFFFF  # Ensure v5 remains within 16 bits

    return (v5 >> 8) & 0xFF  # Return the upper byte as the CRC8 result

def crc32(data: bytes, poly=0x04C11DB7, init=0x0, xorout=0x0) -> int:
    """
    Calculate CRC32 using the given algorithm.

    Args:
        data (bytes): Input data as a bytes object.
        poly (int): CRC polynomial.
        init (int): Initial CRC value.
        xorout (int): Final XOR value.

    Returns:
        int: Calculated CRC32 value.
    """
    crc = init
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFFFFFF  # Ensure CRC remains within 32 bits
    return crc ^ xorout

def fix_firmware_checksum(file_path: str):
    """
    Fix the checksums of a firmware file.
    The first checksum (CRC8) is for bytes 0x0 to 0x1E and is stored at 0x1F.
    The second checksum (CRC32) is for the payload, calculated based on its offset and size in the header.

    Args:
        file_path (str): Path to the firmware file.
    """
    try:
        with open(file_path, "r+b") as f:
            # Fix CRC8 checksum for the header
            f.seek(0)
            header = f.read(0x1F)

            if len(header) < 0x1F:
                raise ValueError("File is too small to contain required header bytes for CRC8 calculation.")

            crc8_checksum = crc8(header)
            f.seek(0x1F)
            f.write(bytes([crc8_checksum]))

            # Read payload offset and size from the header
            f.seek(0x4)
            payload_offset = struct.unpack('>H', f.read(2))[0]  # Big-endian
            payload_size = struct.unpack('>H', f.read(2))[0]  # Big-endian

            if payload_size < 4:
                raise ValueError("Payload size in header is too small to contain checksum.")

            # Read the payload data
            f.seek(payload_offset)
            payload = f.read(payload_size - 4)  # Exclude the checksum itself

            if len(payload) != payload_size - 4:
                raise ValueError("File is too small to contain the entire payload.")

            # Calculate CRC32 checksum for the payload
            crc32_checksum = crc32(payload)

            # Write the CRC32 checksum at the end of the payload (little-endian)
            f.seek(payload_offset + payload_size - 4)
            f.write(struct.pack('<I', crc32_checksum))

        print(f"Checksums fixed successfully for file: {file_path}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python fix_firmware_checksum.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    fix_firmware_checksum(file_path)

