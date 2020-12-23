package ansi.x9_24_2004.utils;

import javax.xml.bind.DatatypeConverter;
import java.util.BitSet;

/**
 * Extension of java.util.BitSet created by Andrew Groot and Josh Green (Software Verde).
 *
 * Source: https://github.com/SoftwareVerde/java-dukpt (MIT license).
 */
@SuppressWarnings({"java:S2160"}) // Implement equals, not needed.
public class BitArray extends BitSet {

    private int size;

    private BitArray(int size) {
        super(size);
        this.size = size;
    }

    public BitArray(final byte[] bytes) {
        super(8 * bytes.length);
        setBytes(bytes);
    }

    public BitArray(final String value) {
        super(8 * DatatypeConverter.parseHexBinary(value).length);
        setBytes(DatatypeConverter.parseHexBinary(value));
    }

    private void setBytes(final byte[] bytes) {
        this.size = 8 * bytes.length;
        for (int i = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                if ((bytes[i] & 0xff & (1L << j)) > 0) {
                    this.set(8 * i + (7 - j));
                }
            }
        }
    }

    @Override
    public BitArray get(int low, int high) {
        return fromBitSet(super.get(low, high));
    }

    @Override
    public int size() {
        return this.size;
    }

    @Override
    public byte[] toByteArray() {
        final int byteSize = (this.size + 7) / 8;
        final byte[] value = new byte[byteSize];
        for (int i = 0; i < byteSize; i++) {
            value[i] = toByte(this.get(i * 8, Math.min(this.size, (i + 1) * 8)));
        }
        return value;
    }

    @Override
    public String toString() {
        return DatatypeConverter.printHexBinary(this.toByteArray());
    }

    private static byte toByte(final BitArray bitArray) {
        byte value = 0;
        for (int i = 0; i < bitArray.size(); i++) {
            if (bitArray.get(i)) {
                value = (byte) (value & 0xff | (1L << 7 - i));
            }
        }
        return value;
    }

    private static BitArray fromBitSet(final BitSet bitSet) {
        final BitArray bitArray = new BitArray(bitSet.size());
        for (int i = 0; i < bitSet.length(); i++) {
            if (bitSet.get(i)) {
                bitArray.set(i);
            }
        }
        return bitArray;
    }

}
