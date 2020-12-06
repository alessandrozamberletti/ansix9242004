package ansi.x9_24_2004.utils;

import javax.xml.bind.DatatypeConverter;
import java.util.BitSet;

/**
 * Extension of java.util.BitSet created by Andrew Groot and Josh Green (Software Verde).
 *
 * Source: https://github.com/SoftwareVerde/java-dukpt (MIT license).
 */
@SuppressWarnings({"java:S2160"}) // Implement equals, not needed.
public class CustomBitSet extends BitSet {

    private int size;

    public CustomBitSet(int nbits) {
        super(nbits);
        size = nbits;
    }

    public CustomBitSet(final byte[] bytes) {
        super(8 * bytes.length);
        this.size = 8 * bytes.length;
        setBytes(bytes);
    }

    public CustomBitSet(final String value) {
        super(8 * DatatypeConverter.parseHexBinary(value).length);
        final byte[] valueBytes = DatatypeConverter.parseHexBinary(value);
        this.size = 8 * valueBytes.length;
        setBytes(valueBytes);
    }

    @Override
    public CustomBitSet get(int low, int high) {
        return fromBitSet(super.get(low, high));
    }

    @Override
    public int size() {
        return this.size;
    }

    @Override
    public byte[] toByteArray() {
        final int byteSize = this.size() / 8 + ((this.size() % 8 == 0) ? 0 : 1);
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

    private void setBytes(final byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                if ((bytes[i] & 0xff & (1L << j)) > 0) {
                    this.set(8 * i + (7 - j));
                }
            }
        }
    }

    private static byte toByte(final CustomBitSet customBitSet) {
        byte value = 0;
        for (int i = 0; i < customBitSet.size(); i++) {
            if (customBitSet.get(i)) {
                value = (byte) (value & 0xff | (1L << 7 - i));
            }
        }
        return value;
    }

    private static CustomBitSet fromBitSet(final BitSet bitSet) {
        final CustomBitSet customBitSet = new CustomBitSet(bitSet.size());
        for (int i = 0; i < bitSet.length(); i++) {
            if (bitSet.get(i)) {
                customBitSet.set(i);
            }
        }
        return customBitSet;
    }

}
