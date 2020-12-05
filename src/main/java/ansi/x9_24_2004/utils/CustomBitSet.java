package ansi.x9_24_2004.utils;

import javax.xml.bind.DatatypeConverter;
import java.util.BitSet;

/**
 * <p>This extension to java.util.BitSet provides a "bitSize()" function
 * to better define the requested or desired size of the object, in order to
 * accommodate a more fixed-length paradigm.  Put more simply, if you declare the BitSet
 * to be 5 bits long, this "bitSize()" method will return 5, while the built-in method would
 * return the number of bits allocated for the BitSet which, depending on the implementation,
 * could very well be much larger.
 *
 * <p>The constructors and get(int, int) method are also overridden to ensure the
 * encapsulated environment to the user (i.e. the user will always receive and be using
 * this BitSet, not a java.util.BitSet, unless they explicitly ask for the latter).
 *
 * @author Software Verde: Andrew Groot
 * @author Software Verde: Josh Green
 */
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
        int size = (int) Math.ceil(this.size() / 8.0d);
        byte[] value = new byte[size];
        for (int i = 0; i < size; i++) {
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
				if ((bytes[i] & (1L << j)) > 0) {
					this.set(8 * i + (7 - j));
				}
			}
		}
	}

    public static CustomBitSet toBitSet(final String value) {
        return new CustomBitSet(DatatypeConverter.parseHexBinary(value));
    }

    private static byte toByte(final CustomBitSet customBitSet) {
        byte value = 0;
        for (int i = 0; i < customBitSet.size(); i++) {
            if (customBitSet.get(i)) {
                value = (byte) (value | (1L << 7 - i));
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
