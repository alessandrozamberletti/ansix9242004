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
	public static final int DEFAULT_SIZE = 8;
	private static final long serialVersionUID = 1L;
	private int size;

	public CustomBitSet() {
		super(DEFAULT_SIZE);
		size = DEFAULT_SIZE;
	}

	public CustomBitSet(int nbits) {
		super(nbits);
		size = nbits;
	}

	private static CustomBitSet fromBitSet(final BitSet bitSet) {
		final CustomBitSet customBitSet = new CustomBitSet(bitSet.size());
		for(int i=0; i<bitSet.length(); i++) {
			if (bitSet.get(i)) {
				customBitSet.set(i);
			}
		}
		return customBitSet;
	}

	@Override
	public CustomBitSet get(int low, int high) {
		return fromBitSet(super.get(low, high));
	}

	public int bitSize() {
		return size;
	}

	public static byte[] toByteArray(CustomBitSet b) {
		int size = (int) Math.ceil(b.bitSize() / 8.0d);
		byte[] value = new byte[size];
		for (int i = 0; i < size; i++) {
			value[i] = toByte(b.get(i * 8, Math.min(b.bitSize(), (i + 1) * 8)));
		}
		return value;
	}

	public static byte toByte(CustomBitSet b) {
		byte value = 0;
		for (int i = 0; i < b.bitSize(); i++) {
			if (b.get(i))
				value = (byte) (value | (1L << 7 - i));
		}
		return value;
	}

	public static CustomBitSet toBitSet(final String value) {
		return ByteArrayUtils.toBitSet(DatatypeConverter.parseHexBinary(value));
	}

	@Override
	public String toString() {
		return DatatypeConverter.printHexBinary(toByteArray(this));
	}

}
