package ansix9242004.utils;

import java.math.BigInteger;

public class ByteArrayUtils {

    public static String toHex(byte[] bytes) {
        BigInteger bi = new BigInteger(1, bytes);
        return String.format("%0" + (bytes.length << 1) + "X", bi);
    }

    public static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        for (int i = 0; i < a.length; i++) {
            c[i] = a[i];
        }
        for (int i = 0; i < b.length; i++) {
            c[a.length + i] = b[i];
        }
        return c;
    }

    public static BitSet toBitSet(byte[] b) {
        BitSet bs = new BitSet(8 * b.length);
        for (int i = 0; i < b.length; i++) {
            for (int j = 0; j < 8; j++) {
                if ((b[i] & (1L << j)) > 0) {
                    bs.set(8 * i + (7 - j));
                }
            }
        }
        return bs;
    }

}
