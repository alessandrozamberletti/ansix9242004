package ansix9242004.utils;

import java.io.ByteArrayOutputStream;

public class ByteArrayUtils {

    public static byte[] concat(byte[] first, byte[] second) {
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            byteArrayOutputStream.write(first);
            byteArrayOutputStream.write(second);
            return byteArrayOutputStream.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
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
