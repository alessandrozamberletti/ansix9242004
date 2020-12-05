package ansi.x9_24_2004.utils;

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

    public static ansi.x9_24_2004.utils.BitSet toBitSet(byte[] b) {
        ansi.x9_24_2004.utils.BitSet bs = new ansi.x9_24_2004.utils.BitSet(8 * b.length);
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
