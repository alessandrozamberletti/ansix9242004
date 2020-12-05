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

}
