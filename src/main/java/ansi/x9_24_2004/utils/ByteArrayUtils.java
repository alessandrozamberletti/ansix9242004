package ansi.x9_24_2004.utils;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

public final class ByteArrayUtils {

    private ByteArrayUtils() {

    }

    public static byte[] concat(final byte[] first,
                                final byte[] second) {
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            byteArrayOutputStream.write(first);
            byteArrayOutputStream.write(second);
            return byteArrayOutputStream.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Error while concatenating '" + Arrays.toString(first) + "' and '" + Arrays.toString(second) + "'",
                    e
            );
        }
    }

}
