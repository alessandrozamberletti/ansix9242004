package ansi.x9_24_2004.utils;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.stream.Collectors;

public final class ByteArrayUtils {

    private ByteArrayUtils() {

    }

    public static byte[] concat(final byte[] ... arrays) {
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            for (byte[] array : arrays) {
                byteArrayOutputStream.write(array);
            }
            return byteArrayOutputStream.toByteArray();
        } catch (Exception e) {
            final String message =
                    Arrays.stream(arrays).sequential().map(x -> " " + Arrays.toString(x)).collect(Collectors.joining());
            throw new IllegalStateException(
                    "Error while concatenating: '" + message.trim() + "'",
                    e
            );
        }
    }

}
