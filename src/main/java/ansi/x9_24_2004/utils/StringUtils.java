package ansi.x9_24_2004.utils;

public final class StringUtils {

    private StringUtils() {

    }

    public static String rightPad(final String element, final int targetLength, final char filler) {
        final String elementFormat = "%-" + targetLength + "s";
        return String.format(elementFormat, element).replace(' ', filler);
    }

    public static String leftPad(final String element, final int targetLength, final char filler) {
        final String elementFormat = "%" + targetLength + "s";
        return String.format(elementFormat, element).replace(' ', filler);
    }

}
