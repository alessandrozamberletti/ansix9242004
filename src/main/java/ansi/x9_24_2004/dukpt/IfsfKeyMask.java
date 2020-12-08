package ansi.x9_24_2004.dukpt;

import ansi.x9_24_2004.utils.CustomBitSet;

public enum IfsfKeyMask {

    KEY_REGISTER_BITMASK("C0C0C0C000000000C0C0C0C000000000"),

    // Mask 1: PIN block encryption 00 00 00 00 00 00 00 FF || 00 00 00 00 00 00 00 FF
    REQUEST_PIN_MASK("00000000000000FF00000000000000FF"),
    // Mask 2: MAC calculation (bi-directional)
    REQUEST_MAC_MASK("000000000000FF00000000000000FF00"),
    // Mask 3: Data encryption (bi-directional)
    REQUEST_DATA_MASK("0000000000FF00000000000000FF0000");

    private String value;

    IfsfKeyMask(String value) {
        this.value = value;
    }

    public CustomBitSet value() {
        return new CustomBitSet(value);
    }

    @Override
    public String toString() {
        return value;
    }

}
