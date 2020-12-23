package ansi.x9_24_2004.dukpt;

import ansi.x9_24_2004.utils.BitArray;

public enum IfsfKeyMask {

    KEY_REGISTER_BITMASK("C0C0C0C000000000C0C0C0C000000000"),

    // Mask 1: PIN block encryption
    REQUEST_PIN_MASK("00000000000000FF00000000000000FF"),
    // Mask 2: MAC calculation (bi-directional)
    REQUEST_MAC_MASK("000000000000FF00000000000000FF00"),
    // Mask 4: FEP to POS (only 2009)
    RESPONSE_MAC_MASK("00000000FF00000000000000FF000000"),
    // Mask 3: Data encryption (bi-directional)
    REQUEST_DATA_MASK("0000000000FF00000000000000FF0000");

    private String value;

    IfsfKeyMask(String value) {
        this.value = value;
    }

    public BitArray value() {
        return new BitArray(value);
    }

    @Override
    public String toString() {
        return value;
    }

}
