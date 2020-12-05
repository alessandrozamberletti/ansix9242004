package ansix9242004.dukpt;

import ansix9242004.utils.BitSet;

public enum Mask {

    KEY_REGISTER_BITMASK("C0C0C0C000000000C0C0C0C000000000"),
    REQUEST_DATA_MASK("0000000000FF00000000000000FF0000"),
    REQUEST_MAC_MASK("000000000000FF00000000000000FF00"),
    PIN_MASK("00000000000000FF00000000000000FF");

    private String value;

    Mask(String value) {
        this.value = value;
    }

    public BitSet value() {
        return BitSet.toBitSet(value);
    }

    @Override
    public String toString() {
        return value;
    }

}
