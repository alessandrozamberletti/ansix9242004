package ansi.x9_24_2004.pin;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayOutputStream;

public class PinProcessor {

    public String decodeIso0PinBlock(final byte[] iso0PinBlock, String pan) {
        final byte[] clearPanBlock = DatatypeConverter.parseHexBinary(getAccountNumberBlock(pan));

        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            for (int i = 0; i < 8; i++) {
                byteArrayOutputStream.write(iso0PinBlock[i] ^ clearPanBlock[i]);
            }
            final String pinData = DatatypeConverter.printHexBinary(byteArrayOutputStream.toByteArray());
            final int pinLength = Integer.parseInt(pinData.substring(0, 2));
            return pinData.substring(2, 2 + pinLength);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String getAccountNumberBlock(String pan) {
        final String accountNumberBlock = pan.substring(Math.max(0, pan.length() - 13), pan.length() - 1);
        return String.format("%16s", accountNumberBlock).replace(' ', '0');
    }

}
