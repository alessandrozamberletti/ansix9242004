package ansi.x9_24_2004.pin;

import ansi.x9_24_2004.utils.CustomBitSet;
import ansi.x9_24_2004.utils.StringUtils;

public class PinProcessor {

    public String toIso0Pin(String pin, String pan) {
        // 1 - Prepare a PIN – L is length of the PIN, P is PIN digit, F is padding value “F”
        // 1	2	3	4	5	6	7	8	9	10	11	12	13	14	15	16
        // 0	L	P	P	P	P	P/F	P/F	P/F	P/F	P/F	P/F	P/F	P/F	P/F	P/F
        String iso0FormatPinBlock = "0";
        iso0FormatPinBlock += String.valueOf(pin.length());
        iso0FormatPinBlock += pin;
        iso0FormatPinBlock = StringUtils.rightPad(iso0FormatPinBlock, 16, 'F');

        // 2 - Prepare PAN – take 12 rightmost digits of the primary account number
        // 1	2	3	4	5	6	7	8	9	10	11	12	13	14	15	16
        // 0	0	0	0	PAN	PAN	PAN	PAN	PAN	PAN	PAN	PAN	PAN	PAN	PAN	PAN
        final String accountNumberBlock = getAccountNumberBlock(pan);

        // 3 - XOR both values
        final CustomBitSet customBitSet = new CustomBitSet(iso0FormatPinBlock);
        customBitSet.xor(new CustomBitSet(accountNumberBlock));

        return customBitSet.toString();
    }

    public String fromIso0Pin(final String iso0Pin, String pan) {
        final CustomBitSet iso0FormatPin = new CustomBitSet(iso0Pin);
        final CustomBitSet accountNumber = new CustomBitSet(getAccountNumberBlock(pan));

        iso0FormatPin.xor(accountNumber);

        final String pinData = iso0FormatPin.toString();

        final int pinLength = Integer.parseInt(pinData.substring(0, 2));
        return pinData.substring(2, 2 + pinLength);
    }

    String getAccountNumberBlock(String pan) {
        final String accountNumberBlock = pan.substring(Math.max(0, pan.length() - 13), pan.length() - 1);
        return StringUtils.leftPad(accountNumberBlock, 16, '0');
    }

}
