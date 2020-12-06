package ansi.x9_24_2004;

import ansi.x9_24_2004.dukpt.Dukpt;
import ansi.x9_24_2004.dukpt.Mask;
import ansi.x9_24_2004.encryption.Des;
import ansi.x9_24_2004.encryption.TripleDes;
import ansi.x9_24_2004.utils.CustomBitSet;

import javax.xml.bind.DatatypeConverter;

public class DataProcessor {

    private final CustomBitSet bdk;
    private final TripleDes tripleDes;
    private final Dukpt dukpt;

    DataProcessor(final String bdk) {
        this.bdk = new CustomBitSet(bdk);
        this.tripleDes = new TripleDes();
        this.dukpt = new Dukpt(new Des(), tripleDes);
    }

    String encryptRequestData(final String ksn, final String data) {
        final CustomBitSet requestDataKey = dukpt.computeKey(bdk, new CustomBitSet(ksn), Mask.REQUEST_DATA_MASK);
        final byte[] encryptedRequestData = tripleDes.encrypt(requestDataKey, DatatypeConverter.parseHexBinary(data), false);

        return DatatypeConverter.printHexBinary(encryptedRequestData);
    }

    String calculateRequestMac(final String ksn, final String messageHash) {
        final CustomBitSet requestMacKey = dukpt.computeKey(bdk, new CustomBitSet(ksn), Mask.REQUEST_MAC_MASK);
        final byte[] requestMac = tripleDes.encrypt(requestMacKey, DatatypeConverter.parseHexBinary(messageHash), false);

        return DatatypeConverter.printHexBinary(requestMac);
    }

}
