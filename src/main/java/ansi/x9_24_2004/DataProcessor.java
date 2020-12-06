package ansi.x9_24_2004;

import ansi.x9_24_2004.dukpt.DukptFactory;
import ansi.x9_24_2004.dukpt.Mask;
import ansi.x9_24_2004.encryption.Des;
import ansi.x9_24_2004.encryption.TripleDes;
import ansi.x9_24_2004.mac.RetailMacFactory;
import ansi.x9_24_2004.utils.CustomBitSet;

import javax.xml.bind.DatatypeConverter;

public class DataProcessor {

    private final CustomBitSet bdk;
    private final TripleDes tripleDes;
    private final DukptFactory dukptFactory;
    private final RetailMacFactory retailMacFactory;

    DataProcessor(final String bdk) {
        this.bdk = new CustomBitSet(bdk);

        this.tripleDes = new TripleDes();
        this.retailMacFactory = new RetailMacFactory();
        this.dukptFactory = new DukptFactory(new Des(), tripleDes);
    }

    String encryptRequestData(final String ksn, final String data) {
        final CustomBitSet requestDataKey = dukptFactory.computeKey(bdk, new CustomBitSet(ksn), Mask.REQUEST_DATA_MASK);
        final byte[] encryptedRequestData = tripleDes.encrypt(requestDataKey, DatatypeConverter.parseHexBinary(data), false);

        return DatatypeConverter.printHexBinary(encryptedRequestData);
    }

    String calculateRequestMac(final String ksn, final String messageHash) {
        final CustomBitSet requestMacKey = dukptFactory.computeKey(bdk, new CustomBitSet(ksn), Mask.REQUEST_MAC_MASK);
        final byte[] requestMac = retailMacFactory.create(requestMacKey, DatatypeConverter.parseHexBinary(messageHash));

        return DatatypeConverter.printHexBinary(requestMac);
    }

}
