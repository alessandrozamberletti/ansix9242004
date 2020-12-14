package ansi.x9_24_2004;

import ansi.x9_24_2004.dukpt.DukptFactory;
import ansi.x9_24_2004.dukpt.IfsfKeyMask;
import ansi.x9_24_2004.encryption.Des;
import ansi.x9_24_2004.encryption.TripleDes;
import ansi.x9_24_2004.mac.RetailMacFactory;
import ansi.x9_24_2004.utils.CustomBitSet;

import javax.xml.bind.DatatypeConverter;

public class IfsfSecurityFieldFactory {

    private final CustomBitSet bdk;
    private final TripleDes tripleDes;
    private final DukptFactory dukptFactory;
    private final RetailMacFactory retailMacFactory;

    public IfsfSecurityFieldFactory(final String bdk) {
        this.bdk = new CustomBitSet(bdk);

        this.tripleDes = new TripleDes();
        this.retailMacFactory = new RetailMacFactory();
        this.dukptFactory = new DukptFactory(new Des(), tripleDes);
    }

    // Sensitive data encryption using ANSI X9.24 2004 data key
    public String encryptRequestData2004(final String ksn, final String data) {
        final CustomBitSet requestDataKey = dukptFactory.computeKey(bdk, new CustomBitSet(ksn), IfsfKeyMask.REQUEST_DATA_MASK);
        final byte[] encryptedRequestData = tripleDes.encrypt(requestDataKey, DatatypeConverter.parseHexBinary(data));

        return DatatypeConverter.printHexBinary(encryptedRequestData);
    }

    // Sensitive data encryption using ANSI X9.24 2009 data key
    public String encryptRequestData2009(final String ksn, final String data) {
        final CustomBitSet x924version2009DataKey = dukptFactory.computeAnsiX924version2009DataKey(bdk, new CustomBitSet(ksn));
        final byte[] encryptedRequestData = tripleDes.encrypt(x924version2009DataKey, DatatypeConverter.parseHexBinary(data));

        return DatatypeConverter.printHexBinary(encryptedRequestData);
    }

    // Encrypt using fixed key
    public String encryptFixed(final String key, final String data) {
        final byte[] requestData = tripleDes.encrypt(new CustomBitSet(key), DatatypeConverter.parseHexBinary(data));

        return DatatypeConverter.printHexBinary(requestData);
    }

    // Sensitive data decryption using ANSI
    public String decryptRequestData2004(final String ksn, final String encryptedData) {
        final CustomBitSet requestDataKey = dukptFactory.computeKey(bdk, new CustomBitSet(ksn), IfsfKeyMask.REQUEST_DATA_MASK);
        final byte[] requestData = tripleDes.decrypt(requestDataKey, DatatypeConverter.parseHexBinary(encryptedData));

        return DatatypeConverter.printHexBinary(requestData);
    }

    // Decrypt using fixed key
    public String decryptFixed(final String key, final String encryptedData) {
        final byte[] requestData = tripleDes.decrypt(new CustomBitSet(key), DatatypeConverter.parseHexBinary(encryptedData));

        return DatatypeConverter.printHexBinary(requestData);
    }

    // Compute retail MAC
    public String calculateRequestMac(final String ksn, final String messageHash) {
        final CustomBitSet requestMacKey = dukptFactory.computeKey(bdk, new CustomBitSet(ksn), IfsfKeyMask.REQUEST_MAC_MASK);
        final byte[] requestMac = retailMacFactory.create(requestMacKey, DatatypeConverter.parseHexBinary(messageHash));

        return DatatypeConverter.printHexBinary(requestMac);
    }

    // Encrypt plain ISO-0 PIN block
    public String encryptIso0PinBlock(final String ksn, final String iso0PinBlock) {
        final CustomBitSet pinKey = dukptFactory.computeKey(bdk, new CustomBitSet(ksn), IfsfKeyMask.REQUEST_PIN_MASK);
        final byte[] encryptedIso0Block =  tripleDes.encrypt(pinKey, DatatypeConverter.parseHexBinary(iso0PinBlock));

        return DatatypeConverter.printHexBinary(encryptedIso0Block);
    }

    // Decrypt encrypted ISO-0 PIN block
    public String decryptIso0PinBlock(final String ksn, final String encryptedIso0PinBlock) {
        final CustomBitSet pinKey = dukptFactory.computeKey(bdk, new CustomBitSet(ksn), IfsfKeyMask.REQUEST_PIN_MASK);
        final byte[] clearIso0Block =  tripleDes.decrypt(pinKey, DatatypeConverter.parseHexBinary(encryptedIso0PinBlock));

        return DatatypeConverter.printHexBinary(clearIso0Block);
    }

}
