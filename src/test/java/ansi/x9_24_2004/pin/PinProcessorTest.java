package ansi.x9_24_2004.pin;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;

public class PinProcessorTest {

    private PinProcessor pinProcessor;

    @BeforeEach
    void init() {
        this.pinProcessor = new PinProcessor();
    }

    @Nested
    class WhenDecodeIso0PinBlockMethodIsCalled {

        @Test
        void shouldReturnPin() {
            // Given
            final String iso0Pin = "0612076FFFFFFEAE";
            final String pan = "5413339000001513";

            // When
            final String pin = pinProcessor.decodeIso0PinBlock(DatatypeConverter.parseHexBinary(iso0Pin), pan);

            // Then
            Assertions.assertEquals("123456", pin);

        }

    }

}
