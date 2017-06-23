package ru.annin.cryptowallet;

import android.support.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import ru.annin.cryptowallet.data.crypto.CryptoManager;

import static org.junit.Assert.assertArrayEquals;

/**
 * Тесты криптографического алгоритма AES 256.
 *
 * @author Pavel Annin.
 */
@RunWith(AndroidJUnit4.class)
public class AES256InstrumentedTest {

    private final static byte[] KEY = CryptoManager.AES256.generateKey();

    private final static byte[] EXTRA = {
            (byte) 0x0c, (byte) 0x8e, (byte) 0xa2, (byte) 0xb7, (byte) 0xca, (byte) 0x51,
            (byte) 0x67, (byte) 0x45, (byte) 0xbf, (byte) 0xea, (byte) 0xfc, (byte) 0x49,
            (byte) 0x90, (byte) 0x4b, (byte) 0x49, (byte) 0x60
    };

    private final static byte[] ENCODE = {
            (byte) 0x1c, (byte) 0x18, (byte) 0xa2, (byte) 0x5e, (byte) 0x2a, (byte) 0x60,
            (byte) 0x8f, (byte) 0x03, (byte) 0x8c, (byte) 0xae, (byte) 0xbc, (byte) 0x3c,
            (byte) 0x97, (byte) 0x3a, (byte) 0x10, (byte) 0x29, (byte) 0xdd, (byte) 0x57,
            (byte) 0x56, (byte) 0xea, (byte) 0xb8, (byte) 0x0d, (byte) 0x32, (byte) 0x65,
            (byte) 0x6a, (byte) 0xe7, (byte) 0x98, (byte) 0x1c, (byte) 0x24, (byte) 0xa0,
            (byte) 0xf1, (byte) 0xa6, (byte) 0xf0, (byte) 0x5f, (byte) 0xcc, (byte) 0xb5,
            (byte) 0x63, (byte) 0x1e, (byte) 0xc8, (byte) 0x00, (byte) 0x26, (byte) 0x14,
            (byte) 0x60, (byte) 0x06, (byte) 0x9e, (byte) 0x75, (byte) 0x63, (byte) 0xa7,
            (byte) 0xa9, (byte) 0x0a, (byte) 0x56, (byte) 0xcc, (byte) 0x2c, (byte) 0x0b,
            (byte) 0x80, (byte) 0x7f, (byte) 0xee, (byte) 0xff, (byte) 0x60, (byte) 0x3c,
            (byte) 0x63, (byte) 0xa1, (byte) 0xe6, (byte) 0xf4, (byte) 0xf1, (byte) 0x3f,
            (byte) 0x75, (byte) 0xb3, (byte) 0xb7, (byte) 0x04, (byte) 0xae, (byte) 0xf2,
            (byte) 0xef, (byte) 0x7c, (byte) 0xe2, (byte) 0xdb, (byte) 0x37, (byte) 0x16,
            (byte) 0x5e, (byte) 0x83, (byte) 0xd6, (byte) 0x13, (byte) 0x81, (byte) 0x3b,
            (byte) 0xae, (byte) 0x79, (byte) 0xc6, (byte) 0x8e, (byte) 0x16, (byte) 0x20,
            (byte) 0x25, (byte) 0x4d, (byte) 0x86, (byte) 0x99, (byte) 0x50, (byte) 0xff,
            (byte) 0x5e, (byte) 0x9b, (byte) 0x3b, (byte) 0x1c, (byte) 0xa7, (byte) 0x0d,
            (byte) 0xd3, (byte) 0x3d, (byte) 0x2a, (byte) 0xc9, (byte) 0xfa, (byte) 0x30,
            (byte) 0x93, (byte) 0x50, (byte) 0xe7, (byte) 0x56
    };

    private final static byte[] DECODE = {
            (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55,
            (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb,
            (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff, (byte) 0x10, (byte) 0x21,
            (byte) 0x32, (byte) 0x43, (byte) 0x54, (byte) 0x65, (byte) 0x76, (byte) 0x87,
            (byte) 0x98, (byte) 0xa9, (byte) 0xba, (byte) 0xcb, (byte) 0xdc, (byte) 0xed,
            (byte) 0xfe, (byte) 0x0f, (byte) 0x20, (byte) 0x31, (byte) 0x42, (byte) 0x53,
            (byte) 0x64, (byte) 0x75, (byte) 0x86, (byte) 0x97, (byte) 0xa8, (byte) 0xb9,
            (byte) 0xca, (byte) 0xdb, (byte) 0xec, (byte) 0xfd, (byte) 0x0e, (byte) 0x1f,
            (byte) 0x30, (byte) 0x41, (byte) 0x52, (byte) 0x63, (byte) 0x74, (byte) 0x85,
            (byte) 0x96, (byte) 0xa7, (byte) 0xb8, (byte) 0xc9, (byte) 0xda, (byte) 0xeb,
            (byte) 0xfc, (byte) 0x0d, (byte) 0x1e, (byte) 0x2f, (byte) 0x40, (byte) 0x51,
            (byte) 0x62, (byte) 0x73, (byte) 0x84, (byte) 0x95, (byte) 0xa6, (byte) 0xb7,
            (byte) 0xc8, (byte) 0xd9, (byte) 0xea, (byte) 0xfb, (byte) 0x0c, (byte) 0x1d,
            (byte) 0x2e, (byte) 0x3f, (byte) 0x50, (byte) 0x61, (byte) 0x72, (byte) 0x83,
            (byte) 0x94, (byte) 0xa5, (byte) 0xb6, (byte) 0xc7, (byte) 0xd8, (byte) 0xe9,
            (byte) 0xfa, (byte) 0x0b, (byte) 0x1c, (byte) 0x2d, (byte) 0x3e, (byte) 0x4f,
            (byte) 0x60, (byte) 0x71, (byte) 0x82, (byte) 0x93
    };

    @Test
    public void testEncode() throws Exception {
        byte[] result = CryptoManager.AES256.encrypt(KEY, EXTRA, DECODE);
        assertArrayEquals(ENCODE, result);
    }

    @Test
    public void testDecode() throws Exception {
        byte[] result = CryptoManager.AES256.decrypt(KEY, EXTRA, ENCODE);
        assertArrayEquals(DECODE, result);
    }

    @Test
    public void testEncodeDecode() throws Exception {
        byte[] encodeResult = CryptoManager.AES256.encrypt(KEY, EXTRA, DECODE);
        byte[] result = CryptoManager.AES256.decrypt(KEY, EXTRA, encodeResult);
        assertArrayEquals(DECODE, result);
    }
}