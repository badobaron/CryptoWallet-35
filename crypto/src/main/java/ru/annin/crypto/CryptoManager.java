package ru.annin.crypto;

/**
 * @author Pavel Annin.
 */

public class CryptoManager {

    public native String stringFromJNI();

    static {
        System.loadLibrary("native-lib");
    }
}
