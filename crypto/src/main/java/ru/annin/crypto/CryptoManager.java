package ru.annin.crypto;

import android.support.annotation.NonNull;

/**
 * <p>Менеджер криптографических алгоритмов.</p>
 *
 * @author Pavel Annin.
 */
public class CryptoManager {

    static {
        try {
            System.loadLibrary("native-crypto");
        } catch (Exception e) {
            throw new CryptoException("Not fount library native-crypto", e);
        }
    }

    @NonNull
    public static native byte[] aes256Encode(@NonNull byte[] key, @NonNull byte[] data);

    @NonNull
    public static native byte[] aes256Decode(@NonNull byte[] key, @NonNull byte[] data);
}