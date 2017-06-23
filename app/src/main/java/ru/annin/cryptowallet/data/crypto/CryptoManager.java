package ru.annin.cryptowallet.data.crypto;

import android.support.annotation.NonNull;

import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Менеджер криптографических операций.
 *
 * @author Pavel Annin.
 */
public final class CryptoManager {

    public static final class AES256 {

        @NonNull
        public static byte[] generateKey() {
            try {
                final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                keyGenerator.init(256);
                final SecretKey key = keyGenerator.generateKey();
                return key.getEncoded();
            } catch (Throwable t) {
                throw new CryptoException("[AES256] Error generate key.", t);
            }
        }

        @NonNull
        public static byte[] generateIV() {
            final SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            return salt;
        }

        @NonNull
        public static byte[] encrypt(@NonNull byte[] key, @NonNull byte[] iv, @NonNull String plainText) {
            return encrypt(key, iv, plainText.getBytes(Charset.forName("UTF-8")));
        }

        @NonNull
        public static byte[] encrypt(@NonNull byte[] key, @NonNull byte[] iv, @NonNull byte[] plainText) {
            try {
                final SecretKey secret = new SecretKeySpec(key, "AES");
                final AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv);

                final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secret, ivSpec);
                return cipher.doFinal(plainText);
            } catch (Throwable t) {
                throw new CryptoException("[AES256] Error encrypt.", t);
            }
        }

        @NonNull
        public static String decryptToString(@NonNull byte[] key, @NonNull byte[] iv, @NonNull byte[] cipherText) {
            return String(decrypt(key, iv, cipherText), Charset.forName("UTF-8");
        }

        @NonNull
        public static byte[] decrypt(@NonNull byte[] key, @NonNull byte[] iv, @NonNull byte[] cipherText) {
            try {
                final SecretKey secret = new SecretKeySpec(key, "AES");
                final AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv);

                final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);
                return cipher.doFinal(cipherText);
            } catch (Throwable t) {
                throw new CryptoException("[AES256] Error decrypt.", t);
            }
        }
    }
}