package ru.annin.crypto;

/**
 * Исключение вызванное криптографическим алгоритмом.
 *
 * @author Pavel Annin.
 */
public final class CryptoException extends RuntimeException {

    public CryptoException() {
    }

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoException(Throwable cause) {
        super(cause);
    }
}