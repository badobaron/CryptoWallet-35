//
// Created by Pavel on 09.06.2017.
//

#include <jni.h>
#include "aes/aes256.cpp"

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_ru_annin_crypto_CryptoManager_aes256Decode(JNIEnv *env, jclass type, jbyteArray key_, jbyteArray data_) {
    if (key_ == NULL || data_ == NULL) {
        return NULL;
    }
    // Key
    jbyte *key = env->GetByteArrayElements(key_, NULL);
    jsize key_length = env->GetArrayLength(key_);

    // Data
    jbyte *data = env->GetByteArrayElements(data_, NULL);
    jsize data_length = env->GetArrayLength(data_);

    ByteArray key_bytes, data_bytes;
    char *key_source = (char *) key;
    for (int i = 0; i < key_length; i++) {
        key_bytes.push_back((const unsigned char &) key_source[i]);
    }
    char *data_source = (char *) data;
    for (int i = 0; i < data_length; i++) {
        data_bytes.push_back((const unsigned char &) data_source[i]);
    }

    // Crypto aes256Decode
    ByteArray decode_bytes;
    ByteArray::size_type decode_length = Aes256::decrypt(key_bytes, data_bytes, decode_bytes);

    // Convert to jByteArray
    jbyteArray encode = env->NewByteArray((jsize) decode_length);
    env->SetByteArrayRegion(encode, 0, (jsize) decode_length, reinterpret_cast<jbyte *>(&decode_bytes[0]));

    //Release
    env->ReleaseByteArrayElements(key_, key, 0);
    env->ReleaseByteArrayElements(data_, data, 0);
    return encode;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_ru_annin_crypto_CryptoManager_aes256Encode(JNIEnv *env, jclass type, jbyteArray key_, jbyteArray data_) {
    if (key_ == NULL || data_ == NULL) {
        return NULL;
    }
    // Key
    jbyte *key = env->GetByteArrayElements(key_, NULL);
    jsize key_length = env->GetArrayLength(key_);

    // Data
    jbyte *data = env->GetByteArrayElements(data_, NULL);
    jsize data_length = env->GetArrayLength(data_);

    ByteArray key_bytes, data_bytes;
    char *key_source = (char *) key;
    for (int i = 0; i < key_length; i++) {
        key_bytes.push_back((const unsigned char &) key_source[i]);
    }
    char *data_source = (char *) data;
    for (int i = 0; i < data_length; i++) {
        data_bytes.push_back((const unsigned char &) data_source[i]);
    }

    // Crypto aes256Encode
    ByteArray encode_bytes;
    ByteArray::size_type encode_length = Aes256::encrypt(key_bytes, data_bytes, encode_bytes);

    // Convert to jByteArray
    jbyteArray encode = env->NewByteArray((jsize) encode_length);
    env->SetByteArrayRegion(encode, 0, (jsize) encode_length, reinterpret_cast<jbyte *>(&encode_bytes[0]));

    //Release
    env->ReleaseByteArrayElements(key_, key, 0);
    env->ReleaseByteArrayElements(data_, data, 0);
    return encode;
}