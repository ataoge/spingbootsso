package com.chinadci.rdc.ssoserver.utils;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import static org.springframework.security.crypto.util.EncodingUtils.concatenate;
import static org.springframework.security.crypto.util.EncodingUtils.subArray;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import com.chinadci.rdc.ssocommons.utils.CommonHelper;

public class NetcorePbkdf2PasswordEncoder  implements PasswordEncoder {
    private static final int DEFAULT_HASH_WIDTH = 256;
    private static final int DEFAULT_ITERATIONS = 10000;
    private static final int DEFAULT_SALTSIZE = 16;

    private final BytesKeyGenerator saltGenerator = KeyGenerators.secureRandom(DEFAULT_SALTSIZE);

    private final byte[] secret;
    private final int hashWidth;
    private final int iterations;
    private String algorithm = Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256.name();
    private boolean encodeHashAsBase64 = true;

    public NetcorePbkdf2PasswordEncoder() {
        this("");
    }

    public NetcorePbkdf2PasswordEncoder(CharSequence secret) {
        this(secret, DEFAULT_ITERATIONS, DEFAULT_HASH_WIDTH);
    }

    public NetcorePbkdf2PasswordEncoder(CharSequence secret, int iterations, int hashWidth) {

        this.secret = Utf8.encode(secret);
        this.iterations = iterations;
        this.hashWidth = hashWidth;
    }

    public void setAlgorithm(Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm secretKeyFactoryAlgorithm) {
        if (secretKeyFactoryAlgorithm == null) {
            throw new IllegalArgumentException("secretKeyFactoryAlgorithm cannot be null");
        }
        String algorithmName = secretKeyFactoryAlgorithm.name();
        try {
            SecretKeyFactory.getInstance(algorithmName);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Invalid algorithm '" + algorithmName + "'.", e);
        }
        this.algorithm = algorithmName;
    }


    public void setEncodeHashAsBase64(boolean encodeHashAsBase64) {
        this.encodeHashAsBase64 = encodeHashAsBase64;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        byte[] salt = this.saltGenerator.generateKey();
        byte[] encoded = encode(rawPassword, salt);
        return encode(encoded);
    }

    private String encode(byte[] bytes) {
        if (this.encodeHashAsBase64) {
            return Base64.getEncoder().encodeToString(bytes);
        }
        return String.valueOf(Hex.encode(bytes));
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        byte[] digested = decode(encodedPassword);
        int alg = CommonHelper.fromByteArray( subArray(digested, 1, 5));
        int iterCount = CommonHelper.fromByteArray(subArray(digested, 5, 9));
        int saltSize = CommonHelper.fromByteArray(subArray(digested, 9, 13));
        byte[] salt = subArray(digested, 13, 13+saltSize);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.values()[alg].name());
            return MessageDigest.isEqual(digested, encode(rawPassword, salt));
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return false;
    }

    private byte[] decode(String encodedBytes) {
        if (this.encodeHashAsBase64) {
            return Base64.getDecoder().decode(encodedBytes);
        }
        return Hex.decode(encodedBytes);
    }

    private byte[] encode(CharSequence rawPassword, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(rawPassword.toString().toCharArray(),
                    concatenate(salt, this.secret), this.iterations, this.hashWidth);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(this.algorithm);
            byte[] hh = new byte[]{ 0x01 };
            byte[] prf = CommonHelper.intToBytes(Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.valueOf(this.algorithm).ordinal());
            byte[] iterCountBytes = CommonHelper.intToBytes(this.iterations);
            byte[] sizeBytes = CommonHelper.intToBytes(salt.length);

            return concatenate(hh, prf, iterCountBytes, sizeBytes, salt, skf.generateSecret(spec).getEncoded());
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not create hash", e);
        }
    }


}
