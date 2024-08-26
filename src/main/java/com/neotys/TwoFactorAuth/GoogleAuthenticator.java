package com.neotys.TwoFactorAuth;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;

public final class GoogleAuthenticator implements IGoogleAuthenticator {
    private static final int BYTES_PER_SCRATCH_CODE = 4;
    private static final String DEFAULT_RANDOM_NUMBER_ALGORITHM = "SHA1PRNG";
    private static final String DEFAULT_RANDOM_NUMBER_ALGORITHM_PROVIDER = "SUN";
    private static final Logger LOGGER = Logger.getLogger(GoogleAuthenticator.class.getName());
   public static final String RNG_ALGORITHM = "com.neotys.googleauth.rng.algorithm";
    public static final String RNG_ALGORITHM_PROVIDER = "com.neotys.googleauth.rng.algorithmProvider";
    private static final int SCRATCH_CODE_INVALID = -1;
    private static final int SCRATCH_CODE_LENGTH = 8;
    public static final int SCRATCH_CODE_MODULUS = ((int) Math.pow(10.0d, 8.0d));
    private final GoogleAuthenticatorConfig config;
    private ICredentialRepository credentialRepository;
    private boolean credentialRepositorySearched;
    private ReseedingSecureRandom secureRandom;

    public GoogleAuthenticator() {
        this.secureRandom = new ReseedingSecureRandom(getRandomNumberAlgorithm(), getRandomNumberAlgorithmProvider());
        this.config = new GoogleAuthenticatorConfig();
    }

    public GoogleAuthenticator(GoogleAuthenticatorConfig config2) {
        this.secureRandom = new ReseedingSecureRandom(getRandomNumberAlgorithm(), getRandomNumberAlgorithmProvider());
        if (config2 == null) {
            throw new IllegalArgumentException("Configuration cannot be null.");
        }
        this.config = config2;
    }

    private String getRandomNumberAlgorithm() {
        return System.getProperty(RNG_ALGORITHM, DEFAULT_RANDOM_NUMBER_ALGORITHM);
    }

    private String getRandomNumberAlgorithmProvider() {
        return System.getProperty(RNG_ALGORITHM_PROVIDER, DEFAULT_RANDOM_NUMBER_ALGORITHM_PROVIDER);
    }

    /* access modifiers changed from: package-private */
    public int calculateCode(byte[] key, long tm) {
        byte[] data = new byte[SCRATCH_CODE_LENGTH];
        long value = tm;
        int i = SCRATCH_CODE_LENGTH;
        while (true) {
            i += SCRATCH_CODE_INVALID;
            if (i <= 0) {
                break;
            }
            data[i] = (byte) ((int) value);
            value >>>= 8;
        }
        SecretKeySpec signKey = new SecretKeySpec(key, this.config.getHmacHashFunction().toString());
        try {
            Mac mac = Mac.getInstance(this.config.getHmacHashFunction().toString());
            mac.init(signKey);
            byte[] hash = mac.doFinal(data);
            int offset = hash[hash.length + SCRATCH_CODE_INVALID] & 15;
            long truncatedHash = 0;
            for (int i2 = 0; i2 < BYTES_PER_SCRATCH_CODE; i2++) {
                truncatedHash = (truncatedHash << 8) | ((long) (hash[offset + i2] & 255));
            }
            return (int) ((truncatedHash & 2147483647L) % ((long) this.config.getKeyModulus()));
        } catch (InvalidKeyException | NoSuchAlgorithmException ex) {
            LOGGER.log(Level.SEVERE, ex.getMessage(), (Throwable) ex);
            throw new GoogleAuthenticatorException("The operation cannot be performed now.");
        }
    }

    private long getTimeWindowFromTime(long time) {
        return time / this.config.getTimeStepSizeInMillis();
    }

    private boolean checkCode(String secret, long code, long timestamp, int window) {
        byte[] decodedKey = decodeSecret(secret);
        long timeWindow = getTimeWindowFromTime(timestamp);
        for (int i = -((window + SCRATCH_CODE_INVALID) / 2); i <= window / 2; i++) {
            if (((long) calculateCode(decodedKey, ((long) i) + timeWindow)) == code) {
                return true;
            }
        }
        return false;
    }

    private byte[] decodeSecret(String secret) {
        switch (this.config.getKeyRepresentation()) {
            case BASE32:
                return new Base32().decode(secret.toUpperCase());
            case BASE64:
                return new Base64().decode(secret);
            default:
                throw new IllegalArgumentException("Unknown key representation type.");
        }
    }

    @Override // com.warrenstrange.googleauth.IGoogleAuthenticator
    public GoogleAuthenticatorKey createCredentials() {
        int bufferSize = this.config.getSecretBits() / SCRATCH_CODE_LENGTH;
        byte[] buffer = new byte[bufferSize];
        this.secureRandom.nextBytes(buffer);
        byte[] secretKey = Arrays.copyOf(buffer, bufferSize);
        String generatedKey = calculateSecretKey(secretKey);
        int validationCode = calculateValidationCode(secretKey);
        return new GoogleAuthenticatorKey.Builder(generatedKey).setConfig(this.config).setVerificationCode(validationCode).setScratchCodes(calculateScratchCodes()).build();
    }

    @Override // com.warrenstrange.googleauth.IGoogleAuthenticator
    public GoogleAuthenticatorKey createCredentials(String userName) {
        if (userName == null) {
            throw new IllegalArgumentException("User name cannot be null.");
        }
        GoogleAuthenticatorKey key = createCredentials();
        getValidCredentialRepository().saveUserCredentials(userName, key.getKey(), key.getVerificationCode(), key.getScratchCodes());
        return key;
    }

    private List<Integer> calculateScratchCodes() {
        List<Integer> scratchCodes = new ArrayList<>();
        for (int i = 0; i < this.config.getNumberOfScratchCodes(); i++) {
            scratchCodes.add(Integer.valueOf(generateScratchCode()));
        }
        return scratchCodes;
    }

    private int calculateScratchCode(byte[] scratchCodeBuffer) {
        if (scratchCodeBuffer.length < BYTES_PER_SCRATCH_CODE) {
            throw new IllegalArgumentException(String.format("The provided random byte buffer is too small: %d.", Integer.valueOf(scratchCodeBuffer.length)));
        }
        int scratchCode = 0;
        for (int i = 0; i < BYTES_PER_SCRATCH_CODE; i++) {
            scratchCode = (scratchCode << SCRATCH_CODE_LENGTH) + (scratchCodeBuffer[i] & 255);
        }
        int scratchCode2 = (Integer.MAX_VALUE & scratchCode) % SCRATCH_CODE_MODULUS;
        return validateScratchCode(scratchCode2) ? scratchCode2 : SCRATCH_CODE_INVALID;
    }

    /* access modifiers changed from: package-private */
    public boolean validateScratchCode(int scratchCode) {
        return scratchCode >= SCRATCH_CODE_MODULUS / 10;
    }

    private int generateScratchCode() {
        int scratchCode;
        do {
            byte[] scratchCodeBuffer = new byte[BYTES_PER_SCRATCH_CODE];
            this.secureRandom.nextBytes(scratchCodeBuffer);
            scratchCode = calculateScratchCode(scratchCodeBuffer);
        } while (scratchCode == SCRATCH_CODE_INVALID);
        return scratchCode;
    }

    private int calculateValidationCode(byte[] secretKey) {
        return calculateCode(secretKey, 0);
    }

    @Override // com.warrenstrange.googleauth.IGoogleAuthenticator
    public int getTotpPassword(String secret) {
        return getTotpPassword(secret, new Date().getTime());
    }

    @Override // com.warrenstrange.googleauth.IGoogleAuthenticator
    public int getTotpPassword(String secret, long time) {
        return calculateCode(decodeSecret(secret), getTimeWindowFromTime(time));
    }

    @Override // com.warrenstrange.googleauth.IGoogleAuthenticator
    public int getTotpPasswordOfUser(String userName) {
        return getTotpPasswordOfUser(userName, new Date().getTime());
    }

    @Override // com.warrenstrange.googleauth.IGoogleAuthenticator
    public int getTotpPasswordOfUser(String userName, long time) {
        return calculateCode(decodeSecret(getValidCredentialRepository().getSecretKey(userName)), getTimeWindowFromTime(time));
    }

    private String calculateSecretKey(byte[] secretKey) {
        switch (this.config.getKeyRepresentation()) {
            case BASE32:
                return new Base32().encodeToString(secretKey);
            case BASE64:
                return new Base64().encodeToString(secretKey);
            default:
                throw new IllegalArgumentException("Unknown key representation type.");
        }
    }

    @Override // com.warrenstrange.googleauth.IGoogleAuthenticator
    public boolean authorize(String secret, int verificationCode) {
        return authorize(secret, verificationCode, new Date().getTime());
    }

    @Override // com.warrenstrange.googleauth.IGoogleAuthenticator
    public boolean authorize(String secret, int verificationCode, long time) {
        if (secret == null) {
            throw new IllegalArgumentException("Secret cannot be null.");
        } else if (verificationCode <= 0 || verificationCode >= this.config.getKeyModulus()) {
            return false;
        } else {
            return checkCode(secret, (long) verificationCode, time, this.config.getWindowSize());
        }
    }

    @Override // com.warrenstrange.googleauth.IGoogleAuthenticator
    public boolean authorizeUser(String userName, int verificationCode) {
        return authorizeUser(userName, verificationCode, new Date().getTime());
    }

    @Override // com.warrenstrange.googleauth.IGoogleAuthenticator
    public boolean authorizeUser(String userName, int verificationCode, long time) {
        return authorize(getValidCredentialRepository().getSecretKey(userName), verificationCode, time);
    }

    private ICredentialRepository getValidCredentialRepository() {
        ICredentialRepository repository = getCredentialRepository();
        if (repository != null) {
            return repository;
        }
        throw new UnsupportedOperationException(String.format("An instance of the %s service must be configured in order to use this feature.", ICredentialRepository.class.getName()));
    }

    @Override // com.warrenstrange.googleauth.IGoogleAuthenticator
    public ICredentialRepository getCredentialRepository() {
        if (this.credentialRepositorySearched) {
            return this.credentialRepository;
        }
        this.credentialRepositorySearched = true;
        Iterator<ICredentialRepository> it = ServiceLoader.load(ICredentialRepository.class).iterator();
        if (it.hasNext()) {
            this.credentialRepository = it.next();
        }
        return this.credentialRepository;
    }

    @Override // com.warrenstrange.googleauth.IGoogleAuthenticator
    public void setCredentialRepository(ICredentialRepository repository) {
        this.credentialRepository = repository;
        this.credentialRepositorySearched = true;
    }
}
