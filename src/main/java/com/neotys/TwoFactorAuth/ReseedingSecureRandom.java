package com.neotys.TwoFactorAuth;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicInteger;

class ReseedingSecureRandom {
    private static final int MAX_OPERATIONS = 1000000;
    private final String algorithm;
    private final AtomicInteger count;
    private final String provider;
    private volatile SecureRandom secureRandom;

    ReseedingSecureRandom() {
        this.count = new AtomicInteger(0);
        this.algorithm = null;
        this.provider = null;
        buildSecureRandom();
    }

    ReseedingSecureRandom(String algorithm2) {
        this.count = new AtomicInteger(0);
        if (algorithm2 == null) {
            throw new IllegalArgumentException("Algorithm cannot be null.");
        }
        this.algorithm = algorithm2;
        this.provider = null;
        buildSecureRandom();
    }

    ReseedingSecureRandom(String algorithm2, String provider2) {
        this.count = new AtomicInteger(0);
        if (algorithm2 == null) {
            throw new IllegalArgumentException("Algorithm cannot be null.");
        } else if (provider2 == null) {
            throw new IllegalArgumentException("Provider cannot be null.");
        } else {
            this.algorithm = algorithm2;
            this.provider = provider2;
            buildSecureRandom();
        }
    }

    private void buildSecureRandom() {
        try {
            if (this.algorithm == null && this.provider == null) {
                this.secureRandom = new SecureRandom();
            } else if (this.provider == null) {
                this.secureRandom = SecureRandom.getInstance(this.algorithm);
            } else {
                this.secureRandom = SecureRandom.getInstance(this.algorithm, this.provider);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new GoogleAuthenticatorException(String.format("Could not initialise SecureRandom with the specified algorithm: %s. Another provider can be chosen setting the %s system property.", this.algorithm, GoogleAuthenticator.RNG_ALGORITHM), e);
        } catch (NoSuchProviderException e2) {
            throw new GoogleAuthenticatorException(String.format("Could not initialise SecureRandom with the specified provider: %s. Another provider can be chosen setting the %s system property.", this.provider, GoogleAuthenticator.RNG_ALGORITHM_PROVIDER), e2);
        }
    }

    /* access modifiers changed from: package-private */
    public void nextBytes(byte[] bytes) {
        if (this.count.incrementAndGet() > MAX_OPERATIONS) {
            synchronized (this) {
                if (this.count.get() > MAX_OPERATIONS) {
                    buildSecureRandom();
                    this.count.set(0);
                }
            }
        }
        this.secureRandom.nextBytes(bytes);
    }
}
