package com.neotys.TwoFactorAuth;

import java.util.ArrayList;
import java.util.List;

public final class GoogleAuthenticatorKey {
    private final GoogleAuthenticatorConfig config;
    private final String key;
    private final List<Integer> scratchCodes;
    private final int verificationCode;

    private GoogleAuthenticatorKey(GoogleAuthenticatorConfig config2, String key2, int verificationCode2, List<Integer> scratchCodes2) {
        if (key2 == null) {
            throw new IllegalArgumentException("Key cannot be null");
        } else if (config2 == null) {
            throw new IllegalArgumentException("Configuration cannot be null");
        } else if (scratchCodes2 == null) {
            throw new IllegalArgumentException("Scratch codes cannot be null");
        } else {
            this.config = config2;
            this.key = key2;
            this.verificationCode = verificationCode2;
            this.scratchCodes = new ArrayList(scratchCodes2);
        }
    }

    public List<Integer> getScratchCodes() {
        return this.scratchCodes;
    }

    public GoogleAuthenticatorConfig getConfig() {
        return this.config;
    }

    public String getKey() {
        return this.key;
    }

    public int getVerificationCode() {
        return this.verificationCode;
    }

    public static class Builder {
        private GoogleAuthenticatorConfig config = new GoogleAuthenticatorConfig();
        private String key;
        private List<Integer> scratchCodes = new ArrayList();
        private int verificationCode;

        public Builder(String key2) {
            this.key = key2;
        }

        public GoogleAuthenticatorKey build() {
            return new GoogleAuthenticatorKey(this.config, this.key, this.verificationCode, this.scratchCodes);
        }

        public Builder setConfig(GoogleAuthenticatorConfig config2) {
            this.config = config2;
            return this;
        }

        public Builder setKey(String key2) {
            this.key = key2;
            return this;
        }

        public Builder setVerificationCode(int verificationCode2) {
            this.verificationCode = verificationCode2;
            return this;
        }

        public Builder setScratchCodes(List<Integer> scratchCodes2) {
            this.scratchCodes = scratchCodes2;
            return this;
        }
    }
}
