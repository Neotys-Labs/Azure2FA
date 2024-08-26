package com.neotys.TwoFactorAuth;

public interface IGoogleAuthenticator {
    boolean authorize(String str, int i);

    boolean authorize(String str, int i, long j);

    boolean authorizeUser(String str, int i);

    boolean authorizeUser(String str, int i, long j);

    GoogleAuthenticatorKey createCredentials();

    GoogleAuthenticatorKey createCredentials(String str);

    ICredentialRepository getCredentialRepository();

    int getTotpPassword(String str);

    int getTotpPassword(String str, long j);

    int getTotpPasswordOfUser(String str);

    int getTotpPasswordOfUser(String str, long j);

    void setCredentialRepository(ICredentialRepository iCredentialRepository);
}
