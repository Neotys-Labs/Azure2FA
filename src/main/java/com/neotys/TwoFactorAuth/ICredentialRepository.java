package com.neotys.TwoFactorAuth;

import java.util.List;

public interface ICredentialRepository {
    String getSecretKey(String str);

    void saveUserCredentials(String str, String str2, int i, List<Integer> list);
}
