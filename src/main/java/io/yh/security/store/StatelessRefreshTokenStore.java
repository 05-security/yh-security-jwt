package io.yh.security.store;

/**
 * Default no-op refresh token store (stateless JWT only).
 */
public class StatelessRefreshTokenStore implements RefreshTokenStore {

    @Override
    public void save(String username, String refreshToken, int ttlMillis) {
        // no-op
    }

    @Override
    public boolean validate(String username, String refreshToken) {
        return true;
    }
}
