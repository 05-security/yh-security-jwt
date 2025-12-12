package io.yh.security.store;

/**
 * Abstraction for refresh token storage/validation (e.g., Redis, DB, in-memory).
 */
public interface RefreshTokenStore {

    /**
     * Persist or index the refresh token for later validation.
     */
    void save(String username, String refreshToken, int ttlMillis);

    /**
     * Validate refresh token for a given user.
     */
    boolean validate(String username, String refreshToken);

    /**
     * Revoke a refresh token (optional).
     */
    default void revoke(String username, String refreshToken) {}
}
