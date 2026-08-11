//! Test for secret caching functionality
//!
//! This test verifies that the secret caching mechanism works correctly
//! to ensure idempotency in compliance operations.

use regent_sdk::secrets::{SecretCache, SecretProvider, SecretProvidersPool, SecretReference};

#[tokio::test]
async fn test_secret_cache_basic_operations() {
    let cache = SecretCache::new();

    // Test that cache is initially empty
    assert!(!cache.contains("test_secret").await);
    assert!(cache.get("test_secret").await.is_none());

    // Insert a secret
    cache
        .insert("test_secret".to_string(), "my_secret_value".to_string())
        .await;

    // Verify it's now in the cache
    assert!(cache.contains("test_secret").await);
    assert_eq!(
        cache.get("test_secret").await,
        Some("my_secret_value".to_string())
    );
}

#[tokio::test]
async fn test_secret_providers_pool_caching() {
    // Create a pool with file provider
    let mut pool = SecretProvidersPool::from("files", SecretProvider::files());

    // Initially, caching should be disabled
    assert!(!pool.is_caching_enabled());

    // Enable caching
    pool.enable_caching();
    assert!(pool.is_caching_enabled());

    // Disable caching
    pool.disable_caching();
    assert!(!pool.is_caching_enabled());
}

#[tokio::test]
async fn test_cache_key_generation() {
    let pool = SecretProvidersPool::from("files", SecretProvider::files());

    // Test cache key with default provider
    let secret_ref1 = SecretReference::from("my_secret", None);
    let cache_key1 = pool.create_cache_key(&secret_ref1);
    assert_eq!(cache_key1, "files:my_secret");

    // Test cache key with explicit provider
    let secret_ref2 = SecretReference::from("my_secret", Some("env".to_string()));
    let cache_key2 = pool.create_cache_key(&secret_ref2);
    assert_eq!(cache_key2, "env:my_secret");
}
