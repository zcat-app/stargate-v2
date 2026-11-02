// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Adapted from v1 HmacVerifierMinter; no token-loader or recovery dependency. */
final class HmacPartition {
    private final SecretKeySpec key;

    HmacPartition(byte[] key) {
        if (key.length != 32) throw new IllegalArgumentException("isolation.key must contain 32 bytes");
        this.key = new SecretKeySpec(Arrays.copyOf(key, key.length), "HmacSHA256");
    }

    String forProfile(String id) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            byte[] input = ("stargate-profile-v2\0" + id).getBytes(StandardCharsets.UTF_8);
            return "sg2:" + HexFormat.of().formatHex(mac.doFinal(input));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC_UNAVAILABLE", e);
        }
    }
}
