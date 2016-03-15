/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.mechanism.publickey;

import java.security.SecureRandom;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.auth.callback.ChannelBindingCallback;
import org.wildfly.security.mechanism.AuthenticationMechanismException;

/**
 * The experimental public key authentication mechanism.
 * <p>
 * This mechanism uses two pairs of messages between the client and server.  The client provides an initial response.
 * The messages are as follows:
 * <ul>
 *     <li>
 *         <em>client-first-message:</em>
 *         <pre>{@code ("n" / "y" / ("p=" cb-name)) "," [ "a=" saslname ] "," "n=" saslname "," "r=" c-nonce "," "k=" c-public-key}</pre>
 *     </li>
 *     <li>
 *         <em>server-first-message:</em>
 *         <pre>{@code "r=" s-nonce "," "k=" s-public-key}</pre>
 *     </li>
 *     <li>
 *         <em>client-final-message:</em>
 *         <pre>{@code "s=" signature(channel-binding-data client-first-message server-first-message)}</pre>
 *     </li>
 *     <li>
 *         <em>server-final-message:</em>
 *         <pre>{@code "s=" signature(channel-binding-data client-first-message server-first-message client-final-message)}</pre>
 *     </li>
 *     <li>
 *         <em>server-error:</em>
 *         <pre>{@code "e=" ("invalid-signature" | "nonce-too-short" | "server-does-support-channel-binding" | "channel-binding-not-supported" | "unknown-user" | "invalid-username-encoding" | "no-resources" | "other-error" )}</pre>
 *     </li>
 * </ul>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PublicKeyMechanism {
    private final String name;
    private final boolean plus;
    private final String signatureAlgorithm;
    private final String keyAlgorithm;

    PublicKeyMechanism(final String name, final boolean plus, final String signatureAlgorithm, final String keyAlgorithm) {
        this.name = name;
        this.plus = plus;
        this.signatureAlgorithm = signatureAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
    }

    public static final PublicKeyMechanism PK_RSA = new PublicKeyMechanism("PK-RSA-SHA256", false, "SHA256withRSA", "RSA");
    public static final PublicKeyMechanism PK_RSA_PLUS = new PublicKeyMechanism("PK-RSA-SHA256-PLUS", true,  "SHA256withRSA", "RSA");

    public static final PublicKeyMechanism PK_DSA = new PublicKeyMechanism("PK-DSA-SHA256", false, "SHA256withDSA", "DSA");
    public static final PublicKeyMechanism PK_DSA_PLUS = new PublicKeyMechanism("PK-DSA-SHA256-PLUS", true,  "SHA256withDSA", "DSA");

    public static final PublicKeyMechanism PK_ECDSA = new PublicKeyMechanism("PK-ECDSA-SHA256", false, "SHA256withECDSA", "EC");
    public static final PublicKeyMechanism PK_ECDSA_PLUS = new PublicKeyMechanism("PK-ECDSA-SHA256-PLUS", true,  "SHA256withECDSA", "EC");

    /**
     * Get the mechanism name.
     *
     * @return the mechanism name
     */
    public String getName() {
        return name;
    }

    public boolean isPlus() {
        return plus;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    /**
     * Create a client for this mechanism.
     *
     * @param authorizationId the authorization ID ({@code null} if none is given)
     * @param callbackHandler the callback handler (may not be {@code null})
     * @param secureRandom an optional secure random implementation to use (may be {@code null})
     * @param bindingCallback the optional channel binding callback result (may be {@code null})
     * @return the client, or {@code null} if the client cannot be created from this mechanism variant
     * @throws AuthenticationMechanismException if the mechanism fails for some reason
     */
    public PublicKeyClient createClient(final String authorizationId, final CallbackHandler callbackHandler, final SecureRandom secureRandom, final ChannelBindingCallback bindingCallback) throws AuthenticationMechanismException {
        final byte[] bindingData;
        final String bindingType;
        if (bindingCallback != null) {
            bindingData = bindingCallback.getBindingData();
            bindingType = bindingCallback.getBindingType();
        } else {
            if (plus) return null;
            bindingData = null;
            bindingType = null;
        }
        return new PublicKeyClient(this, authorizationId, callbackHandler, secureRandom, bindingData, bindingType);
    }

    /**
     * Create a server for this mechanism.
     *
     * @param callbackHandler the callback handler (may not be {@code null})
     * @param secureRandom an optional secure random implementation to use (may be {@code null})
     * @param bindingCallback the optional channel binding callback result (may be {@code null})
     * @return the client, or {@code null} if the client cannot be created from this mechanism variant
     * @throws AuthenticationMechanismException if the mechanism fails for some reason
     */
    public PublicKeyServer createServer(final CallbackHandler callbackHandler, final SecureRandom secureRandom, final ChannelBindingCallback bindingCallback) throws AuthenticationMechanismException {
        final byte[] bindingData;
        final String bindingType;
        if (bindingCallback != null) {
            bindingData = bindingCallback.getBindingData();
            bindingType = bindingCallback.getBindingType();
        } else {
            if (plus) return null;
            bindingData = null;
            bindingType = null;
        }
        return new PublicKeyServer(this, callbackHandler, secureRandom, bindingData, bindingType);

    }

}
