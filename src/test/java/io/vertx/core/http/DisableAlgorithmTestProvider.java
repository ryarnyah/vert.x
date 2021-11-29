/*
 * Copyright (c) 2011-2019 Contributors to the Eclipse Foundation
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */

package io.vertx.core.http;

import javax.net.ssl.*;
import java.security.*;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

class DisableAlgorithmTestProvider extends Provider {
  DisableAlgorithmTestProvider() {
    super(DisableAlgorithmTestProvider.class.getName(), 1.0, "Test Provider");

    putService(new Provider.Service(this,
      "SSLContext",
      "TLS",
      DisableAlgorithmTestSSLContextSpiTLS.class.getName(),
      null,
      null)
    );
    putService(new Provider.Service(this,
      "SSLContext",
      "TLSv1.1",
      DisableAlgorithmTestSSLContextSpiTLS1_1.class.getName(),
      null,
      null)
    );
    putService(new Provider.Service(this,
      "SSLContext",
      "TLSv1.2",
      DisableAlgorithmTestSSLContextSpiTLS1_2.class.getName(),
      null,
      null)
    );
    putService(new Provider.Service(this,
      "SSLContext",
      "TLSv1.3",
      DisableAlgorithmTestSSLContextSpiTLS1_3.class.getName(),
      null,
      null)
    );
  }

  public static final class DisableAlgorithmTestSSLContextSpiTLS extends DisableAlgorithmTestSSLContextSpi {
    public DisableAlgorithmTestSSLContextSpiTLS() throws NoSuchAlgorithmException {
      super("TLS");
    }
  }

  public static final class DisableAlgorithmTestSSLContextSpiTLS1_1 extends DisableAlgorithmTestSSLContextSpi {
    public DisableAlgorithmTestSSLContextSpiTLS1_1() throws NoSuchAlgorithmException {
      super("TLSv1.1");
    }
  }

  public static final class DisableAlgorithmTestSSLContextSpiTLS1_2 extends DisableAlgorithmTestSSLContextSpi {
    public DisableAlgorithmTestSSLContextSpiTLS1_2() throws NoSuchAlgorithmException {
      super("TLSv1.2");
    }
  }

  public static final class DisableAlgorithmTestSSLContextSpiTLS1_3 extends DisableAlgorithmTestSSLContextSpi {
    public DisableAlgorithmTestSSLContextSpiTLS1_3() throws NoSuchAlgorithmException {
      super("TLSv1.3");
    }
  }

  private static class DisableAlgorithmTestSSLContextSpi extends SSLContextSpi {

    private final SSLContext defaultSSLContext;

    public DisableAlgorithmTestSSLContextSpi(String tlsVersion) throws NoSuchAlgorithmException {
      this.defaultSSLContext = SSLContext.getInstance(tlsVersion);
    }

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
      defaultSSLContext.init(km, tm, sr);
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
      return defaultSSLContext.getSocketFactory();
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
      return defaultSSLContext.getServerSocketFactory();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
      return decorateTLSParameters(defaultSSLContext.createSSLEngine());
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
      return decorateTLSParameters(defaultSSLContext.createSSLEngine(host, port));
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
      return defaultSSLContext.getServerSessionContext();
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
      return defaultSSLContext.getClientSessionContext();
    }

    @Override
    protected SSLParameters engineGetDefaultSSLParameters() {
      SSLParameters sslParameters = defaultSSLContext.getDefaultSSLParameters();
      sslParameters.setAlgorithmConstraints(new DisableAlgorithmTestAlgorithmConstraints());
      return sslParameters;
    }

    @Override
    protected SSLParameters engineGetSupportedSSLParameters() {
      SSLParameters sslParameters = defaultSSLContext.getSupportedSSLParameters();
      sslParameters.setAlgorithmConstraints(new DisableAlgorithmTestAlgorithmConstraints());
      return sslParameters;
    }

    private SSLEngine decorateTLSParameters(final SSLEngine engine) {
      if (engine != null) {
        SSLParameters sslParameters = engine.getSSLParameters();
        sslParameters.setAlgorithmConstraints(new DisableAlgorithmTestAlgorithmConstraints());
        engine.setSSLParameters(sslParameters);
      }
      return engine;
    }
  }

  private static final class DisableAlgorithmTestAlgorithmConstraints implements AlgorithmConstraints {

    /* must match name/algorithm/keyAlgorithm see sun.security.ssl.SignatureScheme.getSupportedAlgorithms */
    private static final List<String> ALLOWED_SIGNATURE_ALGORITHMS = Arrays.asList(
      // SIGNATURE_ALGORITHMS
      "SHA256withRSA",
      "SHA384withRSA",
      "SHA512withRSA",
      // KEY_SIGNATURE_ALGORITHMS
      "RSA",
      // SIGNATURE_NAMES
      "rsa_pkcs1_sha256",
      "rsa_pkcs1_sha384",
      "rsa_pkcs1_sha512"
    );

    @Override
    public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters) {
      for (CryptoPrimitive primitive : primitives) {
        if (CryptoPrimitive.SIGNATURE.equals(primitive) &&
          !ALLOWED_SIGNATURE_ALGORITHMS.contains(algorithm)) {
          return false;
        }
      }
      return true;
    }

    @Override
    public boolean permits(Set<CryptoPrimitive> primitives, Key key) {
      return true;
    }

    @Override
    public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters) {
      return true;
    }
  }
}
