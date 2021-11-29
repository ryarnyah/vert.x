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

package io.vertx.core.net;

import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;

class SSLHelperTestProvider extends Provider {

  private static final String[] ENABLED_PROTOCOLS = new String[]{
    "TLSv1.3"
  };

  SSLHelperTestProvider() {
    super(SSLHelperTestProvider.class.getName(), 1.0, "Test Provider");

    putService(new Provider.Service(this,
      "SSLContext",
      "TLS",
      SSLHelperTestSSLContextSpi.class.getName(),
      null,
      null)
    );
  }

  public static final class SSLHelperTestSSLContextSpi extends SSLContextSpi {

    private final SSLContext defaultSSLContext;

    public SSLHelperTestSSLContextSpi() throws NoSuchAlgorithmException {
      this.defaultSSLContext = SSLContext.getInstance("TLS");
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
      SSLParameters sslParameters = new SSLParameters();
      sslParameters.setProtocols(ENABLED_PROTOCOLS);
      sslParameters.setNeedClientAuth(true);
      return sslParameters;
    }

    @Override
    protected SSLParameters engineGetSupportedSSLParameters() {
      SSLParameters sslParameters = new SSLParameters();
      sslParameters.setProtocols(ENABLED_PROTOCOLS);
      sslParameters.setNeedClientAuth(true);
      return sslParameters;
    }

    private SSLEngine decorateTLSParameters(final SSLEngine engine) {
      if (engine != null) {
        SSLParameters sslParameters = engine.getSSLParameters();
        sslParameters.setProtocols(ENABLED_PROTOCOLS);
        sslParameters.setNeedClientAuth(true);
        engine.setSSLParameters(sslParameters);
      }
      return engine;
    }
  }
}
