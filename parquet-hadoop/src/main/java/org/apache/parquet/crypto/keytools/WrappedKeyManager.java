/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */


package org.apache.parquet.crypto.keytools;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import org.apache.parquet.crypto.DecryptionKeyRetriever;


public class WrappedKeyManager {

  private final KmsClient kmsClient;
  private final boolean wrapLocally;
  private final WrappedKeyStore wrappedKeyStore;
  private final String fileID;

  private final SecureRandom random;
  private short keyCounter;

  public static class WrappedKeyRetriever implements DecryptionKeyRetriever {
    private final KmsClient kmsClient;
    private final boolean unwrapLocally;
    private final WrappedKeyStore keyStore;
    private final String fileID;

    private WrappedKeyRetriever(KmsClient kmsClient, boolean unwrapLocally, WrappedKeyStore keyStore, String fileID) {
      this.kmsClient = kmsClient;
      this.keyStore = keyStore;
      this.fileID = fileID;
      this.unwrapLocally = unwrapLocally;
    }

    @Override
    public byte[] getKey(byte[] keyMetaData) throws IOException {
      String keyMaterial;
      if (null != keyStore) {
        String keyIDinFile = new String(keyMetaData, StandardCharsets.UTF_8);
        keyMaterial = keyStore.getWrappedKey(fileID, keyIDinFile);
      }
      else {
        keyMaterial = new String(keyMetaData, StandardCharsets.UTF_8);
      }
      String[] parts = keyMaterial.split(":");
      // TODO check parts
      String encodedWrappedDatakey = parts[0];
      String masterKeyID = parts[1];
      String encodedDataKey = null;
      if (unwrapLocally) {
        //TODO xxx and Cache?!
      }
      else {
        encodedDataKey = kmsClient.unwrapKey(encodedWrappedDatakey, masterKeyID);
      }
      byte[] dataKey = Base64.getDecoder().decode(encodedDataKey);
      return dataKey;
    }
  }
  
  public WrappedKeyManager(KmsClient kmsClient) {
    this(kmsClient, false, null, null);
  }

  public WrappedKeyManager(KmsClient kmsClient, boolean wrapLocally, WrappedKeyStore wrappedKeyStore, String fileID) {
    if (!wrapLocally && !kmsClient.supportsServerSideWrapping()) {
      throw new UnsupportedOperationException("KMS client doesn't support server-side wrapping");
    }
    if (null != wrappedKeyStore && null == fileID) {
      throw new IllegalArgumentException("File ID must be supplied to wrapped key store");
    }
    this.kmsClient = kmsClient;
    this.wrapLocally = wrapLocally;
    this.wrappedKeyStore = wrappedKeyStore;
    this.fileID = fileID;
    random = new SecureRandom();
    keyCounter = 0;
  }

  public EncryptionKey generateKey(String masterKeyID) throws IOException {
    byte[] dataKey = new byte[16]; //TODO
    random.nextBytes(dataKey);
    String encodedDataKey = Base64.getEncoder().encodeToString(dataKey);
    String encodedWrappedDataKey = null;
    if (wrapLocally) {
      //TODO xxx and Cache?!
    }
    else {
      encodedWrappedDataKey = kmsClient.wrapKey(encodedDataKey, masterKeyID);
    }
    String wrappedKeyMaterial = encodedWrappedDataKey + ":" + masterKeyID;
    byte[] keyMetadata = null;
    if (null != wrappedKeyStore) {
      String keyName = "k" + keyCounter;
      wrappedKeyStore.storeWrappedKey(wrappedKeyMaterial, fileID, keyName);
      keyMetadata = keyName.getBytes(StandardCharsets.UTF_8);
      keyCounter++;
    }
    else {
      keyMetadata  = wrappedKeyMaterial.getBytes(StandardCharsets.UTF_8);
    }
    EncryptionKey key = new EncryptionKey(dataKey, keyMetadata);
    return key;
  }

  public DecryptionKeyRetriever getKeyRetriever() {
    return new WrappedKeyRetriever(kmsClient, wrapLocally, wrappedKeyStore, fileID);
  }
}
