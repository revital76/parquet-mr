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


package org.apache.parquet.crypto;

import java.util.Map;

import org.apache.parquet.hadoop.metadata.ColumnPath;

public class FileDecryptionProperties {


  private final byte[] footerDecryptionKey;
  private final byte[] footerSigningKey;
  private final DecryptionKeyRetriever keyRetriever;
  private final AADPrefixRetriever aadPrefixRetriever;
  private final byte[] aadPrefixBytes;
  private final Map<ColumnPath, ColumnDecryptionProperties> columnPropertyMap;
  private final boolean checkPlaintextFooterIntegrity;
  
  private FileDecryptionProperties(byte[] footerDecryptionKey, DecryptionKeyRetriever keyRetriever,
      byte[] footerSigningKey, boolean checkPlaintextFooterIntegrity,
      AADPrefixRetriever aadPrefixRetriever, byte[] aadPrefixBytes, 
      Map<ColumnPath, ColumnDecryptionProperties> columnPropertyMap) {
    
    if ((null == footerDecryptionKey) && (null == keyRetriever) && (null == columnPropertyMap)) {
      throw new IllegalArgumentException("No crypto meta data specified");
    }
    if ((null != aadPrefixBytes) && (null != aadPrefixRetriever)) {
      throw new IllegalArgumentException("Can't set both AAD_Prefix and AAD prefix retriever");
    }
    if ((null != footerDecryptionKey) && 
        !(footerDecryptionKey.length == 16 || footerDecryptionKey.length == 24 || footerDecryptionKey.length == 32)) {
      throw new IllegalArgumentException("Wrong footer decryption key length " + footerDecryptionKey.length);
    }
    if ((null != footerSigningKey) && 
        !(footerSigningKey.length == 16 || footerSigningKey.length == 24 || footerSigningKey.length == 32)) {
      throw new IllegalArgumentException("Wrong footer signing key length " + footerSigningKey.length);
    }
    
    this.footerDecryptionKey = footerDecryptionKey;
    this.checkPlaintextFooterIntegrity = checkPlaintextFooterIntegrity;
    this.footerSigningKey = footerSigningKey;
    this.keyRetriever = keyRetriever;
    this.aadPrefixRetriever = aadPrefixRetriever;
    this.aadPrefixBytes = aadPrefixBytes;
    this.columnPropertyMap = columnPropertyMap;
  }

  public static Builder builder() {
    return new Builder();
  }
  
  public static class Builder {
    private byte[] footerDecryptionKey;
    private byte[] footerSigningKey;
    private DecryptionKeyRetriever keyRetriever;
    private AADPrefixRetriever aadPrefixRetriever;
    private byte[] aadPrefixBytes;
    private Map<ColumnPath, ColumnDecryptionProperties> columnPropertyMap;
    private boolean checkPlaintextFooterIntegrity;

    /**
     * Set an explicit footer decryption key. If applied on a file that contains footer 
     * encryption key metadata - 
     * the metadata will be ignored, the footer will be decrypted with this key.
     * If explicit key is not set, decryption key will be fetched from key retriever.
     * @param footerDecryptionKey Key length must be either 16, 24 or 32 bytes. 
     */
    public Builder withFooterDecryptionKey(byte[] footerDecryptionKey) {
      if (null == footerDecryptionKey) {
        return this;
      }
      if (null != this.footerDecryptionKey) {
        throw new IllegalArgumentException("Footer decryption key already set");
      }
      this.footerDecryptionKey = footerDecryptionKey;
      return this;
    }

    /**
     * Set the column encryption properties.
     * @param columnPropertyMap
     * @return
     */
    public Builder withColumnProperties(Map<ColumnPath, ColumnDecryptionProperties> columnPropertyMap) {
      if (null == columnPropertyMap) {
        return this;
      }
      if (null != this.columnPropertyMap) {
        throw new IllegalArgumentException("Column properties already set");
      }
      this.columnPropertyMap = columnPropertyMap;
      return this;
    }
    
    /**
     * Set a key retriever callback. Its also possible to
     * set explicit footer or column keys on this property object. Upon file decryption, 
     * availability of explicit keys is checked before invocation of the retriever callback.
     * If an explicit key is available for a footer or a column, its key metadata will
     * be ignored. 
     * @param keyRetriever
     */
    public Builder withKeyRetriever(DecryptionKeyRetriever keyRetriever) {
      if (null == keyRetriever) {
        return this;
      }
      if (null != this.keyRetriever) {
        throw new IllegalArgumentException("Key retriever already set");
      }
      this.keyRetriever = keyRetriever;
      return this;
    }
    
    /**
     * Specify whether integrity of plaintext footer must be verified.
     * If yes, an exception will be thrown in the following situations:
     * - file footer is not signed (and not encrypted)
     * - footer signing key is not available (not passed, or not found in key retriever)
     * - footer content and signature don't match
     * @param checkFooterIntegrity
     * @return
     */
    public Builder checkPlaintextFooterSignature(boolean checkFooterIntegrity) {
      this.checkPlaintextFooterIntegrity = checkFooterIntegrity;
      return this;
    }
    
    /**
     * Set an explicit key for verification of plaintext footer signature. 
     * Will be ignored if checkPlaintextFooterSignature(true) is not called.
     * If applied on a file that contains footer signing key metadata - 
     * the metadata will be ignored, the footer signature will be verified with this key.
     * If explicit key is not set (and signature must be verified), signing key will be 
     * fetched from key retriever.
     * @param footerSigningKey Key length must be either 16, 24 or 32 bytes. 
     */
    public Builder withFooterSigningKey(byte[] footerSigningKey) {
      if (null == footerSigningKey) {
        return this;
      }
      if (null != this.footerSigningKey) {
        throw new IllegalArgumentException("Footer signing key already set");
      }
      this.footerSigningKey = footerSigningKey;
      return this;
    }
    
    /**
     * Set the AES-GCM additional authenticated data (AAD) Prefix.
     * @param aad
     */
    public Builder withAADPrefix(byte[] aadPrefixBytes) {
      if (null == aadPrefixBytes) {
        return this;
      }
      if (null != this.aadPrefixBytes) {
        throw new IllegalArgumentException("AAD Prefix already set");
      }
      this.aadPrefixBytes = aadPrefixBytes;
      return this;
    }
    
    /**
     * Set an AAD prefix retrieval callback.
     * @param aadRetriever
     */
    public Builder withAADRetriever(AADPrefixRetriever aadPrefixRetriever) {
      if (null == aadPrefixRetriever) {
        return this;
      }
      if (null != this.aadPrefixRetriever) {
        throw new IllegalArgumentException("AAD retriever already set");
      }
      this.aadPrefixRetriever = aadPrefixRetriever;
      return this;
    }
    
    public FileDecryptionProperties build() {
      return new FileDecryptionProperties(footerDecryptionKey, keyRetriever, footerSigningKey, 
          checkPlaintextFooterIntegrity, aadPrefixRetriever, aadPrefixBytes, columnPropertyMap);
    }
  }
  
  public byte[] getFooterDecryptionKey() {
    return footerDecryptionKey;
  }
  
  public byte[] getColumnKey(ColumnPath path) {
    if (null == columnPropertyMap) return null;
    ColumnDecryptionProperties columnDecryptionProperties = columnPropertyMap.get(path);
    if (null == columnDecryptionProperties) return null;
    return columnDecryptionProperties.getKeyBytes();
  }

  public DecryptionKeyRetriever getKeyRetriever() {
    return keyRetriever;
  }

  public byte[] getAADPrefix() {
    return aadPrefixBytes;
  }

  public AADPrefixRetriever getAADPrefixRetriever() {
    return aadPrefixRetriever;
  }
  
  public boolean checkFooterIntegrity() {
    return checkPlaintextFooterIntegrity;
  }
  
  public byte[] getFooterSigningKey() {
    return footerSigningKey;
  }
}
