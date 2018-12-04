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

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Map;

import org.apache.parquet.format.EncryptionAlgorithm;
import org.apache.parquet.hadoop.metadata.ColumnPath;

import static org.apache.parquet.crypto.AesEncryptor.AAD_FILE_UNIQUE_LENGTH;

public class FileEncryptionProperties {
  
  private static final ParquetCipher ALGORITHM_DEFAULT = ParquetCipher.AES_GCM_V1;
  private static final boolean ENCRYPT_THE_REST_DEFAULT = true;
  
  private final EncryptionAlgorithm algorithm;
  private final byte[] footerEncryptionKey;
  private final byte[] footerEncryptionKeyMetadata;
  private final byte[] footerSigningKey;
  private final byte[] footerSigningKeyMetadata;
  private final byte[] fileAAD;
  private final Map<ColumnPath, ColumnEncryptionProperties> columnPropertyMap;
  private final boolean encryptTheRest;

  
  private FileEncryptionProperties(ParquetCipher cipher, 
      byte[] footerEncryptionKey, byte[] footerEncryptionKeyMetadata, 
      byte[] footerSigningKey, byte[] footerSigningKeyMetadata, 
      byte[] aadPrefixBytes, byte[] aadMetaData, Map<ColumnPath, ColumnEncryptionProperties> columnPropertyMap, 
      boolean encryptTheRest) {

    if (null == footerEncryptionKey) {
      if (encryptTheRest) {
        throw new IllegalArgumentException("Encrypt the rest with null footer key");
      }
      if (null != footerEncryptionKeyMetadata) {
        throw new IllegalArgumentException("Setting key metadata for null footer key");
      }
      if (null == columnPropertyMap) {
        throw new IllegalArgumentException("Footer and all columns are unencrypted (no properties set)");
      }
      else {
        // Check column properties
        boolean allAreUnencrypted = true;
        for (ColumnEncryptionProperties columnProperties : columnPropertyMap.values()) {
          if (columnProperties.isEncrypted()) {
            if (null == columnProperties.getKeyBytes()) {
              throw new IllegalArgumentException("Encrypt column with null footer key. Column: " + 
                  columnProperties.getPath());
            }
            allAreUnencrypted = false;
          }
        }
        if (allAreUnencrypted) {
          throw new IllegalArgumentException("Footer and all columns are unencrypted");
        }
      }
    }
    else {
      if (! (footerEncryptionKey.length == 16 || footerEncryptionKey.length == 24 || footerEncryptionKey.length == 32)) {
           throw new IllegalArgumentException("Wrong footer encryption key length " + footerEncryptionKey.length);
      }
    }
    
    if (null != footerSigningKey) {
      if (! (footerSigningKey.length == 16 || footerSigningKey.length == 24 || footerSigningKey.length == 32)) {
        throw new IllegalArgumentException("Wrong footer signing key length " + footerSigningKey.length);
      }
    }
    
    this.algorithm = cipher.getEncryptionAlgorithm();
    SecureRandom random = new SecureRandom();
    byte[] aadFileUnique = new byte[AAD_FILE_UNIQUE_LENGTH];
    random.nextBytes(aadFileUnique);
    if (algorithm.isSetAES_GCM_V1()) {
      algorithm.getAES_GCM_V1().setAad_file_unique(aadFileUnique);
      if (null != aadMetaData) algorithm.getAES_GCM_V1().setAad_metadata(aadMetaData);
    }
    else {
      algorithm.getAES_GCM_CTR_V1().setAad_file_unique(aadFileUnique);
      if (null != aadMetaData) algorithm.getAES_GCM_CTR_V1().setAad_metadata(aadMetaData);
    }
    if (null == aadPrefixBytes) {
      this.fileAAD = aadFileUnique;
    }
    else {
      this.fileAAD = AesEncryptor.concatByteArrays(aadPrefixBytes, aadFileUnique);
    }

    this.footerEncryptionKey = footerEncryptionKey;
    this.footerEncryptionKeyMetadata = footerEncryptionKeyMetadata;
    this.footerSigningKey = footerSigningKey;
    this.footerSigningKeyMetadata = footerSigningKeyMetadata;
    this.columnPropertyMap = columnPropertyMap;
    this.encryptTheRest = encryptTheRest;
  }
  
  /**
   * 
   * @param keyBytes Encryption key for file footer and some (or all) columns. 
   * Key length must be either 16, 24 or 32 bytes.
   * If null, footer won't be encrypted. At least one column must be encrypted then.
   */
  public static Builder builder(byte[] footerEncryptionKey) {
    return new Builder(footerEncryptionKey);
  }
  
  public static class Builder {
    private final byte[] footerEncryptionKey;
    private ParquetCipher parquetCipher;
    private byte[] footerEncryptionKeyMetadata;
    private byte[] footerSigningKey;
    private byte[] footerSigningKeyMetadata;
    private byte[] aadPrefixBytes;
    private byte[] aadMetaData;
    private Map<ColumnPath, ColumnEncryptionProperties> columnPropertyMap;
    private boolean encryptTheRest;
    
    
    private Builder(byte[] footerEncryptionKey) {
      this.footerEncryptionKey = footerEncryptionKey;
      this.parquetCipher = ALGORITHM_DEFAULT;
      this.encryptTheRest = ENCRYPT_THE_REST_DEFAULT;
    }
    
    public Builder withAlgorithm(ParquetCipher parquetCipher) {
      this.parquetCipher = parquetCipher;
      return this;
    }
    
    /**
    * Set a key retrieval meta data.
    * use either withKeyMetaData or withKeyID, not both
    * @param footerEncryptionKeyMetadata 
    */
    public Builder withFooterEncryptionKeyMetadata(byte[] footerEncryptionKeyMetadata) {
      if (null == footerEncryptionKeyMetadata) {
        return this;
      }
      if (null != this.footerEncryptionKeyMetadata) {
        throw new IllegalArgumentException("Footer key metadata already set");
      }
      this.footerEncryptionKeyMetadata = footerEncryptionKeyMetadata;
      return this;
    }
    
    /**
     * Set a key retrieval meta data (converted from String).
     * use either withKeyMetaData or withKeyID, not both
     * @param keyId will be converted to metadata (UTF-8 array).
     */
    public Builder withFooterKeyID(String keyId) {
      if (null == keyId) {
        return this;
      }
      byte[] metadata = keyId.getBytes(StandardCharsets.UTF_8);
      return withFooterEncryptionKeyMetadata(metadata);
    }
    
    /**
    * Set a footer signing key (for plaintext footers)
    * @param footerSigningKey 
    */
    public Builder withFooterSigningKey(byte[] footerSigningKey) {
      if (null == footerSigningKey) {
        return this;
      }
      if (null != this.footerEncryptionKey) {
        throw new IllegalArgumentException("Can set signing key only for plaintext footer");
      }
      this.footerSigningKey = footerSigningKey;
      return this;
    }
    
    /**
    * Set a footer signing key metadata (for plaintext footers)
    * @param footerSigningKeyMetadata 
    */
    public Builder withFooterSigningKeyMetadata(byte[] footerSigningKeyMetadata) {
      if (null == footerSigningKeyMetadata) {
        return this;
      }
      if (null != this.footerEncryptionKey) {
        throw new IllegalArgumentException("Can set signing key metadata only for plaintext footer");
      }
      this.footerSigningKeyMetadata = footerSigningKeyMetadata;
      return this;
    }
    
    /**
     * Set the AES-GCM additional authenticated data (AAD) Prefix.
     * @param aadBytes
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
     * Set AAD prefix retrieval meta data.
     * @param aadMetadata
     */
    public Builder withAADMetaData(byte[] aadMetadata) {
      if (null == aadMetadata) {
        return this;
      }
      if (null != this.aadMetaData) {
        throw new IllegalArgumentException("AAD metadata already set");
      }
      this.aadMetaData = aadMetadata;
      return this;
    }
    
    /**
     * Set column encryption properties. 
     * The map doesn't have to include all columns in a file. If encryptTheRest is true, 
     * the rest of the columns (not in the map) will be encrypted with the file footer key. 
     * If encryptTheRest is false, the rest of the columns will be left unencrypted.
     * @param columnPropertyMap
     * @param encryptTheRest  
     */
    public Builder withColumnProperties(Map<ColumnPath, ColumnEncryptionProperties> columnPropertyMap, 
        boolean encryptTheRest)  {
      if (null == columnPropertyMap) {
        return this;
      }
      if (null != this.columnPropertyMap) {
        throw new IllegalArgumentException("Column properties already set");
      }
      this.columnPropertyMap = columnPropertyMap;
      this.encryptTheRest = encryptTheRest;
      return this;
    }
    
    public FileEncryptionProperties build() {
      return new FileEncryptionProperties(parquetCipher, 
          footerEncryptionKey, footerEncryptionKeyMetadata, 
          footerSigningKey, footerSigningKeyMetadata, 
          aadPrefixBytes, aadMetaData, columnPropertyMap, encryptTheRest);
    }
  }
  
  public EncryptionAlgorithm getAlgorithm() {
    return algorithm;
  }

  public byte[] getFooterEncryptionKey() {
    return footerEncryptionKey;
  }

  public byte[] getFooterEncryptionKeyMetadata() {
    return footerEncryptionKeyMetadata;
  }
  
  public byte[] getFooterSigningKey() {
    return footerSigningKey;
  }

  public byte[] getFooterSigningKeyMetadata() {
    return footerSigningKeyMetadata;
  }

  public ColumnEncryptionProperties getColumnProperties(ColumnPath columnPath) {
    if (null != columnPropertyMap) {
      ColumnEncryptionProperties columnProperties = columnPropertyMap.get(columnPath);
      if (null != columnProperties) {
        return columnProperties;
      }
    }
    // Not in the map. Create using the encryptTheRest flag.
    return ColumnEncryptionProperties.builder(columnPath, encryptTheRest).build();
  }

  public byte[] getFileAAD() {
    return fileAAD;
  }
}
