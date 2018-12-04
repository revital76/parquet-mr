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


import org.apache.parquet.format.BlockCipher;
import org.apache.parquet.format.EncryptionAlgorithm;
import org.apache.parquet.hadoop.metadata.ColumnPath;
import java.io.IOException;
import java.util.HashMap;


public class InternalFileDecryptor {
  
  private final FileDecryptionProperties fileDecryptionProperties;
  private final DecryptionKeyRetriever keyRetriever;
  private final AADPrefixRetriever aadPrefixRetriever;
  private final boolean checkPlaintextFooterIntegrity;
  
  private byte[] footerDecryptionKey;
  private byte[] footerSigningKey;
  private HashMap<ColumnPath, InternalColumnDecryptionSetup> columnMap;
  private EncryptionAlgorithm algorithm;
  private byte[] aadPrefixBytes;
  private byte[] fileAAD;
  private boolean encryptedFooter;
  private boolean fileCryptoMetaDataProcessed = false;
  private boolean allColumnCryptoMetaDataProcessed = false;
  private BlockCipher.Decryptor aesGcmDecryptorWithFooterKey;
  private BlockCipher.Decryptor aesCtrDecryptorWithFooterKey;

  public InternalFileDecryptor(FileDecryptionProperties fileDecryptionProperties) throws IOException {
    this.fileDecryptionProperties= fileDecryptionProperties;
    checkPlaintextFooterIntegrity = fileDecryptionProperties.checkFooterIntegrity();
    footerDecryptionKey = fileDecryptionProperties.getFooterDecryptionKey();
    footerSigningKey = fileDecryptionProperties.getFooterSigningKey();
    keyRetriever = fileDecryptionProperties.getKeyRetriever();
    aadPrefixBytes = fileDecryptionProperties.getAADPrefix();
    aadPrefixRetriever = fileDecryptionProperties.getAADPrefixRetriever();
    columnMap = new HashMap<ColumnPath, InternalColumnDecryptionSetup>();
  }
  
  private BlockCipher.Decryptor getMetaDataDecryptor(byte[] columnKey) throws IOException {
    if (null == columnKey) { // Decryptor with footer key
      if (null == aesGcmDecryptorWithFooterKey) {
        aesGcmDecryptorWithFooterKey = new AesDecryptor(AesEncryptor.Mode.GCM, footerDecryptionKey);
      }
      return aesGcmDecryptorWithFooterKey;
    }
    else {
      return new AesDecryptor(AesEncryptor.Mode.GCM, columnKey);
    }
  }
  
  private BlockCipher.Decryptor getDataDecryptor(byte[] columnKey) throws IOException {
    if (algorithm.isSetAES_GCM_V1()) {
      return getMetaDataDecryptor(columnKey);
    }
    // AES_GCM_CTR_V1
    if (null == columnKey) { // Decryptor with footer key
      if (null == aesCtrDecryptorWithFooterKey) {
        aesCtrDecryptorWithFooterKey = new AesDecryptor(AesEncryptor.Mode.CTR, footerDecryptionKey);
      }
      return aesCtrDecryptorWithFooterKey;
    }
    else {
      return new AesDecryptor(AesEncryptor.Mode.CTR, columnKey);
    }
  }

  public InternalColumnDecryptionSetup getColumnSetup(ColumnPath path) throws IOException {
    if (!fileCryptoMetaDataProcessed) {
      throw new IOException("Haven't parsed the file crypto metadata yet");
    }
    InternalColumnDecryptionSetup columnDecryptionSetup = columnMap.get(path);
    if (null == columnDecryptionSetup) {
      throw new IOException("Failed to find decryption setup for column " + path);
    }
    return columnDecryptionSetup;
  }

  public BlockCipher.Decryptor getFooterDecryptor() throws IOException {
    if (!fileCryptoMetaDataProcessed) {
      throw new IOException("Haven't parsed the file crypto metadata yet");
    }
    if (!encryptedFooter) return null;
    return getMetaDataDecryptor(null);
  }

  public void setFileCryptoMetaData(EncryptionAlgorithm algorithm, boolean encryptedFooter, byte[] footerKeyMetaData) throws IOException {
    // first use of the decryptor
    if (!fileCryptoMetaDataProcessed) {
      this.encryptedFooter = encryptedFooter;
      this.algorithm = algorithm;
      byte[] aadMetadata = null;
      byte[] aadFileUnique;
      
      if (algorithm.isSetAES_GCM_V1()) {
        aadMetadata = algorithm.getAES_GCM_V1().getAad_metadata();
        aadFileUnique = algorithm.getAES_GCM_V1().getAad_file_unique();
      }
      else if (algorithm.isSetAES_GCM_CTR_V1()) {
        aadMetadata = algorithm.getAES_GCM_CTR_V1().getAad_metadata();
        aadFileUnique = algorithm.getAES_GCM_CTR_V1().getAad_file_unique();
      }
      else {
        throw new IOException("Unsupported algorithm: " + algorithm);
      }
 
      // ignore footer key metadata if footer key is explicitly set via API
      if (encryptedFooter && (null == footerDecryptionKey)) { 
        if (null == footerKeyMetaData) throw new IOException("EncryptedFooter. No footer key or key metadata");
        if (null == keyRetriever) throw new IOException("EncryptedFooter. No footer key or key retriever");
        footerDecryptionKey = keyRetriever.getKey(footerKeyMetaData);
        if (null == footerDecryptionKey) {
          throw new IOException("Footer decryption key unavailable");
        }
      }
      
      // ignore aad metadata if AAD_Prefix is explicitly set via API
      if ((null == aadPrefixBytes) && (null != aadPrefixRetriever) && (null != aadMetadata)) {
        aadPrefixBytes = aadPrefixRetriever.getAADPrefix(aadMetadata);
      }
      
      if (null == aadPrefixBytes) {
        this.fileAAD = aadFileUnique;
      }
      else {
        this.fileAAD = AesEncryptor.concatByteArrays(aadPrefixBytes, aadFileUnique);
      }
      fileCryptoMetaDataProcessed = true;
    }
    // re-use of the decryptor. compare the crypto metadata.
    else {
      if (!this.algorithm.equals(algorithm)) {
        throw new IOException("Decryptor re-use: Different algorithm");
      }
      // TODO check other fields?
    }
  }

  public InternalColumnDecryptionSetup setColumnCryptoMetadata(ColumnPath path, boolean encrypted, 
      boolean encryptedWithFooterKey, byte[] keyMetadata, short columnOrdinal) throws IOException {
    
    if (!fileCryptoMetaDataProcessed) {
      throw new IOException("Haven't parsed the file crypto metadata yet");
    }
    InternalColumnDecryptionSetup columnDecryptionSetup = columnMap.get(path);
    if (allColumnCryptoMetaDataProcessed && (null == columnDecryptionSetup)) {
      throw new IOException("Re-use with unknown column: " + path);
    }
    if (null != columnDecryptionSetup) {
      if (!allColumnCryptoMetaDataProcessed) {
        throw new IOException("File with identical columns: " + path);
      }
      if (columnDecryptionSetup.isEncrypted() != encrypted) {
        throw new IOException("Re-use: wrong encrypted flag. Column: " + path);
      }
      if (encrypted && (encryptedWithFooterKey != columnDecryptionSetup.isEncryptedWithFooterKey())) {
        throw new IOException("Re-use: wrong encryption key (column vs footer). Column: " + path);
      }
      return columnDecryptionSetup;
    }
    
    if (!encrypted) {
      columnDecryptionSetup = new InternalColumnDecryptionSetup(path, false, false,  false, null, null, columnOrdinal);
    }
    else {
      if (encryptedWithFooterKey) {
        if (null == footerDecryptionKey) {
          throw new IOException("Column " + path + " is encrypted with NULL footer key");
        }
        columnDecryptionSetup = new InternalColumnDecryptionSetup(path, true, true, true, 
            getDataDecryptor(null), getMetaDataDecryptor(null), columnOrdinal);
      }
      else {
        // Column is encrypted with column-specific key
        byte[] columnKeyBytes = fileDecryptionProperties.getColumnKey(path);
        if ((null == columnKeyBytes) && (null != keyMetadata) && (null != keyRetriever)) {
          // No explicit column key given via API. Retrieve via key metadata.
          columnKeyBytes = keyRetriever.getKey(keyMetadata);
        }

        if (null == columnKeyBytes) { // Hidden column: encrypted, but key unavailable
          columnDecryptionSetup = new InternalColumnDecryptionSetup(path, true, false,  false, null, null, columnOrdinal);
        }
        else { // Key is available
          columnDecryptionSetup = new InternalColumnDecryptionSetup(path, true, true, false, 
              getDataDecryptor(columnKeyBytes), getMetaDataDecryptor(columnKeyBytes), columnOrdinal);
        }
      }
    }
    columnMap.put(path, columnDecryptionSetup);
    return columnDecryptionSetup;
  }

  public void allColumnCryptoMetaDataProcessed() {
    allColumnCryptoMetaDataProcessed = true;
  }
  
  public byte[] getFileAAD() {
    return this.fileAAD;
  }
  
  public byte[] getFooterSigningKey(byte[] signingKeyMetadata) throws IOException  {
    if (null != footerSigningKey) return footerSigningKey;
    if ((null != keyRetriever) && (null != signingKeyMetadata)) {
      footerSigningKey = keyRetriever.getKey(signingKeyMetadata);
    }
    return footerSigningKey;
  }

  public boolean checkFooterIntegrity() {
    return checkPlaintextFooterIntegrity;
  }
}

