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


import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.parquet.bytes.BytesUtils;
import org.apache.parquet.format.BlockCipher;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

public class AesEncryptor implements BlockCipher.Encryptor{

  public enum Mode {
    GCM, CTR
  }
  
  public static final byte Footer = 0;
  public static final byte ColumnMetaData = 1;
  public static final byte DataPage = 2;
  public static final byte DictionaryPage = 3;
  public static final byte DataPageHeader = 4;
  public static final byte DictionaryPageHeader = 5;
  public static final byte ColumnIndex = 6;
  public static final byte OffsetIndex = 7;

  static final int NONCE_LENGTH = 12;
  static final int CTR_IV_LENGTH = 16;
  static final int GCM_TAG_LENGTH = 16;
  static final int CHUNK_LENGTH = 4 * 1024;
  static final int INT_LENGTH = 4;
  static final int AAD_FILE_UNIQUE_LENGTH = 8;

  private final SecretKey aesKey;
  private final SecureRandom randomGenerator;
  private final int tagLength;
  private final Cipher aesCipher;
  private final Mode aesMode;
  private final byte[] ctrIV;
  private final byte[] nonce;


  public AesEncryptor(Mode mode, byte[] keyBytes) throws IllegalArgumentException, IOException {
    if (null == keyBytes) {
      throw new IllegalArgumentException("Null key bytes");
    }
    aesKey = new SecretKeySpec(keyBytes, "AES");
    randomGenerator = new SecureRandom();
    aesMode = mode;
    
    if (Mode.GCM == mode) {
      tagLength = GCM_TAG_LENGTH;
      try {
        aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
      } catch (GeneralSecurityException e) {
        throw new IOException("Failed to create GCM cipher", e);
      }
      ctrIV = null;
    }
    else {
      tagLength = 0;
      try {
        aesCipher = Cipher.getInstance("AES/CTR/NoPadding");
      } catch (GeneralSecurityException e) {
        throw new IOException("Failed to create CTR cipher", e);
      }
      ctrIV = new byte[CTR_IV_LENGTH];
      Arrays.fill(ctrIV, (byte) 0);
      ctrIV[CTR_IV_LENGTH - 1] = (byte) 1;
    }
    
    nonce = new byte[NONCE_LENGTH];
  }

  @Override
  public byte[] encrypt(byte[] plainText, byte[] AAD)  throws IOException {
    randomGenerator.nextBytes(nonce);
    return encrypt(plainText, nonce, AAD);
  }
  
  public byte[] encrypt(byte[] plainText, byte[] nonce, byte[] AAD)  throws IOException {
    int plainTextLength = plainText.length;
    int cipherTextLength = NONCE_LENGTH + plainTextLength + tagLength;
    byte[] cipherText = new byte[INT_LENGTH + cipherTextLength];
    int inputLength = plainTextLength;
    int inputOffset = 0;
    int outputOffset = INT_LENGTH + NONCE_LENGTH;
    try {
      if (Mode.GCM == aesMode) {
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
        if (null != AAD) aesCipher.updateAAD(AAD);
      }
      else {
        System.arraycopy(nonce, 0, ctrIV, 0, NONCE_LENGTH);
        IvParameterSpec spec = new IvParameterSpec(ctrIV);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
      }
      // Breaking encryption into multiple updates, to trigger h/w acceleration in Java 9-11
      while (inputLength > CHUNK_LENGTH) {
        int written = aesCipher.update(plainText, inputOffset, CHUNK_LENGTH, cipherText, outputOffset);
        inputOffset += CHUNK_LENGTH;
        outputOffset += written;
        inputLength -= CHUNK_LENGTH;
      }
      aesCipher.doFinal(plainText, inputOffset, inputLength, cipherText, outputOffset);
    }
    catch (GeneralSecurityException e) {
      throw new IOException("Failed to encrypt", e);
    }
    // Add ciphertext length
    System.arraycopy(BytesUtils.intToBytes(cipherTextLength), 0, cipherText, 0, INT_LENGTH);
    // Add the nonce
    System.arraycopy(nonce, 0, cipherText, INT_LENGTH, NONCE_LENGTH);

    return cipherText;
  }
  
  public static byte[] createModuleAAD(byte[] aadPrefixBytes, byte moduleType, 
      short rowGroupOrdinal, short columnOrdinal, short pageOrdinal) {
    byte[] typeOrdinalBytes = new byte[1];
    typeOrdinalBytes[0] = moduleType;
    if (Footer == moduleType) {
      return concatByteArrays(aadPrefixBytes, typeOrdinalBytes);      
    }
    
    byte[] rowGroupOrdinalBytes = shortToBytesLE(rowGroupOrdinal);
    byte[] columnOrdinalBytes = shortToBytesLE(columnOrdinal);
    if (DataPage != moduleType && DataPageHeader != moduleType) {
      return concatByteArrays(aadPrefixBytes, typeOrdinalBytes, rowGroupOrdinalBytes, columnOrdinalBytes); 
    }
    
    byte[] pageOrdinalBytes = shortToBytesLE(pageOrdinal);
    return concatByteArrays(aadPrefixBytes, typeOrdinalBytes, rowGroupOrdinalBytes, columnOrdinalBytes, pageOrdinalBytes);
  }
  
  public static void quickUpdatePageAAD(byte[] pageAAD, short newPageOrdinal) {
    byte[] pageOrdinalBytes = shortToBytesLE(newPageOrdinal);
    int length = pageAAD.length;
    System.arraycopy(pageOrdinalBytes, 0, pageAAD, length-2, 2);
  }

  
  static byte[] concatByteArrays(byte[]... arrays) {
    int totalLength = 0;
    for (byte[] array : arrays) {
      totalLength += array.length;
    }
    byte[] output = new byte[totalLength];
    int offset = 0;
    for (byte[] array : arrays) {
      int arrayLength = array.length;
      System.arraycopy(array, 0, output, offset, arrayLength);
      offset += arrayLength;
    }
    return output;
  }
  
  private static byte[] shortToBytesLE(short input) {
    byte[] output  = new byte[2];
    output[1] = (byte)(0xff & (input >> 8));
    output[0] = (byte)(0xff & (input));
    return output;
  }
}

